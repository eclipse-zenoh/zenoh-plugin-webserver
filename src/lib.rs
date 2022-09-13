//
// Copyright (c) 2022 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//

use async_std::prelude::FutureExt;
use async_std::sync::Arc;
use futures::TryStreamExt;
use log::debug;
use std::convert::TryFrom;
use std::str::FromStr;
use tide::http::Mime;
use tide::{Request, Response, Server, StatusCode};
use zenoh::buffers::ZBuf;
use zenoh::plugins::{Plugin, RunningPlugin, RunningPluginTrait, Runtime, ZenohPlugin};
use zenoh::query::Reply;
use zenoh::Result as ZResult;
use zenoh::{prelude::r#async::*, Session};
use zenoh_core::{bail, zerror};

mod config;
use config::Config;

const DEFAULT_DIRECTORY_INDEX: &str = "index.html";

const GIT_VERSION: &str = git_version::git_version!(prefix = "v", cargo_prefix = "v");
lazy_static::lazy_static! {
    static ref LONG_VERSION: String = format!("{} built with {}", GIT_VERSION, env!("RUSTC_VERSION"));
    static ref DEFAULT_MIME: Mime = Mime::from_str(KnownEncoding::AppOctetStream.into()).unwrap();
}

pub struct WebServerPlugin;
impl ZenohPlugin for WebServerPlugin {}
impl Plugin for WebServerPlugin {
    type StartArgs = Runtime;
    type RunningPlugin = RunningPlugin;

    fn start(name: &str, runtime: &Self::StartArgs) -> ZResult<RunningPlugin> {
        env_logger::init();
        let runtime_conf = runtime.config.lock();
        let plugin_conf = runtime_conf
            .plugin(name)
            .ok_or_else(|| zerror!("Plugin `{}`: missing config", name))?;
        let conf: Config = serde_json::from_value(plugin_conf.clone())
            .map_err(|e| zerror!("Plugin `{}` configuration error: {}", name, e))?;
        async_std::task::spawn(run(runtime.clone(), conf));
        Ok(Box::new(WebServerPlugin))
    }

    const STATIC_NAME: &'static str = "webserver";
}
impl RunningPluginTrait for WebServerPlugin {
    fn config_checker(&self) -> zenoh::plugins::ValidationFunction {
        Arc::new(|name, _, _| {
            bail!(
                "Plugin `{}` doesn't support hot configuration changes",
                name
            )
        })
    }
    fn adminspace_getter<'a>(
        &'a self,
        _selector: &'a Selector<'a>,
        _plugin_status_key: &str,
    ) -> ZResult<Vec<zenoh::plugins::Response>> {
        Ok(Vec::new())
    }
}

zenoh_plugin_trait::declare_plugin!(WebServerPlugin);

async fn run(runtime: Runtime, conf: Config) {
    debug!("WebServer plugin {}", LONG_VERSION.as_str());

    let zenoh = match zenoh::init(runtime).res().await {
        Ok(session) => Arc::new(session),
        Err(e) => {
            log::error!("Unable to init zenoh session for WebServer plugin : {}", e);
            return;
        }
    };

    let mut app = Server::with_state(zenoh);

    app.at("*").get(handle_request);

    if let Err(e) = app.listen(conf.http_port).await {
        log::error!("Unable to start http server for WebServer plugin : {}", e);
    }
}

async fn handle_request(req: Request<Arc<Session>>) -> tide::Result<Response> {
    let session = req.state();

    // Reconstruct Selector from req.url() (no easier way...)
    let url = req.url();
    log::debug!("GET on {}", url);

    // Build corresponding Selector
    let path = url.path();
    let mut selector = String::with_capacity(url.as_str().len());
    selector.push_str(path.strip_prefix('/').unwrap_or(path));

    // if URL id a directory, append DirectoryIndex
    if selector.ends_with('/') {
        selector.push_str(DEFAULT_DIRECTORY_INDEX);
    }
    if let Some(q) = url.query() {
        selector.push('?');
        selector.push_str(q);
    }
    log::trace!("GET on {} => selector: {}", url, selector);

    // Check if selector's key expression is a single key (i.e. for a single resource)
    if selector.contains('*') {
        return Ok(bad_request(
            "The URL must correspond to 1 resource only (i.e. zenoh key expressions not supported)",
        ));
    }
    match Selector::try_from(selector) {
        Ok(selector) => {
            if selector
                .parameters_cowmap()
                .ok()
                .map(|m| m.get("_method").map(|x| x.as_ref()) == Some("SUB"))
                .unwrap_or(false)
            {
                log::debug!("Subscribe to {} for Multipart stream", selector.key_expr,);
                let (sender, receiver) = async_std::channel::bounded(1);
                async_std::task::spawn(async move {
                    log::debug!(
                        "Subscribe to {} for Multipart stream (task {})",
                        selector.key_expr,
                        async_std::task::current().id()
                    );
                    let sub = req
                        .state()
                        .declare_subscriber(&selector.key_expr)
                        .res_async()
                        .await
                        .unwrap();
                    loop {
                        let sample = sub.recv_async().await.unwrap();
                        let mut buf = "--boundary\nContent-Type: ".as_bytes().to_vec();
                        buf.extend_from_slice(sample.value.encoding.to_string().as_bytes());
                        buf.extend_from_slice("\n\n".as_bytes());
                        buf.extend_from_slice(sample.value.payload.contiguous().as_ref());

                        match sender
                            .send(Ok(buf))
                            .timeout(std::time::Duration::new(10, 0))
                            .await
                        {
                            Ok(Ok(_)) => {}
                            Ok(Err(e)) => {
                                log::debug!(
                                    "Multipart error ({})! Unsubscribe and terminate (task {})",
                                    e,
                                    async_std::task::current().id()
                                );
                                if let Err(e) = sub.undeclare().res().await {
                                    log::error!("Error undeclaring subscriber: {}", e);
                                }
                                break;
                            }
                            Err(_) => {
                                log::debug!(
                                    "Multipart timeout! Unsubscribe and terminate (task {})",
                                    async_std::task::current().id()
                                );
                                if let Err(e) = sub.undeclare().res().await {
                                    log::error!("Error undeclaring subscriber: {}", e);
                                }
                                break;
                            }
                        }
                    }
                });

                let mut res = Response::new(StatusCode::Ok);
                res.set_content_type("multipart/x-mixed-replace; boundary=\"boundary\"");
                res.set_body(tide::Body::from_reader(receiver.into_async_read(), None));

                Ok(res)
            } else {
                match zenoh_get(session, &selector).await {
                    Ok(Some(value)) => Ok(response_with_value(value)),
                    Ok(None) => {
                        // Check if considering the URL as a directory, there is an existing "URL/DirectoryIndex" resource
                        let mut new_selector = selector.key_expr.as_str().to_string();
                        new_selector.push('/');
                        new_selector.push_str(DEFAULT_DIRECTORY_INDEX);
                        if let Ok(new_selector) = Selector::try_from(new_selector) {
                            if let Ok(Some(_)) = zenoh_get(session, &new_selector).await {
                                // In this case, we must reply a redirection to the URL as a directory
                                Ok(redirect(&format!("{}/", url.path())))
                            } else {
                                Ok(not_found())
                            }
                        } else {
                            Ok(not_found())
                        }
                    }
                    Err(e) => Ok(internal_error(&e.to_string())),
                }
            }
        }
        Err(e) => Err(tide::Error::new(
            tide::StatusCode::BadRequest,
            anyhow::anyhow!("{}", e),
        )),
    }
}

async fn zenoh_get(session: &Session, selector: &Selector<'_>) -> ZResult<Option<Value>> {
    let replies = session.get(selector).res().await?;
    match replies.recv_async().await {
        Ok(Reply {
            sample: Ok(sample), ..
        }) => Ok(Some(sample.value)),
        Ok(Reply {
            sample: Err(value), ..
        }) => bail!("Zenoh get on {} returned the error: {}", selector, value),
        Err(_) => Ok(None),
    }
}

fn response_with_value(value: Value) -> Response {
    let mime = Mime::from_str(&value.encoding.to_string()).unwrap_or_else(|_| DEFAULT_MIME.clone());
    response_ok(mime, value.payload)
}

fn bad_request(body: &str) -> Response {
    let mut res = Response::new(StatusCode::BadRequest);
    res.set_content_type(Mime::from_str("text/plain").unwrap());
    res.set_body(body);
    res
}

fn not_found() -> Response {
    Response::new(StatusCode::NotFound)
}

fn internal_error(body: &str) -> Response {
    let mut res = Response::new(StatusCode::InternalServerError);
    res.set_content_type(Mime::from_str("text/plain").unwrap());
    res.set_body(body);
    res
}

fn redirect(url: &str) -> Response {
    let mut res = Response::new(StatusCode::MovedPermanently);
    res.insert_header("Location", url);
    res
}

fn response_ok(content_type: Mime, payload: ZBuf) -> Response {
    let mut res = Response::new(StatusCode::Ok);
    res.set_content_type(content_type);
    res.set_body(&*payload.contiguous());
    res
}
