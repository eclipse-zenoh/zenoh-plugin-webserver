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
use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;
use tide::http::Mime;
use tide::{Request, Response, Server, StatusCode};
use tracing::debug;
use zenoh::bytes::ZBytes;
use zenoh::encoding::Encoding;
use zenoh::internal::plugins::{RunningPlugin, RunningPluginTrait, ZenohPlugin};
use zenoh::internal::runtime::Runtime;
use zenoh::sample::Sample;
use zenoh::selector::Selector;
use zenoh::Result as ZResult;
use zenoh::{prelude::*, Session};
use zenoh_core::{bail, zerror};
use zenoh_plugin_trait::{plugin_long_version, plugin_version, Plugin, PluginControl};

mod config;
use config::Config;

const DEFAULT_DIRECTORY_INDEX: &str = "index.html";

lazy_static::lazy_static! {
    static ref DEFAULT_MIME: Mime = Mime::from_str(&Encoding::APPLICATION_OCTET_STREAM.to_string()).unwrap();
}
pub struct WebServerPlugin;
impl PluginControl for WebServerPlugin {}
impl ZenohPlugin for WebServerPlugin {}

impl Plugin for WebServerPlugin {
    type StartArgs = Runtime;
    type Instance = RunningPlugin;

    const DEFAULT_NAME: &'static str = "zenoh-plugin-webserver";
    const PLUGIN_VERSION: &'static str = plugin_version!();
    const PLUGIN_LONG_VERSION: &'static str = plugin_long_version!();

    fn start(name: &str, runtime: &Self::StartArgs) -> ZResult<RunningPlugin> {
        zenoh_util::try_init_log_from_env();
        let runtime_conf = runtime.config().lock();
        let plugin_conf = runtime_conf
            .plugin(name)
            .ok_or_else(|| zerror!("Plugin `{}`: missing config", name))?;
        let conf: Config = serde_json::from_value(plugin_conf.clone())
            .map_err(|e| zerror!("Plugin `{}` configuration error: {}", name, e))?;
        async_std::task::spawn(run(runtime.clone(), conf));
        Ok(Box::new(WebServerPlugin))
    }
}

impl RunningPluginTrait for WebServerPlugin {}

#[cfg(feature = "dynamic_plugin")]
zenoh_plugin_trait::declare_plugin!(WebServerPlugin);

async fn run(runtime: Runtime, conf: Config) {
    debug!("WebServer plugin {}", WebServerPlugin::PLUGIN_LONG_VERSION);

    let zenoh = match zenoh::session::init(runtime).await {
        Ok(session) => Arc::new(session),
        Err(e) => {
            tracing::error!("Unable to init zenoh session for WebServer plugin : {}", e);
            return;
        }
    };

    let mut app = Server::with_state(zenoh);

    app.at("").get(handle_request);
    app.at("*").get(handle_request);

    if let Err(e) = app.listen(conf.http_port).await {
        tracing::error!("Unable to start http server for WebServer plugin : {}", e);
    }
}

async fn handle_request(req: Request<Arc<Session>>) -> tide::Result<Response> {
    let session = req.state();

    // Reconstruct Selector from req.url() (no easier way...)
    let url = req.url();
    tracing::debug!("GET on {}", url);

    // Build corresponding Selector
    let path = url.path();
    let mut selector = String::with_capacity(url.as_str().len());
    selector.push_str(path.strip_prefix('/').unwrap_or(path));

    // if URL id a directory, append DirectoryIndex
    if selector.ends_with('/') || selector.is_empty() {
        selector.push_str(DEFAULT_DIRECTORY_INDEX);
    }
    if let Some(q) = url.query() {
        selector.push('?');
        selector.push_str(q);
    }

    // Check if selector's key expression is a single key (i.e. for a single resource)
    if selector.contains('*') {
        return Ok(bad_request(
            "The URL must correspond to 1 resource only (i.e. zenoh key expressions not supported)",
        ));
    }
    match Selector::try_from(selector) {
        Ok(selector) => {
            if HashMap::<&str, &str>::from(&selector.parameters.clone().into_owned())
                .get("_method")
                .map(|x| x.as_ref())
                == Some("SUB")
            {
                tracing::debug!("Subscribe to {} for Multipart stream", selector.key_expr,);
                let (sender, receiver) = async_std::channel::bounded(1);
                async_std::task::spawn(async move {
                    tracing::debug!(
                        "Subscribe to {} for Multipart stream (task {})",
                        selector.key_expr,
                        async_std::task::current().id()
                    );
                    let sub = req
                        .state()
                        .declare_subscriber(&selector.key_expr.into_owned())
                        .await
                        .unwrap();
                    loop {
                        let sample = sub.recv_async().await.unwrap();
                        let mut buf = "--boundary\nContent-Type: ".as_bytes().to_vec();
                        buf.extend_from_slice(sample.encoding().to_string().as_bytes());
                        buf.extend_from_slice("\n\n".as_bytes());
                        buf.extend_from_slice(&sample.payload().into::<Cow<[u8]>>());

                        match sender
                            .send(Ok(buf))
                            .timeout(std::time::Duration::new(10, 0))
                            .await
                        {
                            Ok(Ok(_)) => {}
                            Ok(Err(e)) => {
                                tracing::debug!(
                                    "Multipart error ({})! Unsubscribe and terminate (task {})",
                                    e,
                                    async_std::task::current().id()
                                );
                                if let Err(e) = sub.undeclare().await {
                                    tracing::error!("Error undeclaring subscriber: {}", e);
                                }
                                break;
                            }
                            Err(_) => {
                                tracing::debug!(
                                    "Multipart timeout! Unsubscribe and terminate (task {})",
                                    async_std::task::current().id()
                                );
                                if let Err(e) = sub.undeclare().await {
                                    tracing::error!("Error undeclaring subscriber: {}", e);
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
                    Ok(Some(sample)) => Ok(response_with_value(sample)),
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

async fn zenoh_get(session: &Session, selector: &Selector<'_>) -> ZResult<Option<Sample>> {
    let replies = session.get(selector).await?;
    match replies.recv_async().await {
        Ok(reply) => match reply.result() {
            Ok(sample) => Ok(Some(sample.to_owned())),
            Err(err) => bail!("Zenoh get on {} returned the error: {:?}", selector, err),
        },
        Err(_) => Ok(None),
    }
}

fn response_with_value(sample: Sample) -> Response {
    let mime =
        Mime::from_str(&sample.encoding().to_string()).unwrap_or_else(|_| DEFAULT_MIME.clone());
    response_ok(mime, sample.payload())
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

fn response_ok(content_type: Mime, payload: &ZBytes) -> Response {
    let mut res = Response::new(StatusCode::Ok);
    res.set_content_type(content_type);
    res.set_body(payload.into::<Cow<[u8]>>().as_ref());
    res
}
