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
use std::{
    future::Future,
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use futures::stream::TryStreamExt;
use tide::{http::Mime, Request, Response, Server, StatusCode};
use tokio::task::JoinHandle;
use tracing::debug;
use zenoh::{
    bytes::{Encoding, ZBytes},
    internal::{
        bail,
        plugins::{RunningPlugin, RunningPluginTrait, ZenohPlugin},
        runtime::Runtime,
        zerror,
    },
    query::Selector,
    sample::Sample,
    Result as ZResult, Session,
};
use zenoh_plugin_trait::{plugin_long_version, plugin_version, Plugin, PluginControl};

mod config;
use config::Config;

lazy_static::lazy_static! {
    static ref WORK_THREAD_NUM: AtomicUsize = AtomicUsize::new(config::DEFAULT_WORK_THREAD_NUM);
    static ref MAX_BLOCK_THREAD_NUM: AtomicUsize = AtomicUsize::new(config::DEFAULT_MAX_BLOCK_THREAD_NUM);
    // The global runtime is used in the dynamic plugins, which we can't get the current runtime
    static ref TOKIO_RUNTIME: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
               .worker_threads(WORK_THREAD_NUM.load(Ordering::SeqCst))
               .max_blocking_threads(MAX_BLOCK_THREAD_NUM.load(Ordering::SeqCst))
               .enable_all()
               .build()
               .expect("Unable to create runtime");
}
#[inline(always)]
pub(crate) fn spawn_runtime<F>(task: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    // Check whether able to get the current runtime
    match tokio::runtime::Handle::try_current() {
        Ok(rt) => {
            // Able to get the current runtime (standalone binary), spawn on the current runtime
            rt.spawn(task)
        }
        Err(_) => {
            // Unable to get the current runtime (dynamic plugins), spawn on the global runtime
            TOKIO_RUNTIME.spawn(task)
        }
    }
}

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
        zenoh::try_init_log_from_env();
        let runtime_conf = runtime.config().lock();
        let plugin_conf = runtime_conf
            .plugin(name)
            .ok_or_else(|| zerror!("Plugin `{}`: missing config", name))?;
        let conf: Config = serde_json::from_value(plugin_conf.clone())
            .map_err(|e| zerror!("Plugin `{}` configuration error: {}", name, e))?;
        WORK_THREAD_NUM.store(conf.work_thread_num, Ordering::SeqCst);
        MAX_BLOCK_THREAD_NUM.store(conf.max_block_thread_num, Ordering::SeqCst);

        spawn_runtime(run(runtime.clone(), conf));

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
            if selector.parameters().get("_method") == Some("SUB") {
                tracing::debug!("Subscribe to {} for Multipart stream", selector.key_expr());
                let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
                let c_selector = selector.key_expr().clone().into_owned();
                tokio::task::spawn(async move {
                    tracing::debug!("Subscribe to {} for Multipart stream", c_selector);
                    let sub = req.state().declare_subscriber(c_selector).await.unwrap();
                    loop {
                        let sample = sub.recv_async().await.unwrap();
                        let mut buf = "--boundary\nContent-Type: ".as_bytes().to_vec();
                        buf.extend_from_slice(sample.encoding().to_string().as_bytes());
                        buf.extend_from_slice("\n\n".as_bytes());
                        buf.extend_from_slice(sample.payload().to_bytes().as_ref());

                        match tokio::time::timeout(
                            std::time::Duration::new(10, 0),
                            sender.send(Ok(buf)),
                        )
                        .await
                        {
                            Ok(Ok(_)) => {}
                            Ok(Err(e)) => {
                                tracing::debug!(
                                    "Multipart error ({})! Unsubscribe and terminate",
                                    e
                                );
                                if let Err(e) = sub.undeclare().await {
                                    tracing::error!("Error undeclaring subscriber: {}", e);
                                }
                                break;
                            }
                            Err(_) => {
                                tracing::debug!("Multipart timeout! Unsubscribe and terminate",);
                                if let Err(e) = sub.undeclare().await {
                                    tracing::error!("Error undeclaring subscriber: {}", e);
                                }
                                break;
                            }
                        }
                    }
                });

                let receiver = async_stream::stream! {
                      while let Some(item) = receiver.recv().await {
                          yield item;
                      }
                };
                let mut res = Response::new(StatusCode::Ok);
                res.set_content_type("multipart/x-mixed-replace; boundary=\"boundary\"");
                res.set_body(tide::Body::from_reader(
                    Box::pin(receiver.into_async_read()),
                    None,
                ));

                Ok(res)
            } else {
                match zenoh_get(session, &selector).await {
                    Ok(Some(sample)) => Ok(response_with_value(sample)),
                    Ok(None) => {
                        // Check if considering the URL as a directory, there is an existing "URL/DirectoryIndex" resource
                        let mut new_selector = selector.key_expr().as_str().to_string();
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
    res.set_body(payload.to_bytes().as_ref());
    res
}
