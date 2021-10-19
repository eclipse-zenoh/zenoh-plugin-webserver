//
// Copyright (c) 2017, 2020 ADLINK Technology Inc.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ADLINK zenoh team, <zenoh@adlink-labs.tech>
//
use async_std::sync::Arc;
use clap::{Arg, ArgMatches};
use futures::prelude::*;
use log::debug;
use std::str::FromStr;
use tide::http::Mime;
use tide::{Request, Response, Server, StatusCode};
use zenoh::buf::ZBuf;
use zenoh::net::runtime::Runtime;
use zenoh::{prelude::*, Session};
use zenoh_plugin_trait::{prelude::*, PluginId};

const PORT_SEPARATOR: char = ':';
const DEFAULT_HTTP_HOST: &str = "0.0.0.0";
const DEFAULT_HTTP_PORT: &str = "80";
const DEFAULT_DIRECTORY_INDEX: &str = "index.html";

const GIT_VERSION: &str = git_version::git_version!(prefix = "v", cargo_prefix = "v");
lazy_static::lazy_static! {
    static ref LONG_VERSION: String = format!("{} built with {}", GIT_VERSION, env!("RUSTC_VERSION"));
    static ref DEFAULT_MIME: Mime = Encoding::APP_OCTET_STREAM.to_mime().unwrap();
}

pub struct WebServerPlugin;

impl Plugin for WebServerPlugin {
    type Requirements = Vec<Arg<'static, 'static>>;

    type StartArgs = (Runtime, ArgMatches<'static>);

    fn compatibility() -> zenoh_plugin_trait::PluginId {
        PluginId {
            uid: "zenoh-plugin-webserver",
        }
    }

    fn get_requirements() -> Self::Requirements {
        vec![
            Arg::from_usage("--web-server-port 'The Web Server plugin's http port'")
                .default_value(DEFAULT_HTTP_PORT),
        ]
    }

    fn start(
        (runtime, args): &Self::StartArgs,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<dyn std::error::Error>> {
        async_std::task::spawn(run(runtime.clone(), args.to_owned()));
        Ok(Box::new(()))
    }
}

zenoh_plugin_trait::declare_plugin!(WebServerPlugin);

async fn run(runtime: Runtime, args: ArgMatches<'_>) {
    env_logger::init();
    debug!("WebServer plugin {}", LONG_VERSION.as_str());

    let http_port = parse_http_port(args.value_of("web-server-port").unwrap());

    let zenoh = Session::init(runtime, true, vec![], vec![]).await;

    let mut app = Server::with_state(Arc::new(zenoh));

    app.at("*").get(handle_request);

    if let Err(e) = app.listen(http_port).await {
        log::error!("Unable to start http server for REST : {:?}", e);
    }
}

fn parse_http_port(arg: &str) -> String {
    match arg.split(':').count() {
        1 => {
            match arg.parse::<u16>() {
                Ok(_) => [DEFAULT_HTTP_HOST, arg].join(&PORT_SEPARATOR.to_string()), // port only
                Err(_) => [arg, DEFAULT_HTTP_PORT].join(&PORT_SEPARATOR.to_string()), // host only
            }
        }
        _ => arg.to_string(),
    }
}

async fn handle_request(req: Request<Arc<Session>>) -> tide::Result<Response> {
    let session = req.state();

    // Reconstruct Selector from req.url() (no easier way...)
    let url = req.url();
    log::debug!("GET on {}", url);

    // Build corresponding Selector
    let mut selector = String::with_capacity(url.as_str().len());
    selector.push_str(url.path());

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

    match zenoh_get(session, &selector).await {
        Ok(Some(value)) => Ok(response_with_value(value)),
        Ok(None) => {
            // Check if considering the URL as a directory, there is an existing "URL/DirectoryIndex" resource
            selector.push('/');
            selector.push_str(DEFAULT_DIRECTORY_INDEX);
            if let Ok(Some(_)) = zenoh_get(session, &selector).await {
                // In this case, we must reply a redirection to the URL as a directory
                Ok(redirect(&format!("{}/", url.path())))
            } else {
                Ok(not_found())
            }
        }
        Err(e) => Ok(internal_error(&e.to_string())),
    }
}

async fn zenoh_get(session: &Session, selector: &str) -> ZResult<Option<Value>> {
    let mut stream = session.get(selector).await?;
    Ok(stream.next().await.map(|reply| reply.data.value))
}

fn response_with_value(value: Value) -> Response {
    response_ok(
        value
            .encoding
            .to_mime()
            .unwrap_or_else(|_| DEFAULT_MIME.clone()),
        value.payload,
    )
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
    res.set_body(payload.contiguous().as_slice());
    res
}
