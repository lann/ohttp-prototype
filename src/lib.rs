use std::convert::Infallible;

use anyhow::Context;
use bytes::Bytes;
use http::{
    header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE},
    HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri,
};
use http_body_util::{combinators::BoxBody, BodyExt};
use wasi::http::types::{IncomingRequest, ResponseOutparam};
use wasi_hyperium::{
    hyperium1::{handle_service_call, send_outbound_request},
    poll::Poller,
    IncomingHttpBody,
};

struct Guest;

wasi::http::proxy::export!(Guest);

impl wasi::exports::http::incoming_handler::Guest for Guest {
    fn handle(request: IncomingRequest, response_out: ResponseOutparam) {
        let svc = tower::service_fn(handle_request);
        handle_service_call(svc, request, response_out, poller()).unwrap()
    }
}

type Response = http::Response<BoxBody<Bytes, wasi_hyperium::Error>>;

static ALLOWED_CONTENT_TYPES: &[&HeaderValue] = {
    static OHTTP_REQ: HeaderValue = HeaderValue::from_static("message/ohttp-req");
    static OHTTP_CHUNKED_REQ: HeaderValue = HeaderValue::from_static("message/ohttp-chunked-req");
    &[&OHTTP_REQ, &OHTTP_CHUNKED_REQ]
};

async fn handle_request(req: Request<IncomingHttpBody<Poller>>) -> Result<Response, Infallible> {
    if req.method() != Method::POST {
        eprintln!("Bad method: {}", req.method());
        return Ok(error_response(StatusCode::METHOD_NOT_ALLOWED));
    }

    let content_type = req.headers().get(CONTENT_TYPE);
    if !content_type.is_some_and(|val| ALLOWED_CONTENT_TYPES.contains(&val)) {
        eprintln!("Bad content-type: {content_type:?}");
        return Ok(error_response(StatusCode::NOT_ACCEPTABLE));
    }

    Ok(match forward_request(req).await {
        Ok(resp) => resp,
        Err(err) => {
            eprintln!("Error: {err:?}");
            error_response(StatusCode::INTERNAL_SERVER_ERROR)
        }
    })
}

async fn forward_request(mut req: Request<IncomingHttpBody<Poller>>) -> anyhow::Result<Response> {
    let gateway_url =
        spin_sdk::variables::get("gateway_url").context("couldn't get gateway_url")?;

    *req.uri_mut() = Uri::from_maybe_shared(gateway_url).context("invalid gateway_url")?;
    filter_headers(req.headers_mut());

    let resp = send_outbound_request(req, poller())
        .await
        .context("failed sending gateway request")?;

    Ok(resp.map(|body| body.boxed()))
}

fn filter_headers(headers: &mut HeaderMap) {
    const ALLOWED_HEADERS: &[HeaderName] = &[ACCEPT, CONTENT_LENGTH, CONTENT_TYPE];
    headers
        .keys()
        .filter(|key| !ALLOWED_HEADERS.contains(key))
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .for_each(|key| {
            headers.remove(key);
        })
}

fn error_response(status_code: StatusCode) -> Response {
    let mut resp = Response::default();
    *resp.status_mut() = status_code;
    resp
}

fn poller() -> Poller {
    // We know we're single-threaded
    static mut POLLER: Option<Poller> = None;
    #[allow(static_mut_refs)]
    unsafe {
        POLLER.get_or_insert_default().clone()
    }
}
