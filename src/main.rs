mod features_from_query_parameter;
mod get;
mod get_polyfill_string;
mod old_ua;
mod parse;
mod polyfill_parameters;
mod toposort;
mod ua;
mod useragent;

use crate::features_from_query_parameter::features_from_query_parameter;
use crate::get::get;
use crate::get_polyfill_string::get_polyfill_string;
use fastly::cache::simple::{get_or_set_with, CacheEntry};
use fastly::http::{header, Method, StatusCode};
use fastly::{Error, Request, Response};
use polyfill_parameters::PolyfillParameters;
use regex::Regex;
use std::collections::HashMap;
use urlencoding::decode;

use std::time::Duration;

#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
    // fastly::log::set_panic_endpoint("slack").unwrap();
    // let endpoint = Endpoint::from_name("slack");
    // Log service version
    println!(
        "FASTLY_SERVICE_VERSION: {}",
        std::env::var("FASTLY_SERVICE_VERSION").unwrap_or_else(|_| String::new())
    );
    let url = req.get_url_str().to_string();
    println!("url: {}", url);
    std::panic::set_hook(Box::new(move |info| {
        eprintln!(
            "FASTLY_SERVICE_VERSION: {}\nurl: {}\n{}",
            std::env::var("FASTLY_SERVICE_VERSION").unwrap_or_else(|_| String::new()),
            url.clone(),
            info.to_string()
        );
    }));

    let method = req.get_method();
    let path = req.get_path();
    if method == Method::POST && path == "/__panic" {
        panic!("{}", req.into_body_str_lossy());
    }
    if method == Method::OPTIONS {
        return Ok(
            Response::from_status(StatusCode::OK)
            .with_header("allow", "OPTIONS, GET, HEAD")
            .with_header("Cache-Control", "public, s-maxage=31536000, max-age=604800, stale-while-revalidate=604800, stale-if-error=604800, immutable")
        );
    } else if method != Method::GET && method != Method::HEAD {
        return Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
            .with_header(header::ALLOW, "GET, HEAD")
            .with_body_text_plain("This method is not allowed\n"));
    };
    match path {
        "/" => {
            Ok(
                Response::from_status(StatusCode::PERMANENT_REDIRECT)
                .with_header("Location", "/v3/")
                .with_header("Cache-Control", "public, s-maxage=31536000, max-age=604800, stale-while-revalidate=604800, stale-if-error=604800, immutable")
            )
        },
        "/robots.txt" => {
            Ok(Response::from_body("User-agent: *\nDisallow:"))
        },
        "/v1" => {
            Ok(
                Response::from_status(StatusCode::PERMANENT_REDIRECT)
                .with_header("Location", "/v3/")
                .with_header("Cache-Control", "public, s-maxage=31536000, max-age=604800, stale-while-revalidate=604800, stale-if-error=604800, immutable")
            )
        },

        _ => {
            if req.get_path().starts_with("/v1/") {
                return Ok(
                    Response::from_status(StatusCode::PERMANENT_REDIRECT)
                    .with_header("Location", String::from("/v2") + &req.get_path()[3..])
                    .with_header("Cache-Control", "public, s-maxage=31536000, max-age=604800, stale-while-revalidate=604800, stale-if-error=604800, immutable")
                )
            }
            if req.get_path() == "/v2/polyfill.js" || req.get_path() == "/v2/polyfill.min.js" {
                req.set_path(&(String::from("/v3") + &req.get_path()[3..]));

                let mut search_params: HashMap<String, String> = req.get_query().unwrap();
                search_params.insert("version".to_string(), "3.25.1".to_string());
                if !search_params.contains_key("unknown") {
                    search_params.insert("unknown".to_string(), "ignore".to_string());
                }
                req.set_query(&search_params).unwrap();
            }

            if (req.get_path().starts_with("/v2/") || req.get_path() == "/v2") && !(req.get_path().starts_with("/v2/polyfill.") && req.get_path().ends_with("js")) {
                return Ok(
                    Response::from_status(StatusCode::PERMANENT_REDIRECT)
                    .with_header("Location", "/v3/")
                    .with_header("Cache-Control", "public, s-maxage=31536000, max-age=604800, stale-while-revalidate=604800, stale-if-error=604800, immutable")
                )
            }

            if req.get_path() == "/v3/polyfill.min.js" || req.get_path() == "/v3/polyfill.js" {
                Ok(polyfill(&req))
            } else {
                let res = get("site", req)?;
                Ok(res.unwrap_or_else(|| {
                    Response::from_status(StatusCode::NOT_FOUND).with_body("Not Found")
                    .with_header("Cache-Control", "public, s-maxage=31536000, max-age=604800, stale-while-revalidate=604800, stale-if-error=604800, immutable")
                }))
            }
        }
    }
}

fn get_polyfill_parameters(request: &Request) -> PolyfillParameters {
    let query: HashMap<String, String> = request.get_query().unwrap();
    let path = request.get_path();
    let excludes = query
        .get("excludes")
        .map(|f| {
            decode(f)
                .map(|f| f.to_string())
                .unwrap_or_else(|_| f.to_string())
        })
        .unwrap_or_else(|| "".to_owned());
    let features = query
        .get("features")
        .map(|f| {
            decode(f)
                .map(|f| f.to_string())
                .unwrap_or_else(|_| f.to_string())
        })
        .unwrap_or_else(|| "default".to_owned());
    let unknown = query
        .get("unknown")
        .map(|f| f.to_owned())
        .unwrap_or_else(|| "polyfill".to_owned());
    let version = query
        .get("version")
        .map(|f| f.to_owned())
        .map(|f| {
            if f.is_empty() {
                "3.111.0".to_owned()
            } else {
                f
            }
        })
        .unwrap_or_else(|| "3.111.0".to_owned());
    let callback = query
        .get("callback")
        .filter(|callback| Regex::new(r"^[\w.]+$").unwrap().is_match(callback))
        .map(|callback| callback.to_owned());
    let ua_string = query.get("ua").map(|f| f.to_owned()).unwrap_or_else(|| {
        request
            .get_header_str("user-agent")
            .unwrap_or_default()
            .to_owned()
    });
    let flags = query
        .get("flags")
        .map(|f| f.to_owned())
        .unwrap_or_else(|| "".to_owned());

    let strict = query.contains_key("strict");

    return PolyfillParameters {
        excludes: if !excludes.is_empty() {
            excludes.split(',').map(|e| e.to_owned()).collect()
        } else {
            vec![]
        },
        features: features_from_query_parameter(&features, &flags),
        minify: path.ends_with(".min.js"),
        callback,
        unknown,
        ua_string,
        version,
        strict,
    };
}

fn polyfill(request: &Request) -> Response {
    let parameters = get_polyfill_parameters(request);

    let library = match parameters.version.as_str() {
        "3.25.1" => "polyfill-library-3.25.1",
        "3.27.4" => "polyfill-library-3.27.4",
        "3.34.0" => "polyfill-library-3.34.0",
        "3.39.0" => "polyfill-library-3.39.0",
        "3.40.0" => "polyfill-library-3.40.0",
        "3.41.0" => "polyfill-library-3.41.0",
        "3.42.0" => "polyfill-library-3.42.0",
        "3.46.0" => "polyfill-library-3.46.0",
        "3.48.0" => "polyfill-library-3.48.0",
        "3.50.2" => "polyfill-library-3.50.2",
        "3.51.0" => "polyfill-library-3.51.0",
        "3.52.0" => "polyfill-library-3.52.0",
        "3.52.1" => "polyfill-library-3.52.1",
        "3.52.2" => "polyfill-library-3.52.2",
        "3.52.3" => "polyfill-library-3.52.3",
        "3.53.1" => "polyfill-library-3.53.1",
        "3.89.4" => "polyfill-library-3.89.4",
        "3.96.0" => "polyfill-library-3.96.0",
        "3.98.0" => "polyfill-library-3.98.0",
        "3.101.0" => "polyfill-library-3.101.0",
        "3.103.0" => "polyfill-library-3.103.0",
        "3.104.0" => "polyfill-library-3.104.0",
        "3.108.0" => "polyfill-library-3.108.0",
        "3.109.0" => "polyfill-library-3.109.0",
        "3.110.1" => "polyfill-library-3.110.1",
        "3.111.0" => "polyfill-library-3.111.0",
        _ => {
            return Response::from_status(StatusCode::BAD_REQUEST)
            .with_header("Cache-Control", "public, s-maxage=31536000, max-age=604800, stale-while-revalidate=604800, stale-if-error=604800, immutable")
            .with_body("requested version does not exist");
        }
    };
    let version = parameters.version.clone();
    let is_running_locally =
        std::env::var("FASTLY_HOSTNAME").unwrap_or_else(|_| String::new()) == "localhost";
    let bundle = if !is_running_locally {
        let fastly_service_version = std::env::var("FASTLY_SERVICE_VERSION").unwrap();
        get_or_set_with(
            fastly_service_version + &request.get_url_str().to_owned(),
            || {
                Ok(CacheEntry {
                    value: get_polyfill_string(&parameters, library, &version),
                    ttl: Duration::from_secs(600),
                })
            },
        )
        .unwrap()
        .expect("closure always returns `Ok`, so we have a value")
    } else {
        get_polyfill_string(&parameters, library, &version)
    };
    Response::from_body(bundle)
        .with_header("x-compress-hint", "on")
        .with_header("Content-Type", "text/javascript; charset=UTF-8")
}
