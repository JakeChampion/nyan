use fastly::KVStore;
use fastly::http::{header, Method, StatusCode};
use fastly::Body;
use fastly::ConfigStore;
use fastly::{Error, Request, Response};
use regex::Regex;
use semver::Version;
use semver::VersionReq;
use serde::Deserialize;
use std::collections::HashMap;
use std::collections::HashSet;
use std::iter::FromIterator;
use std::time::Duration;
use fastly::cache::simple::{get_or_set_with, CacheEntry};

fn toposort(nodes: Vec<String>, edges: Vec<(String, String)>) -> Result<Vec<String>, String> {
    let mut cursor = nodes.len();
    let mut sorted: Vec<String> = vec!["".to_string(); cursor];
    let mut visited: HashMap<u32, bool> = HashMap::new();
    let mut i = cursor as u32;
    let outgoing_edges = make_outgoing_edges(&edges);
    let nodes_hash = make_nodes_hash(&nodes);

    for edge in &edges {
        if !nodes_hash.contains_key(&edge.0) || !nodes_hash.contains_key(&edge.1) {
            return Err("Unknown node. There is an unknown node in the supplied edges.".to_string());
        }
    }

    while i > 0 {
        i -= 1;
        if !visited.contains_key(&i) {
            visit(nodes.get(i as usize).unwrap().to_string(), i, &mut HashSet::new(), &mut visited, &outgoing_edges, &nodes_hash, &mut sorted, &mut cursor)?;
        }
    }

    Ok(sorted)
}

fn visit(
    node: String,
    i: u32,
    predecessors: &mut HashSet<String>,
    visited: &mut HashMap<u32, bool>,
    outgoing_edges: &HashMap<String, HashSet<String>>,
    nodes_hash: &HashMap<String, usize>,
    sorted: &mut Vec<String>,
    cursor: &mut usize
) -> Result<(), String> {
    if predecessors.contains(&node) {
        let node_rep = format!(", node was: {}", node);
        return Err(format!("Cyclic dependency{}", node_rep));
    }

    if !nodes_hash.contains_key(&node) {
        return Err(format!(
            "Found unknown node. Make sure to provide all involved nodes. Unknown node: {}",
            node
        ));
    }

    if visited.contains_key(&i) {
        return Ok(());
    }
    visited.insert(i, true);

    let outgoing = outgoing_edges.get(&node).unwrap_or(&HashSet::new()).clone();
    let outgoing: Vec<String> = outgoing.iter().cloned().collect();

    let mut i = outgoing.len() as usize;
    if i > 0 {
        predecessors.insert(node.clone());
        while i > 0 {
            i -= 1;
            let child = outgoing.get(i).unwrap();
            visit(child.to_string(), *nodes_hash.get(child).unwrap() as u32, predecessors, visited, outgoing_edges, nodes_hash, sorted, cursor)?;
        }
        predecessors.remove(&node);
    }

    sorted[cursor.clone() - 1] = node;
    *cursor -= 1;

    Ok(())
}

fn make_outgoing_edges(arr: &Vec<(String, String)>) -> HashMap<String, HashSet<String>> {
    let mut edges: HashMap<String, HashSet<String>> = HashMap::new();
    for edge in arr {
        edges.entry(edge.0.clone()).or_insert_with(HashSet::new).insert(edge.1.clone());
        edges.entry(edge.1.clone()).or_insert_with(HashSet::new);
    }
    edges
}

fn make_nodes_hash(arr: &Vec<String>) -> HashMap<String, usize> {
    let mut res: HashMap<String, usize> = HashMap::new();
    for (i, &ref node) in arr.iter().enumerate() {
        res.insert(node.to_string(), i);
    }
    res
}

#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
    // Log service version
    println!(
        "FASTLY_SERVICE_VERSION: {}",
        std::env::var("FASTLY_SERVICE_VERSION").unwrap_or_else(|_| String::new())
    );

    let method = req.get_method();
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
    // app.use('*', logger());
    // let isRunningLocally;
    // app.use('*', (c, next) => {
    //     let fastlyHostname = env("FASTLY_HOSTNAME");
    //     isRunningLocally = fastlyHostname == "localhost";
    //     return next();
    // });

    // app.get('/v3/', () => {
    //     return new HTMLResponse(home())
    // })
    match req.get_path() {
        "/" => {
            return Ok(
                Response::from_status(StatusCode::PERMANENT_REDIRECT)
                .with_header("Location", "/v3/")
                .with_header("Cache-Control", "public, s-maxage=31536000, max-age=604800, stale-while-revalidate=604800, stale-if-error=604800, immutable")
            )
        },
        "/robots.txt" => {
            return Ok(Response::from_body("User-agent: *\nDisallow:"))
        },
        "/v1" => {
            return Ok(
                Response::from_status(StatusCode::PERMANENT_REDIRECT)
                .with_header("Location", "/v3/")
                .with_header("Cache-Control", "public, s-maxage=31536000, max-age=604800, stale-while-revalidate=604800, stale-if-error=604800, immutable")
            )
        },

        // Catch all other requests and return a 404.
        _ => {
            if req.get_path().starts_with("/v1/") {
                return Ok(
                    Response::from_status(StatusCode::PERMANENT_REDIRECT)
                    .with_header("Location", String::from("/v2") + &req.get_path()[3..])
                    .with_header("Cache-Control", "public, s-maxage=31536000, max-age=604800, stale-while-revalidate=604800, stale-if-error=604800, immutable")
                )
            }
            // let requestURL = req.get_url_mut();
            if req.get_path() == "/v2/polyfill.js" || req.get_path() == "/v2/polyfill.min.js" {
                req.set_path(&(String::from("/v3") + &req.get_path()[3..]));

                let mut search_params: HashMap<String, String> = req.get_query().unwrap();
                search_params.insert("version".to_string(), "3.25.1".to_string());
                if !search_params.contains_key("unknown") {
                    search_params.insert("unknown".to_string(), "ignore".to_string());
                }
                req.set_query(&search_params).unwrap();
            }

            if req.get_path().starts_with("/v2/") || req.get_path() == "/v2" {
                if !(req.get_path().starts_with("/v2/polyfill.") && req.get_path().ends_with("js")) {
                    return Ok(
                        Response::from_status(StatusCode::PERMANENT_REDIRECT)
                        .with_header("Location", "/v3/")
                        .with_header("Cache-Control", "public, s-maxage=31536000, max-age=604800, stale-while-revalidate=604800, stale-if-error=604800, immutable")
                    )
                }
            }

            if req.get_path() == "/v3/polyfill.min.js" || req.get_path() == "/v3/polyfill.js" {
                // requestURL.search = normalise_querystring_parameters_for_polyfill_bundle(
                //     c.req,
                //     requestURL.searchParams
                // ).toString();
                let backend_response = polyfill(&req);
                return Ok(backend_response);
            } else {
                return Ok(
                    Response::from_status(StatusCode::NOT_FOUND)
                    .with_header("Cache-Control", "public, s-maxage=31536000, max-age=604800, stale-while-revalidate=604800, stale-if-error=604800, immutable")
                )
            }
        }
    }
}

fn features_from_query_parameter(
    features_parameter: &String,
    flags_parameter: &String,
) -> HashMap<String, HashSet<String>> {
    let features: Vec<String> = features_parameter
        .split(",")
        .filter(|f| f.len() > 0)
        .map(|f| f.to_owned())
        .collect();
    let global_flags: Vec<String> = flags_parameter.split(",").map(|f| f.to_owned()).collect();
    let mut features_with_flags: HashMap<String, HashSet<String>> = HashMap::new();

    for feature in features {
        // Eliminate XSS vuln
        let safe_feature = feature.replace("*/", "");
        let mut things: Vec<String> = safe_feature.split("|").map(|f| f.to_owned()).collect();
        let name = things.remove(0);
        things.append(&mut global_flags.clone());
        let feature_specific_flags = things;
        features_with_flags.insert(
            name.replace("?", ""),
            HashSet::from_iter(feature_specific_flags),
        );
    }

    if features_with_flags.contains_key("all") {
        features_with_flags.insert("default".to_owned(), features_with_flags["all"].clone());
        features_with_flags.remove("all");
    }

    return features_with_flags;
}

#[derive(Clone, Default)]
struct PolyfillParameters {
    excludes: Vec<String>,
    features: HashMap<String, HashSet<String>>,
    minify: bool,
    callback: Option<String>,
    unknown: String,
    ua_string: String,
    version: String,
    // strict: bool,
}

fn get_polyfill_parameters(request: &Request) -> PolyfillParameters {
    let query: HashMap<String, String> = request.get_query().unwrap();
    let path = request.get_path();
    let excludes = query
        .get("excludes")
        .map(|f| f.to_owned())
        .unwrap_or_else(|| "".to_owned());
    let features = query
        .get("features")
        .map(|f| f.to_owned())
        .unwrap_or_else(|| "default".to_owned());
    let unknown = query
        .get("unknown")
        .map(|f| f.to_owned())
        .unwrap_or_else(|| "polyfill".to_owned());
    let version = query
        .get("version")
        .map(|f| f.to_owned())
        .unwrap_or_else(|| "3.111.0".to_owned());
    // let callback = query.get("callback");
    let ua_string = query
        .get("ua")
        .map(|f| f.to_owned())
        .unwrap_or_else(|| "".to_owned());
    let flags = query
        .get("flags")
        .map(|f| f.to_owned())
        .unwrap_or_else(|| "".to_owned());

    // let strict = query.contains_key("strict");

    return PolyfillParameters {
        excludes: if !excludes.is_empty() {
            excludes.split(",").map(|e| e.to_owned()).collect()
        } else {
            vec![]
        },
        features: features_from_query_parameter(&features, &flags),
        minify: path.ends_with(".min.js"),
        // callback: /^[\w.]+$/.test(callback || "") ? callback : false,
        callback: None,
        unknown,
        ua_string,
        version,
        // strict,
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
    let bundle = get_or_set_with(request.get_url_str().to_owned(), || {
        Ok(CacheEntry {
            value: get_polyfill_string(parameters, library.to_owned(), version),
            ttl: Duration::from_secs(60 * 1),
        })
    })
    .unwrap()
    .expect("closure always returns `Ok`, so we have a value");
    // return respondWithBundle(c, bundle);
    return Response::from_body(bundle);
}

#[derive(Clone, Default)]
struct Feature {
    alias_of: HashSet<String>,
    dependency_of: HashSet<String>,
    flags: HashSet<String>,
    comment: Option<String>,
}

fn remove_feature(
    feature_name: String,
    feature_names: &mut HashSet<String>,
    targeted_features: &mut HashMap<String, Feature>,
) -> bool {
    targeted_features.remove(&feature_name);
    return feature_names.remove(&feature_name);
}

fn add_feature(
    feature_name: String,
    feature: Feature,
    feature_names: &mut HashSet<String>,
    targeted_features: &mut HashMap<String, Feature>,
) -> bool {
    // targeted_features[feature_name] = Object.assign(Object.create(null), featureFlags, featureProperties);
    targeted_features.insert(
        feature_name.clone(),
        feature,
    );
    return feature_names.insert(feature_name);
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct Browsers {
    android: Option<String>,
    bb: Option<String>,
    chrome: Option<String>,
    edge: Option<String>,
    edge_mob: Option<String>,
    firefox: Option<String>,
    firefox_mob: Option<String>,
    ie: Option<String>,
    ie_mob: Option<String>,
    ios_saf: Option<String>,
    op_mini: Option<String>,
    opera: Option<String>,
    safari: Option<String>,
    samsung_mob: Option<String>,
}

// #[derive(Clone, Deserialize)]
// struct Install {
//     module: String,
//     paths: Option<Vec<String>>,
// }

#[derive(Clone, Deserialize)]
struct PolyfillConfig {
    license: Option<String>,
    // repo: Option<String>,
    // install: Option<Install>,
    // aliases: Vec<String>,
    dependencies: Option<Vec<String>>,
    // spec: Option<String>,
    // docs: Option<String>,
    // notes: Option<Vec<String>>,
    browsers: HashMap<String, String>,
    detect_source: Option<String>,
    // base_dir: Option<String>,
    // has_tests: Option<bool>,
    // is_testable: Option<bool>,
    // is_public: Option<bool>,
    // size: Option<usize>,
}

fn get_polyfill_meta(store: String, feature_name: String) -> Option<PolyfillConfig> {
    if feature_name.is_empty() {
        return None;
    }
    let n = store.replace('-', "_").replace('.', "_");
    let config = ConfigStore::open(&n);
    let meta = config.get(&feature_name);
    return meta.map(|m| serde_json::from_str(&m).unwrap());
}

fn get_config_aliases(store: String, alias: String) -> Option<Vec<String>> {
    if alias.is_empty() {
        return None;
    }
    let n = store.replace('-', "_").replace('.', "_");
    let aliases = ConfigStore::open(&(n + "_aliases"));
    return aliases
        .get(&alias)
        .map(|m| serde_json::from_str(&m).unwrap());
}

struct UA {
    version: String,
    family: String,
    // major: String,
    // minor: String,
    // patch: String,
}

impl UA {
    fn new(ua_string: String) -> UA {
        let mut family: String;
        let mut major: String;
        let mut minor: String;
        // let mut patch: String = "0".to_owned();
        let re: Regex = Regex::new(r"(?i)^(\w+)\/(\d+)(?:\.(\d+){2})?$").unwrap();
        if let Some(normalized) = re.captures(&ua_string) {
            family = normalized
                .get(1)
                .map(|f| Into::<&str>::into(f))
                .unwrap()
                .into();
            major = normalized
                .get(2)
                .map(|f| Into::<&str>::into(f))
                .unwrap()
                .into();
            minor = normalized
                .get(3)
                .map(|f| Into::<&str>::into(f))
                .or_else(|| Some("0"))
                .unwrap()
                .to_owned();
        } else {
            // Google Search iOS app should be detected as the underlying browser, which is safari on iOS
            let ua_string = Regex::new(r"(?i) GSA\/[\d.]+")
                .unwrap()
                .replace(&ua_string, "");

            // Instagram should be detected as the underlying browser, which is safari on ios
            let ua_string = Regex::new(r"(?i) Instagram [\d.]+")
                .unwrap()
                .replace(&ua_string, "");

            // WebPageTest is not a real browser, remove the token to find the underlying browser
            let ua_string = Regex::new(r"(?i) PTST\/[\d.]+")
                .unwrap()
                .replace(&ua_string, "");

            // Waterfox is a Firefox fork, we can remove the Waterfox identifiers and parse the result as Firefox
            let ua_string = Regex::new(r"(?i) Waterfox\/[\d.]+")
                .unwrap()
                .replace(&ua_string, "");

            // Pale Moon has a Firefox-compat UA string, we can remove the Pale Moon and Goanna identifiers and parse the result as Firefox
            let ua_string = Regex::new(r"(?i) Goanna\/[\d.]+")
                .unwrap()
                .replace(&ua_string, "");

            // Pale Moon has a Firefox-compat UA string, we can remove the Pale Moon and Goanna identifiers and parse the result as Firefox
            let ua_string = Regex::new(r"(?i) PaleMoon\/[\d.]+")
                .unwrap()
                .replace(&ua_string, "");

            // Yandex browser is recognised by UA module but is actually Chromium under the hood, so better to remove the Yandex identifier and get the UA module to detect it as Chrome
            let ua_string = Regex::new(r"(?i)(YaBrowser)\/(\d+\.)+\d+ /")
                .unwrap()
                .replace(&ua_string, "");

            // Crosswalk browser is recognised by UA module but is actually Chromium under the hood, so better to remove the identifier and get the UA module to detect it as Chrome
            let ua_string = Regex::new(r"(?i) (Crosswalk)\/(\d+)\.(\d+)\.(\d+)\.(\d+)")
                .unwrap()
                .replace(&ua_string, "");

            // Chrome and Opera on iOS uses a UIWebView of the underlying platform to render content. By stripping the CriOS or OPiOS strings, the useragent parser will alias the user agent to ios_saf for the UIWebView, which is closer to the actual renderer
            let ua_string = Regex::new(
                r"(?i)((CriOS|OPiOS)\/(\d+)\.(\d+)\.(\d+)\.(\d+)|(FxiOS\/(\d+)\.(\d+)))",
            )
            .unwrap()
            .replace(&ua_string, "");

            // Vivaldi browser is recognised by UA module but is actually identical to Chrome, so the best way to get accurate targeting is to remove the vivaldi token from the UA
            let ua_string = Regex::new(r"(?i) vivaldi\/[\d.]+\d+")
                .unwrap()
                .replace(&ua_string, "");

            // Facebook in-app browser `[FBAN/.....]` or `[FB_IAB/.....]` (see https://github.com/Financial-Times/polyfill-servicessues/990)
            let ua_string = Regex::new(r"(?i) \[(FB_IAB|FBAN|FBIOS|FB4A)\/[^\]]+\]")
                .unwrap()
                .replace(&ua_string, "");

            // Electron/X.Y.Z` (see https://github.com/Financial-Times/polyfill-servicessues/1129)
            let ua_string = Regex::new(r"(?i) Electron\/[\d.]+\d+")
                .unwrap()
                .replace(&ua_string, "");

            // Chromium-based Edge
            let ua_string = Regex::new(r"(?i) Edg\/[\d.]+\d+")
                .unwrap()
                .replace(&ua_string, "");

            // Modern mobile Googlebot which uses modern Chrome
            let ua_string = Regex::new(
                r"(?i)Safari.* Googlebot\/2\.1; \+http:\/\/www\.google\.com\/bot\.html\)",
            )
            .unwrap()
            .replace(&ua_string, "");

            // Modern desktop Googlebot which uses modern Chrome
            let ua_string =
                Regex::new(r"(?i) Googlebot\/2\.1; \+http:\/\/www\.google\.com\/bot\.html\) ")
                    .unwrap()
                    .replace(&ua_string, "");

            let ua = useragent(ua_string.to_string());
            family = ua[0].clone();
            major = ua[1].clone();
            minor = ua[2].clone();
            // patch = ua[3].clone();
        }
        if family == "blackberry webkit" {
            family = "bb".to_owned();
        }
        if family == "blackberry" {
            family = "bb".to_owned();
        }
        if family == "pale moon (firefox variant)" {
            family = "firefox".to_owned();
        }
        if family == "pale moon" {
            family = "firefox".to_owned();
        }
        if family == "firefox mobile" {
            family = "firefox_mob".to_owned();
        }
        if family == "firefox namoroka" {
            family = "firefox".to_owned();
        }
        if family == "firefox shiretoko" {
            family = "firefox".to_owned();
        }
        if family == "firefox minefield" {
            family = "firefox".to_owned();
        }
        if family == "firefox alpha" {
            family = "firefox".to_owned();
        }
        if family == "firefox beta" {
            family = "firefox".to_owned();
        }
        if family == "microb" {
            family = "firefox".to_owned();
        }
        if family == "mozilladeveloperpreview" {
            family = "firefox".to_owned();
        }
        if family == "iceweasel" {
            family = "firefox".to_owned();
        }
        if family == "opera tablet" {
            family = "opera".to_owned();
        }
        if family == "opera mobile" {
            family = "op_mob".to_owned();
        }
        if family == "opera mini" {
            family = "op_mini".to_owned();
        }
        if family == "chrome mobile webview" {
            family = "chrome".to_owned();
        }
        if family == "chrome mobile" {
            family = "chrome".to_owned();
        }
        if family == "chrome frame" {
            family = "chrome".to_owned();
        }
        if family == "chromium" {
            family = "chrome".to_owned();
        }
        if family == "headlesschrome" {
            family = "chrome".to_owned();
        }
        if family == "ie mobile" {
            family = "ie_mob".to_owned();
        }
        if family == "ie large screen" {
            family = "ie".to_owned();
        }
        if family == "internet explorer" {
            family = "ie".to_owned();
        }
        if family == "edge mobile" {
            family = "edge_mob".to_owned();
        }
        if family == "uc browser" && major == "9" && minor == "9" {
            family = "ie".to_owned();
            major = "10".to_owned();
            minor = "0".to_owned();
        }
        if family == "chrome mobile ios" {
            family = "ios_chr".to_owned();
        }
        if family == "mobile safari" {
            family = "ios_saf".to_owned();
        }
        if family == "iphone" {
            family = "ios_saf".to_owned();
        }
        if family == "iphone simulator" {
            family = "ios_saf".to_owned();
        }
        if family == "mobile safari uiwebview" {
            family = "ios_saf".to_owned();
        }
        if family == "mobile safari ui/wkwebview" {
            family = "ios_saf".to_owned();
        }
        if family == "mobile safari/wkwebview" {
            family = "ios_saf".to_owned();
        }
        if family == "samsung internet" {
            family = "samsung_mob".to_owned();
        }
        if family == "phantomjs" {
            family = "safari".to_owned();
            major = "5".to_owned();
            minor = "0".to_owned();
        }
        if family == "opera" {
            if family == "opera" && major == "20" {
                family = "chrome".to_owned();
                major = "33".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "21" {
                family = "chrome".to_owned();
                major = "34".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "22" {
                family = "chrome".to_owned();
                major = "35".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "23" {
                family = "chrome".to_owned();
                major = "36".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "24" {
                family = "chrome".to_owned();
                major = "37".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "25" {
                family = "chrome".to_owned();
                major = "38".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "26" {
                family = "chrome".to_owned();
                major = "39".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "27" {
                family = "chrome".to_owned();
                major = "40".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "28" {
                family = "chrome".to_owned();
                major = "41".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "29" {
                family = "chrome".to_owned();
                major = "42".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "30" {
                family = "chrome".to_owned();
                major = "43".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "31" {
                family = "chrome".to_owned();
                major = "44".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "32" {
                family = "chrome".to_owned();
                major = "45".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "33" {
                family = "chrome".to_owned();
                major = "46".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "34" {
                family = "chrome".to_owned();
                major = "47".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "35" {
                family = "chrome".to_owned();
                major = "48".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "36" {
                family = "chrome".to_owned();
                major = "49".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "37" {
                family = "chrome".to_owned();
                major = "50".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "38" {
                family = "chrome".to_owned();
                major = "51".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "39" {
                family = "chrome".to_owned();
                major = "52".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "40" {
                family = "chrome".to_owned();
                major = "53".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "41" {
                family = "chrome".to_owned();
                major = "54".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "42" {
                family = "chrome".to_owned();
                major = "55".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "43" {
                family = "chrome".to_owned();
                major = "56".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "44" {
                family = "chrome".to_owned();
                major = "57".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "45" {
                family = "chrome".to_owned();
                major = "58".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "46" {
                family = "chrome".to_owned();
                major = "59".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "47" {
                family = "chrome".to_owned();
                major = "60".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "48" {
                family = "chrome".to_owned();
                major = "61".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "49" {
                family = "chrome".to_owned();
                major = "62".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "50" {
                family = "chrome".to_owned();
                major = "63".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "51" {
                family = "chrome".to_owned();
                major = "64".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "52" {
                family = "chrome".to_owned();
                major = "65".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "53" {
                family = "chrome".to_owned();
                major = "66".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "54" {
                family = "chrome".to_owned();
                major = "67".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "55" {
                family = "chrome".to_owned();
                major = "68".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "56" {
                family = "chrome".to_owned();
                major = "69".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "57" {
                family = "chrome".to_owned();
                major = "70".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "58" {
                family = "chrome".to_owned();
                major = "71".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "59" {
                family = "chrome".to_owned();
                major = "72".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "60" {
                family = "chrome".to_owned();
                major = "73".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "61" {
                family = "chrome".to_owned();
                major = "74".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "62" {
                family = "chrome".to_owned();
                major = "75".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "63" {
                family = "chrome".to_owned();
                major = "76".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "64" {
                family = "chrome".to_owned();
                major = "77".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "65" {
                family = "chrome".to_owned();
                major = "78".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "66" {
                family = "chrome".to_owned();
                major = "79".to_owned();
                minor = "0".to_owned();
            }
            if family == "opera" && major == "67" {
                family = "chrome".to_owned();
                major = "80".to_owned();
                minor = "0".to_owned();
            }
        }
        if family == "googlebot" {
            if family == "googlebot" && major == "2" && minor == "1" {
                family = "chrome".to_owned();
                major = "41".to_owned();
                minor = "0".to_owned();
            }
        }
        if family == "edge"
            || family == "edge_mob"
            || (family == "ie" && major.parse::<i32>().unwrap() >= 8)
            || (family == "ie_mob" && major.parse::<i32>().unwrap() >= 11)
            || (family == "chrome" && major.parse::<i32>().unwrap() >= 29)
            || (family == "safari" && major.parse::<i32>().unwrap() >= 9)
            || (family == "ios_saf" && major.parse::<i32>().unwrap() >= 9)
            || (family == "ios_chr" && major.parse::<i32>().unwrap() >= 9)
            || (family == "firefox" && major.parse::<i32>().unwrap() >= 38)
            || (family == "firefox_mob" && major.parse::<i32>().unwrap() >= 38)
            || (family == "android" && format!("{major}.{minor}").parse::<f32>().unwrap() >= 4.3)
            || (family == "opera" && major.parse::<i32>().unwrap() >= 33)
            || (family == "op_mob" && major.parse::<i32>().unwrap() >= 10)
            || (family == "op_mini" && major.parse::<i32>().unwrap() >= 5)
            || (family == "bb" && major.parse::<i32>().unwrap() >= 6)
            || (family == "samsung_mob" && major.parse::<i32>().unwrap() >= 4)
        {
            /*empty*/
        } else {
            family = "other".to_owned();
            major = "0".to_owned();
            minor = "0".to_owned();
            // patch = "0".to_owned();
        }

        let version = format!("{major}.{minor}.0");

        return UA {
            version,
            family: family.to_owned(),
            // major: major.to_owned(),
            // minor: minor.to_owned(),
            // patch: patch.to_owned(),
        };
    }

    fn get_family(&self) -> String {
        return self.family.clone();
    }

    // fn get_version(&self) -> String {
    //     return self.version.clone();
    // }

    fn satisfies(&self, range: String) -> bool {
        let req = VersionReq::parse(&range).unwrap();
        let version = Version::parse(&self.version).unwrap();
        return req.matches(&version);
    }

    // fn get_baseline(&self) -> String {
    //     return UA::get_baselines().get(&self.family).unwrap().to_string();
    // }

    fn meets_baseline(&self) -> bool {
        let family = &self.family;
        let range = format!(">={}", UA::get_baselines().get(family).unwrap());
        return self.satisfies(range);
    }

    fn is_unknown(&self) -> bool {
        return !UA::get_baselines().contains_key(&self.family) || !self.meets_baseline();
    }

    // fn normalize(ua_string: String) -> String {
    //     let ua = UA::new(ua_string);
    //     return format!("{}/{}", ua.family, ua.version);
    // }

    fn get_baselines() -> HashMap<String, String> {
        let mut b: HashMap<String, String> = HashMap::new();
        b.insert("edge".to_owned(), "*".to_owned());
        b.insert("edge_mob".to_owned(), "*".to_owned());
        b.insert("ie".to_owned(), "8".to_owned());
        b.insert("ie_mob".to_owned(), "11".to_owned());
        b.insert("chrome".to_owned(), "29".to_owned());
        b.insert("safari".to_owned(), "9".to_owned());
        b.insert("ios_saf".to_owned(), "9".to_owned());
        b.insert("ios_chr".to_owned(), "9".to_owned());
        b.insert("firefox".to_owned(), "38".to_owned());
        b.insert("firefox_mob".to_owned(), "38".to_owned());
        b.insert("android".to_owned(), "4.3".to_owned());
        b.insert("opera".to_owned(), "33".to_owned());
        b.insert("op_mob".to_owned(), "10".to_owned());
        b.insert("op_mini".to_owned(), "5".to_owned());
        b.insert("bb".to_owned(), "6".to_owned());
        b.insert("samsung_mob".to_owned(), "4".to_owned());
        return b;
    }
}

fn useragent(ua: String) -> [String; 4] {
    let family = "Other".to_owned();
    let major = "0".to_owned();
    let minor = "0".to_owned();
    let patch = "0".to_owned();
    if let Some(result) = Regex::new(r"Opera\/9\.80 \(.+(Opera Mini)\/(\d+)(?:\.(\d+)|)(?:\.(\d+)|)").unwrap().captures(&ua) {
            let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
            let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
            let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
            let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
            return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"Opera\/9\.80 \(.+(Opera Mini)\/(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
            let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
            let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
            let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
            return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/525\.18(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "3".to_owned();
              let minor="1".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/528\.18(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "4".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/531\.21(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "4".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/532\.9(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "4".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/532\+").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "5".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/533\.17(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "5".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/534\.12(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "5".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/534\.46(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "5".to_owned();
              let minor="1".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/536\.26(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "6".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/537\.51(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "7".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/600\.1(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "8".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/601\.1(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "9".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/601\.5(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "9".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/602\.1(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "10".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/602\.2(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "10".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/602\.3(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "10".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/602\.4(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "10".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/603\.1(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "10".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/603\.2(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "10".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/604\.1(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "11".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/604\.2(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "11".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/604\.3(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "11".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/604\.5(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "11".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/605\.1(?:\.\d+|) \(KHTML, like Gecko\) Version\/(\d+)\.?(\d+)?\.?(\d+)?.+?Mobile\/\w+\s(Safari)").unwrap().captures(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(iPod|iPhone|iPad).+OS (\d+)_(\d+) like Mac OS X\) AppleWebKit\/605\.1(?:\.\d+|) \(KHTML, like Gecko\) Mobile\/\w+").unwrap().captures(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/605\.1(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "11".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/606\.1(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "12".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/607\.1(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "12".to_owned();
              let minor="1".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).+AppleWebKit\/608\.2(?:\.\d+|)").unwrap().is_match(&ua) {
              let family = "Mobile Safari/WKWebView".to_owned();
              let major = "13".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(MQQBrowser\/Mini)(?:(\d+)(?:\.(\d+)|)(?:\.(\d+)|)|)").unwrap().captures(&ua) {
              let family = "QQ Browser Mini".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(MQQBrowser)(?:\/(\d+)(?:\.(\d+)|)(?:\.(\d+)|)|)").unwrap().captures(&ua) {
              let family = "QQ Browser Mobile".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(QQBrowser)(?:\/(\d+)(?:\.(\d+)\.(\d+)(?:\.(\d+)|)|)|)").unwrap().captures(&ua) {
              let family = "QQ Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(ESPN)[%20| ]+Radio\/(\d+)\.(\d+)\.(\d+) CFNetwork").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Antenna)\/(\d+) CFNetwork").unwrap().captures(&ua) {
              let family = "AntennaPod".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(TopPodcasts)Pro\/(\d+) CFNetwork").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(MusicDownloader)Lite\/(\d+)\.(\d+)\.(\d+) CFNetwork").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(.*)-iPad\/(\d+)(?:\.(\d+)|)(?:\.(\d+)|)(?:\.(\d+)|) CFNetwork").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(.*)-iPhone\/(\d+)(?:\.(\d+)|)(?:\.(\d+)|)(?:\.(\d+)|) CFNetwork").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(.*)\/(\d+)(?:\.(\d+)|)(?:\.(\d+)|)(?:\.(\d+)|) CFNetwork").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(espn\.go)").unwrap().is_match(&ua) {
              let family = "ESPN".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(espnradio\.com)").unwrap().is_match(&ua) {
              let family = "ESPN".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"ESPN APP$").unwrap().is_match(&ua) {
              let family = "ESPN".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(audioboom\.com)").unwrap().is_match(&ua) {
              let family = "AudioBoom".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r" (Rivo) RHYTHM").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(CFNetwork)(?:\/(\d+)\.(\d+)(?:\.(\d+)|)|)").unwrap().captures(&ua) {
              let family = "CFNetwork".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Pingdom\.com_bot_version_)(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "PingdomBot".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(PingdomTMS)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "PingdomBot".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r" (PTST)\/(\d+)(?:\.(\d+)|)$").unwrap().captures(&ua) {
              let family = "WebPageTest.org bot".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"X11; (Datanyze); Linux").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(NewRelicPinger)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "NewRelicPingerBot".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Tableau)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Tableau".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Salesforce)(?:.)\/(\d+)\.(\d?)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(\(StatusCake\))").unwrap().is_match(&ua) {
              let family = "StatusCakeBot".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(facebookexternalhit)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "FacebookBot".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"Google.*\/\+\/web\/snippet").unwrap().is_match(&ua) {
              let family = "GooglePlusBot".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"via ggpht\.com GoogleImageProxy").unwrap().is_match(&ua) {
              let family = "GmailImageProxy".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"YahooMailProxy; https:\/\/help\.yahoo\.com\/kb\/yahoo-mail-proxy-SLN28749\.html").unwrap().is_match(&ua) {
              let family = "YahooMailProxy".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Twitterbot)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Twitterbot".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"\/((?:Ant-|)Nutch|[A-z]+[Bb]ot|[A-z]+[Ss]pider|Axtaris|fetchurl|Isara|ShopSalad|Tailsweep)[ \-](\d+)(?:\.(\d+)|)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"\b(008|Altresium|Argus|BaiduMobaider|BoardReader|DNSGroup|DataparkSearch|EDI|Goodzer|Grub|INGRID|Infohelfer|LinkedInBot|LOOQ|Nutch|OgScrper|PathDefender|Peew|PostPost|Steeler|Twitterbot|VSE|WebCrunch|WebZIP|Y!J-BR[A-Z]|YahooSeeker|envolk|sproose|wminer)\/(\d+)(?:\.(\d+)|)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(MSIE) (\d+)\.(\d+)([a-z]\d|[a-z]|);.* MSIECrawler").unwrap().captures(&ua) {
              let family = "MSIECrawler".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(DAVdroid)\/(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Google-HTTP-Java-Client|Apache-HttpClient|Go-http-client|scalaj-http|http%20client|Python-urllib|HttpMonitor|TLSProber|WinHTTP|JNLP|okhttp|aihttp|reqwest|axios|unirest-(?:java|python|ruby|nodejs|php|net))(?:[ /](\d+)(?:\.(\d+)|)(?:\.(\d+)|)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Pinterest(?:bot|))\/(\d+)(?:\.(\d+)|)(?:\.(\d+)|)[;\s(]+\+https:\/\/www.pinterest.com\/bot.html").unwrap().captures(&ua) {
              let family = "Pinterestbot".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(CSimpleSpider|Cityreview Robot|CrawlDaddy|CrawlFire|Finderbots|Index crawler|Job Roboter|KiwiStatus Spider|Lijit Crawler|QuerySeekerSpider|ScollSpider|Trends Crawler|USyd-NLP-Spider|SiteCat Webbot|BotName\/\$BotVersion|123metaspider-Bot|1470\.net crawler|50\.nu|8bo Crawler Bot|Aboundex|Accoona-[A-z]{1,30}-Agent|AdsBot-Google(?:-[a-z]{1,30}|)|altavista|AppEngine-Google|archive.{0,30}\.org_bot|archiver|Ask Jeeves|[Bb]ai[Dd]u[Ss]pider(?:-[A-Za-z]{1,30})(?:-[A-Za-z]{1,30}|)|bingbot|BingPreview|blitzbot|BlogBridge|Bloglovin|BoardReader Blog Indexer|BoardReader Favicon Fetcher|boitho.com-dc|BotSeer|BUbiNG|\b\w{0,30}favicon\w{0,30}\b|\bYeti(?:-[a-z]{1,30}|)|Catchpoint(?: bot|)|[Cc]harlotte|Checklinks|clumboot|Comodo HTTP\(S\) Crawler|Comodo-Webinspector-Crawler|ConveraCrawler|CRAWL-E|CrawlConvera|Daumoa(?:-feedfetcher|)|Feed Seeker Bot|Feedbin|findlinks|Flamingo_SearchEngine|FollowSite Bot|furlbot|Genieo|gigabot|GomezAgent|gonzo1|(?:[a-zA-Z]{1,30}-|)Googlebot(?:-[a-zA-Z]{1,30}|)|Google SketchUp|grub-client|gsa-crawler|heritrix|HiddenMarket|holmes|HooWWWer|htdig|ia_archiver|ICC-Crawler|Icarus6j|ichiro(?:\/mobile|)|IconSurf|IlTrovatore(?:-Setaccio|)|InfuzApp|Innovazion Crawler|InternetArchive|IP2[a-z]{1,30}Bot|jbot\b|KaloogaBot|Kraken|Kurzor|larbin|LEIA|LesnikBot|Linguee Bot|LinkAider|LinkedInBot|Lite Bot|Llaut|lycos|Mail\.RU_Bot|masscan|masidani_bot|Mediapartners-Google|Microsoft .{0,30} Bot|mogimogi|mozDex|MJ12bot|msnbot(?:-media {0,2}|)|msrbot|Mtps Feed Aggregation System|netresearch|Netvibes|NewsGator[^/]{0,30}|^NING|Nutch[^/]{0,30}|Nymesis|ObjectsSearch|OgScrper|Orbiter|OOZBOT|PagePeeker|PagesInventory|PaxleFramework|Peeplo Screenshot Bot|PlantyNet_WebRobot|Pompos|Qwantify|Read%20Later|Reaper|RedCarpet|Retreiver|Riddler|Rival IQ|scooter|Scrapy|Scrubby|searchsight|seekbot|semanticdiscovery|SemrushBot|Simpy|SimplePie|SEOstats|SimpleRSS|SiteCon|Slackbot-LinkExpanding|Slack-ImgProxy|Slurp|snappy|Speedy Spider|Squrl Java|Stringer|TheUsefulbot|ThumbShotsBot|Thumbshots\.ru|Tiny Tiny RSS|Twitterbot|WhatsApp|URL2PNG|Vagabondo|VoilaBot|^vortex|Votay bot|^voyager|WASALive.Bot|Web-sniffer|WebThumb|WeSEE:[A-z]{1,30}|WhatWeb|WIRE|WordPress|Wotbox|www\.almaden\.ibm\.com|Xenu(?:.s|) Link Sleuth|Xerka [A-z]{1,30}Bot|yacy(?:bot|)|YahooSeeker|Yahoo! Slurp|Yandex\w{1,30}|YodaoBot(?:-[A-z]{1,30}|)|YottaaMonitor|Yowedo|^Zao|^Zao-Crawler|ZeBot_www\.ze\.bz|ZooShot|ZyBorg)(?:[ /]v?(\d+)(?:\.(\d+)(?:\.(\d+)|)|)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"\b(Boto3?|JetS3t|aws-(?:cli|sdk-(?:cpp|go|java|nodejs|ruby2?|dotnet-(?:\d{1,2}|core)))|s3fs)\/(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"\[(FBAN\/MessengerForiOS|FB_IAB\/MESSENGER);FBAV\/(\d+)(?:\.(\d+)(?:\.(\d+)|)|)").unwrap().captures(&ua) {
              let family = "Facebook Messenger".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"\[FB.*;(FBAV)\/(\d+)(?:\.(\d+)|)(?:\.(\d+)|)").unwrap().captures(&ua) {
              let family = "Facebook".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"\[FB.*;").unwrap().is_match(&ua) {
              let family = "Facebook".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(?:\/[A-Za-z0-9\.]+|) {0,5}([A-Za-z0-9 \-_\!\[\]:]{0,50}(?:[Aa]rchiver|[Ii]ndexer|[Ss]craper|[Bb]ot|[Ss]pider|[Cc]rawl[a-z]{0,50}))[/ ](\d+)(?:\.(\d+)(?:\.(\d+)|)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"((?:[A-Za-z][A-Za-z0-9 -]{0,50}|)[^C][^Uu][Bb]ot)\b(?:(?:[ /]| v)(\d+)(?:\.(\d+)|)(?:\.(\d+)|)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"((?:[A-z0-9]{1,50}|[A-z\-]{1,50} ?|)(?: the |)(?:[Ss][Pp][Ii][Dd][Ee][Rr]|[Ss]crape|[Cc][Rr][Aa][Ww][Ll])[A-z0-9]{0,50})(?:(?:[ /]| v)(\d+)(?:\.(\d+)|)(?:\.(\d+)|)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(HbbTV)\/(\d+)\.(\d+)\.(\d+) \(").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Chimera|SeaMonkey|Camino|Waterfox)\/(\d+)\.(\d+)\.?([ab]?\d+[a-z]*|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(SailfishBrowser)\/(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
              let family = "Sailfish Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"\[(Pinterest)\/[^\]]+\]").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Pinterest)(?: for Android(?: Tablet|)|)\/(\d+)(?:\.(\d+)|)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"Mozilla.*Mobile.*(Instagram).(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"Mozilla.*Mobile.*(Flipboard).(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"Mozilla.*Mobile.*(Flipboard-Briefing).(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"Mozilla.*Mobile.*(Onefootball)\/Android.(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Snapchat)\/(\d+)\.(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Firefox)\/(\d+)\.(\d+) Basilisk\/(\d+)").unwrap().captures(&ua) {
              let family = "Basilisk".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(PaleMoon)\/(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
              let family = "Pale Moon".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Fennec)\/(\d+)\.(\d+)\.?([ab]?\d+[a-z]*)").unwrap().captures(&ua) {
              let family = "Firefox Mobile".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Fennec)\/(\d+)\.(\d+)(pre)").unwrap().captures(&ua) {
              let family = "Firefox Mobile".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Fennec)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Firefox Mobile".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(?:Mobile|Tablet);.*(Firefox)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Firefox Mobile".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Namoroka|Shiretoko|Minefield)\/(\d+)\.(\d+)\.(\d+(?:pre|))").unwrap().captures(&ua) {
              let family = "Firefox ($1)".replace("$1", result.get(1).unwrap().into());
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Firefox)\/(\d+)\.(\d+)(a\d+[a-z]*)").unwrap().captures(&ua) {
              let family = "Firefox Alpha".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Firefox)\/(\d+)\.(\d+)(b\d+[a-z]*)").unwrap().captures(&ua) {
              let family = "Firefox Beta".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Firefox)-(?:\d+\.\d+|)\/(\d+)\.(\d+)(a\d+[a-z]*)").unwrap().captures(&ua) {
              let family = "Firefox Alpha".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Firefox)-(?:\d+\.\d+|)\/(\d+)\.(\d+)(b\d+[a-z]*)").unwrap().captures(&ua) {
              let family = "Firefox Beta".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Namoroka|Shiretoko|Minefield)\/(\d+)\.(\d+)([ab]\d+[a-z]*|)").unwrap().captures(&ua) {
              let family = "Firefox ($1)".replace("$1", result.get(1).unwrap().into());
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Firefox).*Tablet browser (\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "MicroB".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(MozillaDeveloperPreview)\/(\d+)\.(\d+)([ab]\d+[a-z]*|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(FxiOS)\/(\d+)\.(\d+)(\.(\d+)|)(\.(\d+)|)").unwrap().captures(&ua) {
              let family = "Firefox iOS".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Flock)\/(\d+)\.(\d+)(b\d+?)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(RockMelt)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Navigator)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Netscape".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Navigator)\/(\d+)\.(\d+)([ab]\d+)").unwrap().captures(&ua) {
              let family = "Netscape".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Netscape6)\/(\d+)\.(\d+)\.?([ab]?\d+|)").unwrap().captures(&ua) {
              let family = "Netscape".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(MyIBrow)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "My Internet Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(UC? ?Browser|UCWEB|U3)[ /]?(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "UC Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Opera Tablet).*Version\/(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Opera Mini)(?:\/att|)\/?(\d+|)(?:\.(\d+)|)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Opera)\/.+Opera Mobi.+Version\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Opera Mobile".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Opera)\/(\d+)\.(\d+).+Opera Mobi").unwrap().captures(&ua) {
              let family = "Opera Mobile".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"Opera Mobi.+(Opera)(?:\/|\s+)(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Opera Mobile".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"Opera Mobi").unwrap().is_match(&ua) {
              let family = "Opera Mobile".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Opera)\/9.80.*Version\/(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(?:Mobile Safari).*(OPR)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Opera Mobile".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(?:Chrome).*(OPR)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Opera".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Coast)\/(\d+).(\d+).(\d+)").unwrap().captures(&ua) {
              let family = "Opera Coast".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(OPiOS)\/(\d+).(\d+).(\d+)").unwrap().captures(&ua) {
              let family = "Opera Mini".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"Chrome\/.+( MMS)\/(\d+).(\d+).(\d+)").unwrap().captures(&ua) {
              let family = "Opera Neon".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(hpw|web)OS\/(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
              let family = "webOS Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if  Regex::new(r"(luakit)").unwrap().is_match(&ua) {
              let family = "LuaKit".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Snowshoe)\/(\d+)\.(\d+).(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"Gecko\/\d+ (Lightning)\/(\d+)\.(\d+)\.?((?:[ab]?\d+[a-z]*)|(?:\d*))").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Firefox)\/(\d+)\.(\d+)\.(\d+(?:pre|)) \(Swiftfox\)").unwrap().captures(&ua) {
              let family = "Swiftfox".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Firefox)\/(\d+)\.(\d+)([ab]\d+[a-z]*|) \(Swiftfox\)").unwrap().captures(&ua) {
              let family = "Swiftfox".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(rekonq)\/(\d+)\.(\d+)(?:\.(\d+)|) Safari").unwrap().captures(&ua) {
              let family = "Rekonq".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if  Regex::new(r"rekonq").unwrap().is_match(&ua) {
              let family = "Rekonq".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(conkeror|Conkeror)\/(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
              let family = "Conkeror".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(konqueror)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Konqueror".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(WeTab)-Browser").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Comodo_Dragon)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Comodo Dragon".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Symphony) (\d+).(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if  Regex::new(r"PLAYSTATION 3.+WebKit").unwrap().is_match(&ua) {
              let family = "NetFront NX".to_owned();
        return [ family, major, minor, patch ];
        } else if  Regex::new(r"PLAYSTATION 3").unwrap().is_match(&ua) {
              let family = "NetFront".to_owned();
        return [ family, major, minor, patch ];
        } else if  Regex::new(r"(PlayStation Portable)").unwrap().is_match(&ua) {
              let family = "NetFront".to_owned();
        return [ family, major, minor, patch ];
        } else if  Regex::new(r"(PlayStation Vita)").unwrap().is_match(&ua) {
              let family = "NetFront NX".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"AppleWebKit.+ (NX)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "NetFront NX".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if  Regex::new(r"(Nintendo 3DS)").unwrap().is_match(&ua) {
              let family = "NetFront NX".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Silk)\/(\d+)\.(\d+)(?:\.([0-9\-]+)|)").unwrap().captures(&ua) {
              let family = "Amazon Silk".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Puffin)\/(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"Windows Phone .*(Edge)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Edge Mobile".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(SamsungBrowser)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Samsung Internet".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(SznProhlizec)\/(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
              let family = "Seznam prohlížeč".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(coc_coc_browser)\/(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
              let family = "Coc Coc".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(baidubrowser)[/\s](\d+)(?:\.(\d+)|)(?:\.(\d+)|)").unwrap().captures(&ua) {
              let family = "Baidu Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(FlyFlow)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Baidu Explorer".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(MxBrowser)\/(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
              let family = "Maxthon".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Crosswalk)\/(\d+)\.(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Line)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "LINE".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(MiuiBrowser)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "MiuiBrowser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Mint Browser)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Mint Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"Mozilla.+Android.+(GSA)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Google".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"Version\/.+(Chrome)\/(\d+)\.(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Chrome Mobile WebView".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"; wv\).+(Chrome)\/(\d+)\.(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Chrome Mobile WebView".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(CrMo)\/(\d+)\.(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Chrome Mobile".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(CriOS)\/(\d+)\.(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Chrome Mobile iOS".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Chrome)\/(\d+)\.(\d+)\.(\d+)\.(\d+) Mobile(?:[ /]|$)").unwrap().captures(&ua) {
              let family = "Chrome Mobile".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r" Mobile .*(Chrome)\/(\d+)\.(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Chrome Mobile".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(chromeframe)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Chrome Frame".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(SLP Browser)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Tizen Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(SE 2\.X) MetaSr (\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Sogou Explorer".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(MQQBrowser\/Mini)(?:(\d+)(?:\.(\d+)|)(?:\.(\d+)|)|)").unwrap().captures(&ua) {
              let family = "QQ Browser Mini".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(MQQBrowser)(?:\/(\d+)(?:\.(\d+)|)(?:\.(\d+)|)|)").unwrap().captures(&ua) {
              let family = "QQ Browser Mobile".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(QQBrowser)(?:\/(\d+)(?:\.(\d+)\.(\d+)(?:\.(\d+)|)|)|)").unwrap().captures(&ua) {
              let family = "QQ Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Rackspace Monitoring)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "RackspaceBot".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(PyAMF)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(YaBrowser)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Yandex Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Chrome)\/(\d+)\.(\d+)\.(\d+).* MRCHROME").unwrap().captures(&ua) {
              let family = "Mail.ru Chromium Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(AOL) (\d+)\.(\d+); AOLBuild (\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(PodCruncher|Downcast)[ /]?(\d+)(?:\.(\d+)|)(?:\.(\d+)|)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r" (BoxNotes)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Whale)\/(\d+)\.(\d+)\.(\d+)\.(\d+) Mobile(?:[ /]|$)").unwrap().captures(&ua) {
              let family = "Whale".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Whale)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Whale".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Ghost)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Slack_SSB)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Slack Desktop Client".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(HipChat)\/?(\d+|)").unwrap().captures(&ua) {
              let family = "HipChat Desktop Client".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"\b(MobileIron|FireWeb|Jasmine|ANTGalio|Midori|Fresco|Lobo|PaleMoon|Maxthon|Lynx|OmniWeb|Dillo|Camino|Demeter|Fluid|Fennec|Epiphany|Shiira|Sunrise|Spotify|Flock|Netscape|Lunascape|WebPilot|NetFront|Netfront|Konqueror|SeaMonkey|Kazehakase|Vienna|Iceape|Iceweasel|IceWeasel|Iron|K-Meleon|Sleipnir|Galeon|GranParadiso|Opera Mini|iCab|NetNewsWire|ThunderBrowse|Iris|UP\.Browser|Bunjalloo|Google Earth|Raven for Mac|Openwave|MacOutlook|Electron|OktaMobile)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"Microsoft Office Outlook 12\.\d+\.\d+|MSOffice 12").unwrap().is_match(&ua) {
              let family = "Outlook".to_owned();
              let major = "2007".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"Microsoft Outlook 14\.\d+\.\d+|MSOffice 14").unwrap().is_match(&ua) {
              let family = "Outlook".to_owned();
              let major = "2010".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"Microsoft Outlook 15\.\d+\.\d+").unwrap().is_match(&ua) {
              let family = "Outlook".to_owned();
              let major = "2013".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"Microsoft Outlook (?:Mail )?16\.\d+\.\d+|MSOffice 16").unwrap().is_match(&ua) {
              let family = "Outlook".to_owned();
              let major = "2016".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"Microsoft Office (Word) 2014").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"Outlook-Express\/7\.0.*").unwrap().is_match(&ua) {
              let family = "Windows Live Mail".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Airmail) (\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Thunderbird)\/(\d+)\.(\d+)(?:\.(\d+(?:pre|))|)").unwrap().captures(&ua) {
              let family = "Thunderbird".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Postbox)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Postbox".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Barca(?:Pro)?)\/(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
              let family = "Barca".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Lotus-Notes)\/(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
              let family = "Lotus Notes".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Vivaldi)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Edge?)\/(\d+)(?:\.(\d+)|)(?:\.(\d+)|)(?:\.(\d+)|)").unwrap().captures(&ua) {
              let family = "Edge".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(brave)\/(\d+)\.(\d+)\.(\d+) Chrome").unwrap().captures(&ua) {
              let family = "Brave".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Chrome)\/(\d+)\.(\d+)\.(\d+)[\d.]* Iron[^/]").unwrap().captures(&ua) {
              let family = "Iron".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"\b(Dolphin)(?: |HDCN\/|\/INT\-)(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(HeadlessChrome)(?:\/(\d+)\.(\d+)\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Evolution)\/(\d+)\.(\d+)\.(\d+\.\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(RCM CardDAV plugin)\/(\d+)\.(\d+)\.(\d+(?:-dev|))").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(bingbot|Bolt|AdobeAIR|Jasmine|IceCat|Skyfire|Midori|Maxthon|Lynx|Arora|IBrowse|Dillo|Camino|Shiira|Fennec|Phoenix|Flock|Netscape|Lunascape|Epiphany|WebPilot|Opera Mini|Opera|NetFront|Netfront|Konqueror|Googlebot|SeaMonkey|Kazehakase|Vienna|Iceape|Iceweasel|IceWeasel|Iron|K-Meleon|Sleipnir|Galeon|GranParadiso|iCab|iTunes|MacAppStore|NetNewsWire|Space Bison|Stainless|Orca|Dolfin|BOLT|Minimo|Tizen Browser|Polaris|Abrowser|Planetweb|ICE Browser|mDolphin|qutebrowser|Otter|QupZilla|MailBar|kmail2|YahooMobileMail|ExchangeWebServices|ExchangeServicesClient|Dragon|Outlook-iOS-Android)\/(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Chromium|Chrome)\/(\d+)\.(\d+)(?:\.(\d+)|)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(IEMobile)[ /](\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "IE Mobile".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(BacaBerita App)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(bPod|Pocket Casts|Player FM)$").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(AlexaMediaPlayer|VLC)\/(\d+)\.(\d+)\.([^.\s]+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(AntennaPod|WMPlayer|Zune|Podkicker|Radio|ExoPlayerDemo|Overcast|PocketTunes|NSPlayer|okhttp|DoggCatcher|QuickNews|QuickTime|Peapod|Podcasts|GoldenPod|VLC|Spotify|Miro|MediaGo|Juice|iPodder|gPodder|Banshee)\/(\d+)\.(\d+)(?:\.(\d+)|)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(Peapod|Liferea)\/([^.\s]+)\.([^.\s]+|)\.?([^.\s]+|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(bPod|Player FM) BMID\/(\S+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(Podcast ?Addict)\/v(\d+) ").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if  Regex::new(r"^(Podcast ?Addict) ").unwrap().is_match(&ua) {
              let family = "PodcastAddict".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Replay) AV").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(VOX) Music Player").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(CITA) RSS Aggregator\/(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Pocket Casts)$").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Player FM)$").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(LG Player|Doppler|FancyMusic|MediaMonkey|Clementine) (\d+)\.(\d+)\.?([^.\s]+|)\.?([^.\s]+|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(philpodder)\/(\d+)\.(\d+)\.?([^.\s]+|)\.?([^.\s]+|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Player FM|Pocket Casts|DoggCatcher|Spotify|MediaMonkey|MediaGo|BashPodder)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(QuickTime)\.(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Kinoma)(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Fancy) Cloud Music (\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "FancyMusic".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if  Regex::new(r"EspnDownloadManager").unwrap().is_match(&ua) {
              let family = "ESPN".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(ESPN) Radio (\d+)\.(\d+)(?:\.(\d+)|) ?(?:rv:(\d+)|) ").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(podracer|jPodder) v ?(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(ZDM)\/(\d+)\.(\d+)[; ]?").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Zune|BeyondPod) (\d+)(?:\.(\d+)|)[\);]").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(WMPlayer)\/(\d+)\.(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if  Regex::new(r"^(Lavf)").unwrap().is_match(&ua) {
              let family = "WMPlayer".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(RSSRadio)[ /]?(\d+|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(RSS_Radio) (\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "RSSRadio".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Podkicker) \S+\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Podkicker".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(HTC) Streaming Player \S+ \/ \S+ \/ \S+ \/ (\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(Stitcher)\/iOS").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(Stitcher)\/Android").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(VLC) .*version (\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r" (VLC) for").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(vlc)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "VLC".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(foobar)\S+\/([^.\s]+)\.([^.\s]+|)\.?([^.\s]+|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(Clementine)\S+ ([^.\s]+)\.([^.\s]+|)\.?([^.\s]+|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(amarok)\/([^.\s]+)\.([^.\s]+|)\.?([^.\s]+|)").unwrap().captures(&ua) {
              let family = "Amarok".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Custom)-Feed Reader").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(iRider|Crazy Browser|SkipStone|iCab|Lunascape|Sleipnir|Maemo Browser) (\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(iCab|Lunascape|Opera|Android|Jasmine|Polaris|Microsoft SkyDriveSync|The Bat!) (\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Kindle)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Android) Donut").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
              let major = "1".to_owned();
              let minor="2".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Android) Eclair").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
              let major = "2".to_owned();
              let minor="1".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Android) Froyo").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
              let major = "2".to_owned();
              let minor="2".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Android) Gingerbread").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
              let major = "2".to_owned();
              let minor="3".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Android) Honeycomb").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
              let major = "3".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(MSIE) (\d+)\.(\d+).*XBLWP7").unwrap().captures(&ua) {
              let family = "IE Large Screen".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Nextcloud)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(mirall)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(ownCloud-android)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Owncloud".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(OC)\/(\d+)\.(\d+)\.(\d+)\.(\d+) \(Skype for Business\)").unwrap().captures(&ua) {
              let family = "Skype".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Obigo)InternetBrowser").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Obigo)\-Browser").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Obigo|OBIGO)[^\d]*(\d+)(?:.(\d+)|)").unwrap().captures(&ua) {
              let family = "Obigo".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(MAXTHON|Maxthon) (\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Maxthon".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Maxthon|MyIE2|Uzbl|Shiira)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
              let major = "0".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(BrowseX) \((\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(NCSA_Mosaic)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "NCSA Mosaic".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(POLARIS)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Polaris".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Embider)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Polaris".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(BonEcho)\/(\d+)\.(\d+)\.?([ab]?\d+|)").unwrap().captures(&ua) {
              let family = "Bon Echo".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(iPod|iPhone|iPad).+GSA\/(\d+)\.(\d+)\.(\d+) Mobile").unwrap().captures(&ua) {
              let family = "Google".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(iPod|iPhone|iPad).+Version\/(\d+)\.(\d+)(?:\.(\d+)|).*[ +]Safari").unwrap().captures(&ua) {
              let family = "Mobile Safari".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(iPod|iPod touch|iPhone|iPad);.*CPU.*OS[ +](\d+)_(\d+)(?:_(\d+)|).* AppleNews\/\d+\.\d+\.\d+?").unwrap().captures(&ua) {
              let family = "Mobile Safari UI/WKWebView".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(iPod|iPhone|iPad).+Version\/(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
              let family = "Mobile Safari UI/WKWebView".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(iPod|iPod touch|iPhone|iPad);.*CPU.*OS[ +](\d+)_(\d+)(?:_(\d+)|).*Mobile.*[ +]Safari").unwrap().captures(&ua) {
              let family = "Mobile Safari".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(iPod|iPod touch|iPhone|iPad);.*CPU.*OS[ +](\d+)_(\d+)(?:_(\d+)|).*Mobile").unwrap().captures(&ua) {
              let family = "Mobile Safari UI/WKWebView".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad).* Safari").unwrap().is_match(&ua) {
              let family = "Mobile Safari".to_owned();
        return [ family, major, minor, patch ];
        } else if Regex::new(r"(iPod|iPhone|iPad)").unwrap().is_match(&ua) {
              let family = "Mobile Safari UI/WKWebView".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Watch)(\d+),(\d+)").unwrap().captures(&ua) {
              let family = "Apple $1 App".replace("$1", result.get(1).unwrap().into());
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Outlook-iOS)\/\d+\.\d+\.prod\.iphone \((\d+)\.(\d+)\.(\d+)\)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(AvantGo) (\d+).(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(OneBrowser)\/(\d+).(\d+)").unwrap().captures(&ua) {
              let family = "ONE Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Avant)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
              let major = "1".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(QtCarBrowser)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
              let major = "1".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(iBrowser\/Mini)(\d+).(\d+)").unwrap().captures(&ua) {
              let family = "iBrowser Mini".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(iBrowser|iRAPP)\/(\d+).(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if  Regex::new(r"^(Nokia)").unwrap().is_match(&ua) {
              let family = "Nokia Services (WAP) Browser".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(NokiaBrowser)\/(\d+)\.(\d+).(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Nokia Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(NokiaBrowser)\/(\d+)\.(\d+).(\d+)").unwrap().captures(&ua) {
              let family = "Nokia Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(NokiaBrowser)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Nokia Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(BrowserNG)\/(\d+)\.(\d+).(\d+)").unwrap().captures(&ua) {
              let family = "Nokia Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if  Regex::new(r"(Series60)\/5\.0").unwrap().is_match(&ua) {
              let family = "Nokia Browser".to_owned();
              let major = "7".to_owned();
              let minor="0".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Series60)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Nokia OSS Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(S40OviBrowser)\/(\d+)\.(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Ovi Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Nokia)[EN]?(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(PlayBook).+RIM Tablet OS (\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "BlackBerry WebKit".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Black[bB]erry|BB10).+Version\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "BlackBerry WebKit".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Black[bB]erry)\s?(\d+)").unwrap().captures(&ua) {
              let family = "BlackBerry".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(OmniWeb)\/v(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Blazer)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Palm Blazer".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Pre)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Palm Pre".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(ELinks)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(ELinks) \((\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Links) \((\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(QtWeb) Internet Browser\/(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(PhantomJS)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(AppleWebKit)\/(\d+)(?:\.(\d+)|)\+ .* Safari").unwrap().captures(&ua) {
              let family = "WebKit Nightly".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Version)\/(\d+)\.(\d+)(?:\.(\d+)|).*Safari\/").unwrap().captures(&ua) {
              let family = "Safari".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Safari)\/\d+").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(OLPC)\/Update(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(OLPC)\/Update()\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
              let major = "0".to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(SEMC\-Browser)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if  Regex::new(r"(Teleca)").unwrap().is_match(&ua) {
              let family = "Teleca Browser".to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Phantom)\/V(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Phantom Browser".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Trident)\/(7|8)\.(0)").unwrap().captures(&ua) {
              let family = "IE".to_owned();
              let major = "11".to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Trident)\/(6)\.(0)").unwrap().captures(&ua) {
              let family = "IE".to_owned();
              let major = "10".to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Trident)\/(5)\.(0)").unwrap().captures(&ua) {
              let family = "IE".to_owned();
              let major = "9".to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Trident)\/(4)\.(0)").unwrap().captures(&ua) {
              let family = "IE".to_owned();
              let major = "8".to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Espial)\/(\d+)(?:\.(\d+)|)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(AppleWebKit)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Apple Mail".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Firefox)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Firefox)\/(\d+)\.(\d+)(pre|[ab]\d+[a-z]*|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"([MS]?IE) (\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "IE".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(python-requests)\/(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Python Requests".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"\b(Windows-Update-Agent|Microsoft-CryptoAPI|SophosUpdateManager|SophosAgent|Debian APT-HTTP|Ubuntu APT-HTTP|libcurl-agent|libwww-perl|urlgrabber|curl|PycURL|Wget|aria2|Axel|OpenBSD ftp|lftp|jupdate|insomnia|fetch libfetch|akka-http|got)(?:[ /](\d+)(?:\.(\d+)|)(?:\.(\d+)|)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Python\/3\.\d{1,3} aiohttp)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Python\/3\.\d{1,3} aiohttp)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Java)[/ ]{0,1}\d+\.(\d+)\.(\d+)[_-]*([a-zA-Z0-9]+|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(Cyberduck)\/(\d+)\.(\d+)\.(\d+)(?:\.\d+|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(S3 Browser) (\d+)-(\d+)-(\d+)(?:\s*http:\/\/s3browser\.com|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(S3Gof3r)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"\b(ibm-cos-sdk-(?:core|java|js|python))\/(\d+)\.(\d+)(?:\.(\d+)|)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(rusoto)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(rclone)\/v(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(Roku)\/DVP-(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"(Kurio)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "Kurio App".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(Box(?: Sync)?)\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
        let family = Into::<&str>::into(result.get(1).unwrap()).to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
        } else if let Some(result) = Regex::new(r"^(ViaFree|Viafree)-(?:tvOS-)?[A-Z]{2}\/(\d+)\.(\d+)\.(\d+)").unwrap().captures(&ua) {
              let family = "ViaFree".to_owned();
        let major = Into::<&str>::into(result.get(2).unwrap()).to_owned();
        let minor = Into::<&str>::into(result.get(3).unwrap()).to_owned();
        let patch = Into::<&str>::into(result.get(4).unwrap()).to_owned();
        return [ family, major, minor, patch ];
      }

    return [family, major, minor, patch];
}

fn get_polyfills(
    options: PolyfillParameters,
    store: String,
    version: String,
) -> HashMap<String, Feature> {
    let ua: UA = if version == "3.25.1" {
        // oldUA(options.ua_string)
        unimplemented!("uh oh");
    } else {
        UA::new(options.ua_string)
    };
    let unknown = ua.is_unknown();
    let family = ua.get_family().clone();
    let mut feature_names: HashSet<String> =
        HashSet::from_iter(options.features.keys().map(|f| f.to_owned()));
    let mut targeted_features: HashMap<String, Feature> = HashMap::new();
    loop {
        let mut bbreak = true;
        for feature_name in feature_names.clone() {
            // Remove feature if it exists in the `excludes` array.
            if options.excludes.contains(&feature_name) {
                let removed = remove_feature(
                    feature_name.to_string(),
                    &mut feature_names,
                    &mut targeted_features,
                );
                if removed {
                    bbreak = false;
                }
                continue;
            }

            let feature = targeted_features.get(&feature_name);
            let mut properties: Feature = match feature {
                Some(f) => f.to_owned(),
                None => Feature {
                    comment: None,
                    alias_of: HashSet::new(),
                    dependency_of: HashSet::new(),
                    flags: options
                        .features
                        .get(&feature_name)
                        .map(|f| f.to_owned())
                        .unwrap_or_else(|| HashSet::new()),
                },
            };

            // If feature_name is an alias for a group of features
            // Add each feature.
            let alias = get_config_aliases(store.clone(), feature_name.to_string());
            if let Some(alias) = alias {
                let mut alias_properties = Feature {
                    comment: None,
                    alias_of: HashSet::from(properties.clone().alias_of),
                    dependency_of: HashSet::from(properties.clone().dependency_of),
                    flags: HashSet::from(properties.clone().flags),
                };
                alias_properties.alias_of.insert(feature_name.to_string());
                for aliased_feature in alias {
                    let added = add_feature(
                        aliased_feature,
                        alias_properties.clone(),
                        &mut feature_names,
                        &mut targeted_features,
                    );
                    if added {
                        bbreak = false;
                    }
                }
                continue;
            }

            // If always flag is set, then the feature should be targeted at the browser.
            let mut targeted = properties.flags.contains("always");

            // If not already targeted, then set targeted to true if the browser is unknown/unsupported
            // and the unknown option is set the serve polyfills.
            if !targeted {
                let unknown_override = options.unknown == "polyfill" && unknown;
                if unknown_override {
                    targeted = true;
                    properties.flags.insert("gated".to_owned());
                }
            }

            let meta = get_polyfill_meta(store.clone(), feature_name.to_string());
            if meta.is_none() {
                // this is a bit strange but the best thing I could come up with.
                // by adding the feature, it will show up as an "unrecognized" polyfill
                // which I think is better than just pretending it doesn't exsist.
                let added = add_feature(
                    feature_name.to_string(),
                    Default::default(),
                    &mut feature_names,
                    &mut targeted_features,
                );
                if added {
                    bbreak = false;
                }
                continue;
            }
            let meta = meta.unwrap();
            // If not already targeted, check to see if the polyfill's configuration states it should target
            // this browser version.
            if !targeted {
                targeted = ua.satisfies(meta.browsers.get(&family).unwrap().clone());
            }

            if targeted {
                let added = add_feature(
                    feature_name.to_string(),
                    properties.clone(),
                    &mut feature_names,
                    &mut targeted_features,
                );
                if added {
                    bbreak = false;
                }
                let deps = meta.dependencies;
                // If feature has dependency then add the dependencies as well.
                if let Some(deps) = deps {
                    let mut dependency_properties = Feature {
                        comment: None,
                        alias_of: HashSet::from(properties.clone().alias_of),
                        dependency_of: HashSet::from(properties.clone().dependency_of),
                        flags: HashSet::from(properties.clone().flags.clone()),
                    };
                    dependency_properties
                        .dependency_of
                        .insert(feature_name.to_string());
                    for dep in deps {
                        let added = add_feature(
                            dep,
                            dependency_properties.clone(),
                            &mut feature_names,
                            &mut targeted_features,
                        );
                        if added {
                            bbreak = false;
                        }
                    }
                }
            } else {
                let removed = remove_feature(
                    feature_name.to_string(),
                    &mut feature_names,
                    &mut targeted_features,
                );
                if removed {
                    bbreak = false;
                }
            }
        }
        if bbreak {
            break;
        }
    }
    return targeted_features;
}

fn get_polyfill_string(options: PolyfillParameters, store: String, app_version: String) -> Body {
    let lf = if options.minify { "" } else { "\n" };
    let app_version_text = "Polyfill service v".to_owned() + &app_version;
    let mut output = Body::new();
    let mut explainer_comment: Vec<String> = vec![];
    // Build a polyfill bundle of polyfill sources sorted in dependency order
    let mut targeted_features = get_polyfills(options.clone(), store.clone(), "3.111.0".to_owned());
    let mut warnings: Vec<String> = vec![];
    let mut feature_nodes: Vec<String> = vec![];
    let mut feature_edges: Vec<(String, String)> = vec![];

    let t = targeted_features.clone();
    for (feature_name, feature) in targeted_features.iter_mut() {
        let polyfill = get_polyfill_meta(store.clone(), feature_name.to_string());
        match polyfill {
            Some(polyfill) => {
                feature_nodes.push(feature_name.to_string());
                if let Some(deps) = polyfill.dependencies {
                    for dep_name in deps {
                        if t.contains_key(&dep_name) {
                            feature_edges.push((dep_name, feature_name.to_string()));
                        }
                    }
                }
                let license = polyfill.license.clone().unwrap_or_else(|| "CC0".to_owned());
                // let required_by = if !feature.dependency_of.is_empty() || !feature.alias_of.is_empty() {
                //     let dep: Vec<String> = feature.dependency_of.union(&feature.alias_of).into_iter().map(|f|f.to_owned()).collect();
                //     " (required by \"".to_owned() + &dep.join("\", \"") + "\")"
                // } else {
                //     "".to_owned()
                // };
                // feature.comment = Some(format!("{feature_name}, License: {license} {required_by}"));
                feature.comment = Some(format!("{feature_name}, License: {license}"));
            },
            None => warnings.push(feature_name.to_string()),
        }
    }

    feature_nodes.sort();
    feature_edges.sort_by_key(|f| f.1.to_string());
    // feature_nodes.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
    // feature_edges.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase()));
    let sorted_features = toposort(feature_nodes, feature_edges).unwrap();
    if !options.minify {
    	explainer_comment.push(app_version_text);
        explainer_comment.push("For detailed credits and licence information see https://github.com/JakeChampion/polyfill-service.".to_owned());
        explainer_comment.push("".to_owned());
        explainer_comment.push("Features requested: ".to_owned() + &options.clone().features.keys().map(|s|s.to_owned()).collect::<Vec<String>>().join(", "));
        explainer_comment.push("".to_owned());
        sorted_features
        .iter()
        .for_each(|feature_name| {
            if let Some(feature) = targeted_features.get(feature_name) {
                explainer_comment.push(format!("- {}", feature.comment.as_ref().unwrap()));
            }
        });
        // explainer_comment.push(
        //     sorted_features
        //     .iter()
        //     .map(|comment| "- ".to_string() + &comment).collect::<Vec<String>>().join("\n")
        // );
        if !warnings.is_empty() {
            explainer_comment.push("".to_owned());
            explainer_comment.push("These features were not recognised:".to_owned());
            explainer_comment.push(warnings.iter().map(|s| "- ".to_owned() + s).collect::<Vec<String>>().join(", "));
        }
    } else {
        explainer_comment.push(app_version_text);
        explainer_comment.push("Disable minification (remove `.min` from URL path) for more info".to_owned());
    }
    output.write_str(format!("/* {} */\n\n", explainer_comment.join("\n * ")).as_str());
    if !sorted_features.is_empty() {
    	// Outer closure hides private features from global scope
    	output.write_str("(function(self, undefined) {");
        output.write_str(lf);

    	// Using the graph, stream all the polyfill sources in dependency order
    	for feature_name in sorted_features {
    		let wrap_in_detect = targeted_features[&feature_name].flags.contains("gated");
            let m = if options.minify { "min" } else { "raw" }.to_owned();
    		if wrap_in_detect {
    			let meta = get_polyfill_meta(store.clone(), feature_name.clone());
    			if let Some(meta) = meta {
                    if let Some(detect_source) = meta.detect_source {
                        if !detect_source.is_empty() {
                            output.write_str("if (!(");
                            output.write_str(detect_source.as_str());
                            output.write_str(")) {");
                            output.write_str(lf);
                            output.append(polyfill_source(store.clone(), feature_name.clone(), m));
                            output.write_str(lf);
                            output.write_str("}");
                            output.write_str(lf);
                            output.write_str(lf);
                        }
                    }
    			} else {
                    output.append(polyfill_source(store.clone(), feature_name, m));
                }
    		} else {
                output.append(polyfill_source(store.clone(), feature_name, m));
    		}
    	}
    	// Invoke the closure, passing the global object as the only argument
    	output.write_str("})");
        output.write_str(lf);
        output.write_str("('object' == typeof window && window || 'object' == typeof self && self || 'object' == typeof global && global || {});");
        output.write_str(lf);
    } else {
    	if !options.minify {
    		output.write_str("\n/* No polyfills needed for current settings and browser */\n\n");
    	}
    }
    if let Some(callback) = options.callback {
    	output.write_str("\ntypeof ");
        output.write_str(&callback);
        output.write_str("=='function' && ");
        output.write_str(&callback);
        output.write_str("();");
    }
    return output;

}

fn polyfill_source(store: String, feature_name: String, format: String) -> Body {
    let n = store.replace('-', "_").replace('.', "_");
    let config = ConfigStore::open(&n);
	let c = config.get(&format!("{feature_name}/{format}.js"));
	if let Some(c) = c {
		return Body::from(c);
	}
    let polyfills = KVStore::open(&store).unwrap().unwrap();
    let polyfill = polyfills.lookup(&format!("/{feature_name}/{format}.js")).unwrap();
    if polyfill.is_none() {
        let format = if format == "raw" { "min" } else { "raw" };
        let polyfill = polyfills.lookup(&format!("/{feature_name}/{format}.js")).unwrap();
        return polyfill.unwrap();
    }
	return polyfill.unwrap();
}
