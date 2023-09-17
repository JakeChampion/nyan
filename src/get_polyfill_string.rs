use crate::useragent::useragent;
use fastly::{Body, ConfigStore, KVStore};
use regex::Regex;
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    iter::FromIterator,
    sync::OnceLock,
};

use crate::{polyfill_parameters::PolyfillParameters, toposort::toposort};

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

struct UA {
    version: String,
    family: String,
}

impl UA {
    fn new(ua_string: &str) -> UA {
        let mut family: String;
        let mut major: String;
        let mut minor: String;
        // let mut patch: String = "0".to_owned();
        let re: Regex = Regex::new(r"(?i)^(\w+)\/(\d+)(?:\.(\d+){2})?$").unwrap();
        if let Some(normalized) = re.captures(&ua_string) {
            family = normalized.get(1).map(Into::<&str>::into).unwrap().into();
            major = normalized.get(2).map(Into::<&str>::into).unwrap().into();
            minor = normalized
                .get(3)
                .map(Into::<&str>::into)
                .unwrap_or("0")
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

            let ua = useragent(&ua_string);
            family = ua[0].clone();
            major = ua[1].clone();
            minor = ua[2].clone();
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
        if family == "googlebot" && major == "2" && minor == "1" {
            family = "chrome".to_owned();
            major = "41".to_owned();
            minor = "0".to_owned();
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

        UA {
            version,
            family: family.to_owned(),
            // major: major.to_owned(),
            // minor: minor.to_owned(),
            // patch: patch.to_owned(),
        }
    }

    fn get_family(&self) -> String {
        self.family.clone()
    }

    fn satisfies(&self, range: String) -> bool {
        let req = VersionReq::parse(&range).unwrap();
        let version = Version::parse(&self.version).unwrap();
        req.matches(&version)
    }

    fn meets_baseline(&self) -> bool {
        let family = &self.family;
        let range = format!(">={}", UA::get_baselines().get(family).unwrap());
        self.satisfies(range)
    }

    fn is_unknown(&self) -> bool {
        !UA::get_baselines().contains_key(&self.family) || !self.meets_baseline()
    }

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
        b
    }
}

#[derive(Clone, Deserialize)]
struct PolyfillConfig {
    license: Option<String>,
    dependencies: Option<Vec<String>>,
    browsers: HashMap<String, String>,
    detect_source: Option<String>,
}

static POLYFILL_META_CONFIG_STORE: OnceLock<ConfigStore> = OnceLock::new();
fn get_polyfill_meta(store: &str, feature_name: &str) -> Option<PolyfillConfig> {
    if feature_name.is_empty() {
        return None;
    }
    let config = POLYFILL_META_CONFIG_STORE.get_or_init(|| {
        let n = store.replace(['-', '.'], "_");
        ConfigStore::open(&n)
    });
    let meta = config.get(&feature_name);
    meta.map(|m| serde_json::from_str(&m).unwrap())
}

static POLYFILL_ALIASES_CONFIG_STORE: OnceLock<ConfigStore> = OnceLock::new();
fn get_config_aliases(store: &str, alias: &str) -> Option<Vec<String>> {
    if alias.is_empty() {
        return None;
    }
    let aliases = POLYFILL_ALIASES_CONFIG_STORE.get_or_init(|| {
        let n = store.replace(['-', '.'], "_");
        ConfigStore::open(&(n + "_aliases"))
    });
    aliases
        .get(&alias)
        .map(|m| serde_json::from_str(&m).unwrap())
}

#[derive(Clone, Default)]
struct Feature {
    alias_of: HashSet<String>,
    flags: HashSet<String>,
    comment: Option<String>,
}

fn remove_feature(
    feature_name: String,
    feature_names: &mut HashSet<String>,
    targeted_features: &mut HashMap<String, Feature>,
) -> bool {
    targeted_features.remove(&feature_name);
    feature_names.remove(&feature_name)
}

fn add_feature(
    feature_name: String,
    feature: Feature,
    feature_names: &mut HashSet<String>,
    targeted_features: &mut HashMap<String, Feature>,
) -> bool {
    // targeted_features[feature_name] = Object.assign(Object.create(null), featureFlags, featureProperties);
    targeted_features.insert(feature_name.clone(), feature);
    feature_names.insert(feature_name)
}

fn get_polyfills(
    options: &PolyfillParameters,
    store: &str,
    version: &str,
) -> HashMap<String, Feature> {
    let ua: UA = if version == "3.25.1" {
        // oldUA(options.ua_string)
        unimplemented!("uh oh");
    } else {
        UA::new(&options.ua_string)
    };
    let unknown = ua.is_unknown();
    let family = ua.get_family();
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
                    flags: options
                        .features
                        .get(&feature_name)
                        .map(|f| f.to_owned())
                        .unwrap_or_else(HashSet::new),
                },
            };

            // If feature_name is an alias for a group of features
            // Add each feature.
            let alias = get_config_aliases(store, &feature_name);
            if let Some(alias) = alias {
                let mut alias_properties = Feature {
                    comment: None,
                    alias_of: properties.clone().alias_of,
                    flags: properties.clone().flags,
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

            let meta = get_polyfill_meta(store, &feature_name);
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
                targeted = ua.satisfies(meta.browsers.get(&family).unwrap().to_string());
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
                    let dependency_properties = Feature {
                        comment: None,
                        alias_of: properties.clone().alias_of,
                        flags: properties.clone().flags.clone(),
                    };
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
    targeted_features
}

pub(crate) fn get_polyfill_string(
    options: &PolyfillParameters,
    store: &str,
    app_version: &str,
) -> Body {
    let lf = if options.minify { "" } else { "\n" };
    let app_version_text = "Polyfill service v".to_owned() + &app_version;
    let mut output = Body::new();
    let mut explainer_comment: Vec<String> = vec![];
    // Build a polyfill bundle of polyfill sources sorted in dependency order
    let mut targeted_features = get_polyfills(&options, store, "3.111.0");
    let mut warnings: Vec<String> = vec![];
    let mut feature_nodes: Vec<String> = vec![];
    let mut feature_edges: Vec<(String, String)> = vec![];

    let t = targeted_features.clone();
    for (feature_name, feature) in targeted_features.iter_mut() {
        let polyfill = get_polyfill_meta(store, feature_name);
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
                let license = polyfill.license.unwrap_or_else(|| "CC0".to_owned());
                feature.comment = Some(format!("{feature_name}, License: {license}"));
                // feature.comment = Some(format!("{feature_name}, License: {license}"));
            }
            None => warnings.push(feature_name.to_string()),
        }
    }

    feature_nodes.sort();
    feature_edges.sort_by_key(|f| f.1.to_string());

    // feature_nodes.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
    // feature_edges.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase()));
    let sorted_features = toposort(&feature_nodes, &feature_edges).unwrap();
    if !options.minify {
        explainer_comment.push(app_version_text);
        explainer_comment.push("For detailed credits and licence information see https://github.com/JakeChampion/polyfill-service.".to_owned());
        explainer_comment.push("".to_owned());
        explainer_comment.push(
            "Features requested: ".to_owned()
                + &options
                    .features
                    .keys()
                    .map(|s| s.to_owned())
                    .collect::<Vec<String>>()
                    .join(", "),
        );
        explainer_comment.push("".to_owned());
        sorted_features.iter().for_each(|feature_name| {
            if let Some(feature) = targeted_features.get(feature_name) {
                explainer_comment.push(format!("- {}", feature.comment.as_ref().unwrap()));
            }
        });
        // explainer_comment.push(
        //     sorted_features
        //         .iter()
        //         .map(|comment| "- ".to_string() + &comment)
        //         .collect::<Vec<String>>()
        //         .join("\n"),
        // );
        if !warnings.is_empty() {
            explainer_comment.push("".to_owned());
            explainer_comment.push("These features were not recognised:".to_owned());
            explainer_comment.push(
                warnings
                    .iter()
                    .map(|s| "- ".to_owned() + s)
                    .collect::<Vec<String>>()
                    .join(", "),
            );
        }
    } else {
        explainer_comment.push(app_version_text);
        explainer_comment
            .push("Disable minification (remove `.min` from URL path) for more info".to_owned());
    }
    output.write_str(format!("/* {} */\n\n", explainer_comment.join("\n * ")).as_str());
    if !sorted_features.is_empty() {
        // Outer closure hides private features from global scope
        output.write_str("(function(self, undefined) {");
        output.write_str(lf);

        // Using the graph, stream all the polyfill sources in dependency order
        for feature_name in sorted_features {
            let wrap_in_detect = targeted_features[&feature_name].flags.contains("gated");
            let m = if options.minify { "min" } else { "raw" };
            if wrap_in_detect {
                let meta = get_polyfill_meta(store, &feature_name);
                if let Some(meta) = meta {
                    if let Some(detect_source) = meta.detect_source {
                        if !detect_source.is_empty() {
                            output.write_str("if (!(");
                            output.write_str(detect_source.as_str());
                            output.write_str(")) {");
                            output.write_str(lf);
                            output.append(polyfill_source(store, &feature_name, m));
                            output.write_str(lf);
                            output.write_str("}");
                            output.write_str(lf);
                            output.write_str(lf);
                        }
                    }
                } else {
                    output.append(polyfill_source(store, &feature_name, m));
                }
            } else {
                output.append(polyfill_source(store, &feature_name, m));
            }
        }
        // Invoke the closure, passing the global object as the only argument
        output.write_str("})");
        output.write_str(lf);
        output.write_str("('object' === typeof window && window || 'object' === typeof self && self || 'object' === typeof global && global || {});");
        output.write_str(lf);
    } else if !options.minify {
        output.write_str("\n/* No polyfills needed for current settings and browser */\n\n");
    }
    if let Some(callback) = &options.callback {
        output.write_str("\ntypeof ");
        output.write_str(&callback);
        output.write_str("==='function' && ");
        output.write_str(&callback);
        output.write_str("();");
    }
    output
}

static POLYFILL_SOURCE_CONFIG_STORE: OnceLock<ConfigStore> = OnceLock::new();
static POLYFILL_SOURCE_KV_STORE: OnceLock<KVStore> = OnceLock::new();
fn polyfill_source(store: &str, feature_name: &str, format: &str) -> Body {
    let c = POLYFILL_SOURCE_CONFIG_STORE.get_or_init(|| {
        let n = store.replace(['-', '.'], "_");
        ConfigStore::open(&n)
    });
    let c = c.get(&format!("{feature_name}/{format}.js"));
    if let Some(c) = c {
        return Body::from(c);
    }
    let polyfills =
        POLYFILL_SOURCE_KV_STORE.get_or_init(|| KVStore::open(&store).unwrap().unwrap());
    // return Body::from("value");
    let polyfill = polyfills
        .lookup(&format!("/{feature_name}/{format}.js"))
        .unwrap();
    if polyfill.is_none() {
        let format = if format == "raw" { "min" } else { "raw" };
        let polyfill = polyfills
            .lookup(&format!("/{feature_name}/{format}.js"))
            .unwrap();
        return polyfill.unwrap();
    }
    polyfill.unwrap()
}
