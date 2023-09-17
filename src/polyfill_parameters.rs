use std::collections::{HashMap, HashSet};

#[derive(Clone, Default)]
pub(crate) struct PolyfillParameters {
    pub excludes: Vec<String>,
    pub features: HashMap<String, HashSet<String>>,
    pub minify: bool,
    pub callback: Option<String>,
    pub unknown: String,
    pub ua_string: String,
    pub version: String,
}
