use std::collections::HashMap;

pub(crate) trait UserAgent {
    fn new(ua_string: &str) -> Self;
	fn get_family(&self) -> String;
	fn satisfies(&self, range: String) -> bool;
	fn meets_baseline(&self) -> bool;
	fn is_unknown(&self) -> bool;
	fn get_baselines() -> HashMap<String, String>;
}