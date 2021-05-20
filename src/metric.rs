use lazy_static::lazy_static;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;

lazy_static! {
    pub static ref M: Arc<RwLock<BTreeMap<String, usize>>> = Arc::new(RwLock::new(BTreeMap::new()));
}
