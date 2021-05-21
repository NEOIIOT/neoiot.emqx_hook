use lazy_static::lazy_static;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;

lazy_static! {
    static ref M: Arc<RwLock<BTreeMap<String, usize>>> = Arc::new(RwLock::new(BTreeMap::new()));
}

pub async fn send(metric: &str) {
    *M.write().await.entry(metric.to_string()).or_insert(0) += 1;
}
pub async fn read_all() -> BTreeMap<String, usize> {
    M.read().await.clone()
}
