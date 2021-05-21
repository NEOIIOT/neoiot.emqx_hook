use anyhow::{anyhow, Result};
use lru_time_cache::LruCache;
use sqlx::{FromRow, PgPool};
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::sync::Mutex;

use crate::metric;
const Q_USER: &str = "SELECT mqtt_secret, is_super FROM devices WHERE is_active = TRUE AND deleted_at IS NULL AND mqtt_username = $1 LIMIT 1";

#[derive(FromRow)]
pub struct UserInfo {
    pub mqtt_secret: String,
    pub is_super: bool,
}

const Q_ACL: &str = "SELECT acl_pubs, acl_subs FROM devices WHERE is_active = TRUE AND deleted_at IS NULL AND mqtt_username = $1 LIMIT 1";

#[derive(FromRow, Clone, Default)]
pub struct Acl {
    pub acl_pubs: Vec<String>,
    pub acl_subs: Vec<String>,
}

pub struct AuthPostgres {
    pg_pool: PgPool,
    acl_cache: Arc<Mutex<LruCache<String, Acl>>>,
    super_cache: Arc<Mutex<HashSet<String>>>,
}

impl AuthPostgres {
    pub async fn new(postgres_url: &str, acl_cache_ttl: u64) -> AuthPostgres {
        let pg_pool = PgPool::connect(postgres_url)
            .await
            .expect("postgres connect failed");
        let acl_cache = LruCache::with_expiry_duration(Duration::from_secs(acl_cache_ttl));
        let super_cache = HashSet::new();
        return AuthPostgres {
            pg_pool,
            acl_cache: Arc::new(Mutex::new(acl_cache)),
            super_cache: Arc::new(Mutex::new(super_cache)),
        };
    }

    async fn _query_user(&self, username: &str, password: &str) -> Result<UserInfo> {
        metric::send("auth.query_user").await;
        println!("fetching remote user data");
        let user = sqlx::query_as::<_, UserInfo>(Q_USER)
            .bind(username)
            .fetch_one(&self.pg_pool)
            .await?;
        if !bcrypt::verify(password, &user.mqtt_secret)? {
            return Err(anyhow!("password verify failed"));
        }
        Ok(user)
    }

    pub async fn authenticate(&self, username: &str, password: &str) -> bool {
        match self._query_user(username, password).await {
            Ok(u) => {
                if u.is_super {
                    self.super_cache.lock().await.insert(username.to_string());
                }
                true
            }
            Err(err) => {
                println!("authenticate failed :{}", err.to_string());
                self.clear_cache(username).await;
                false
            }
        }
    }

    async fn _query_acl(&self, username: &str) -> Result<Acl> {
        metric::send("auth.query_acl").await;
        println!("fetching remote acl rules");
        let acl = sqlx::query_as::<_, Acl>(Q_ACL)
            .bind(username)
            .fetch_one(&self.pg_pool)
            .await?;
        Ok(acl)
    }

    async fn _get_acl(&self, username: &str) -> Acl {
        let mut c = self.acl_cache.lock().await;
        let cached = c.peek(username);
        if let Some(acl) = cached {
            metric::send("auth.query_acl.hit_cache").await;
            return acl.clone();
        }
        let new_acl = self._query_acl(username).await;
        return match new_acl {
            Ok(acl) => {
                c.insert(username.to_string(), acl.clone());
                acl
            }
            Err(err) => {
                println!("get new acl failed {}", err);
                Acl::default()
            }
        };
    }
    pub async fn check_acl(&self, username: &str, r#type: i32, topic: &str) -> bool {
        {
            // 如果是超级用户则无需判断,提前释放锁
            if self.super_cache.lock().await.contains(username) {
                return true;
            }
        }
        let acl = self._get_acl(username).await;
        let rules;
        match r#type {
            0 => rules = acl.acl_pubs,
            1 => rules = acl.acl_subs,
            _ => return false,
        }
        let passed = rules.iter().fold(false, |prev, filter| {
            if prev {
                true
            } else {
                matches(topic, filter)
            }
        });
        if !passed{
            println!("acl auth failed. username: {}, topic: {}, type: {}, white list: {:?}", username, topic, r#type, rules);
        };
        passed
    }
    pub async fn clear_cache(&self, username: &str){
        self.super_cache.lock().await.remove(username);
        self.acl_cache.lock().await.remove(username);
    }
}

pub fn matches(topic: &str, filter: &str) -> bool {
    if !topic.is_empty() && topic[..1].contains('$') {
        return false;
    }

    let mut topics = topic.split('/');
    let mut filters = filter.split('/');

    for f in filters.by_ref() {
        // "#" being the last element is validated by the broker with 'valid_filter'
        if f == "#" {
            return true;
        }

        // filter still has remaining elements
        // filter = a/b/c/# should match topci = a/b/c
        // filter = a/b/c/d should not match topic = a/b/c
        let top = topics.next();
        match top {
            Some("#") => return false,
            Some(_) if f == "+" => continue,
            Some(t) if f != t => return false,
            Some(_) => continue,
            None => return false,
        }
    }

    // topic has remaining elements and filter's last element isn't "#"
    if topics.next().is_some() {
        return false;
    }

    true
}
