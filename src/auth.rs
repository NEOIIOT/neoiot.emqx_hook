use anyhow::{anyhow, Result};
use lru_time_cache::LruCache;
use sqlx::{FromRow, PgPool};
use std::collections::HashSet;
use std::{env, sync::Arc, time};
use tokio::sync::Mutex;

const ACL_EXPIRES: time::Duration = time::Duration::from_secs(60);

const Q_USER: &str = "SELECT mqtt_secret, is_super FROM devices WHERE is_active = TRUE AND deleted_at IS NULL AND mqtt_username = $1 LIMIT 1";

#[derive(FromRow)]
pub struct UserInfo {
    pub mqtt_secret: String,
    pub is_super: bool,
}

const Q_ACL: &str = "SELECT acl_pubs, acl_subs FROM devices WHERE is_active = TRUE AND deleted_at IS NULL AND mqtt_username = $1 LIMIT 1";

const PUBLISH: i32 = 0;
const SUBSCRIBE: i32 = 1;

#[derive(FromRow)]
pub struct Acl {
    pub acl_pubs: Vec<String>,
    pub acl_subs: Vec<String>,
}

pub struct AuthPostgres {
    pg_pool: PgPool,
    acl_cache: Arc<Mutex<LruCache<String, [Vec<String>; 2]>>>,
    super_cache: Arc<Mutex<HashSet<String>>>,
}

impl AuthPostgres {
    pub async fn new() -> AuthPostgres {
        let uri = env::var("POSTGRES_DSN").expect("POSTGRES_DSN must set");
        let pg_pool = PgPool::connect(&uri)
            .await
            .expect("postgres connect failed");
        let acl_cache = LruCache::with_expiry_duration(ACL_EXPIRES);
        let super_cache = HashSet::new();
        return AuthPostgres {
            pg_pool,
            acl_cache: Arc::new(Mutex::new(acl_cache)),
            super_cache: Arc::new(Mutex::new(super_cache)),
        };
    }

    async fn _query_user(&self, username: &str, password: &str) -> Result<UserInfo> {
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
        let mut c = self.super_cache.lock().await;
        match self._query_user(username, password).await {
            Ok(u) => {
                if u.is_super {
                    c.insert(username.to_string());
                }
                true
            }
            Err(err) => {
                println!("authenticate failed :{}", err.to_string());
                c.remove(&username.to_string());
                false
            }
        }
    }

    async fn _query_acl(&self, username: &str) -> Result<[Vec<String>; 2]> {
        println!("fetching remote acl rules");
        let user = sqlx::query_as::<_, Acl>(Q_ACL)
            .bind(username)
            .fetch_one(&self.pg_pool)
            .await?;
        Ok([user.acl_pubs, user.acl_subs])
    }

    async fn _get_acl(&self, username: &str) -> [Vec<String>; 2] {
        let mut c = self.acl_cache.lock().await;
        let cached = c.peek(username);
        if let Some(acl) = cached {
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
                [vec![], vec![]]
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
        let [pubs, subs] = self._get_acl(username).await;
        let rules;
        match r#type {
            PUBLISH => rules = pubs,
            SUBSCRIBE => rules = subs,
            _ => return false,
        }

        return rules.iter().fold(false, |prev, filter| {
            if prev {
                true
            } else {
                matches(topic, filter).is_some()
            }
        });
    }
}

fn matches(topic: &str, filter: &str) -> Option<Vec<String>> {
    // topic must not contain wildcards.
    if topic.contains('+') || topic.contains('#') {
        return None;
    }
    if filter == topic {
        return Some(vec![]);
    }
    if filter == "#" {
        return Some(vec![topic.to_string()]);
    }
    let topics = topic.split('/').collect::<Vec<&str>>();
    let filters = filter.split('/').collect::<Vec<&str>>();

    let mut result = vec![];

    let mut cursor = 0;
    while cursor < topics.len() {
        match filters.get(cursor) {
            None => return None,
            Some(&"+") => result.push(topics[cursor].to_string()),
            Some(&"#") => {
                result.push(topics[cursor..].join("/"));
                return Some(result);
            }
            Some(&x) if x != topics[cursor] => return None,
            _ => {}
        }
        cursor += 1;
    }
    if let Some(&"#") = filters.get(cursor) {
        cursor += 1;
    }
    if filters.len() == cursor {
        return Some(result);
    }
    None
}

#[cfg(test)]
mod test {
    #[test]
    fn topics_match_with_filters_as_expected() {
        // full matching
        assert_eq!(super::matches("test/123", "test/123"), Some(vec![]));
        // no matching
        assert!(super::matches("test/test/test", "test/test").is_none());
        assert!(super::matches("test/test", "test/test/test").is_none());
        assert!(super::matches("test/test", "test/test/test/test").is_none());
        // matching #
        assert_eq!(super::matches("test", "#"), Some(vec!["test".to_string()]));
        assert_eq!(
            super::matches("test/test", "#"),
            Some(vec!["test/test".to_string()])
        );
        assert_eq!(
            super::matches("test/test", "#"),
            Some(vec!["test/test".to_string()])
        );
        assert_eq!(
            super::matches("test/test", "test/#"),
            Some(vec!["test".to_string()])
        );
        assert_eq!(
            super::matches("test/test/test", "test/#"),
            Some(vec!["test/test".to_string()])
        );
        assert_eq!(super::matches("/", "/#"), Some(vec!["".to_string()]));
        assert_eq!(
            super::matches("/test", "/#"),
            Some(vec!["test".to_string()])
        );
        assert_eq!(
            super::matches("/test/", "/#"),
            Some(vec!["test/".to_string()])
        );
        assert_eq!(super::matches("test/test", "test/test/#"), Some(vec![]));
        // mismatching #
        assert!(super::matches("test", "/#").is_none());
        assert!(super::matches("", "test/#").is_none());
        // matching +
        assert_eq!(super::matches("test", "+"), Some(vec!["test".to_string()]));
        assert_eq!(
            super::matches("test/", "test/+"),
            Some(vec!["".to_string()])
        );
        assert_eq!(
            super::matches("test/test", "test/+"),
            Some(vec!["test".to_string()])
        );
        assert_eq!(
            super::matches("test/test/test", "test/+/+"),
            Some(vec!["test".to_string(), "test".to_string()])
        );
        assert_eq!(
            super::matches("test/test/test", "test/+/test"),
            Some(vec!["test".to_string()])
        );
        // mismatching +
        assert!(super::matches("test", "/+").is_none());
        assert!(super::matches("test", "test/+").is_none());
        assert!(super::matches("test/test", "test/test/+").is_none());
        // matching + #
        assert_eq!(
            super::matches("test/test", "+/#"),
            Some(vec!["test".to_string(), "test".to_string()])
        );
        assert_eq!(
            super::matches("test/test/", "+/test/#"),
            Some(vec!["test".to_string(), "".to_string()])
        );
        assert_eq!(
            super::matches("test/test/", "test/+/#"),
            Some(vec!["test".to_string(), "".to_string()])
        );
        assert_eq!(
            super::matches("test/test/test", "+/test/#"),
            Some(vec!["test".to_string(), "test".to_string()])
        );
        assert_eq!(
            super::matches("test/test/test", "test/+/#"),
            Some(vec!["test".to_string(), "test".to_string()])
        );
        assert_eq!(
            super::matches("test/test/test", "+/+/#"),
            Some(vec![
                "test".to_string(),
                "test".to_string(),
                "test".to_string()
            ])
        );
        assert_eq!(
            super::matches("test/test/test/test", "test/+/+/#"),
            Some(vec![
                "test".to_string(),
                "test".to_string(),
                "test".to_string()
            ])
        );
        assert_eq!(
            super::matches("test", "+/#"),
            Some(vec!["test".to_string()])
        );
        assert_eq!(
            super::matches("test/test", "test/+/#"),
            Some(vec!["test".to_string()])
        );
        assert_eq!(
            super::matches("test/test/test", "test/+/test/#"),
            Some(vec!["test".to_string()])
        );

        // invalid topic
        assert!(super::matches("a/b/+", "#").is_none());
        assert!(super::matches("a/+/c/d", "a/+/+/d").is_none());
        assert!(super::matches("a/+/+/d", "a/+/c/d").is_none());
    }
}
