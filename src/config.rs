use crate::proto::HookSpec;
use config::{Config, ConfigError, Environment};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct HookConfig {
    pub topic: String,
    pub filters: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub postgres_url: String,
    pub kafka_brokers: String,
    pub acl_cache_ttl: u64,
    pub on_client_connect: Option<HookConfig>,
    pub on_client_connack: Option<HookConfig>,
    pub on_client_connected: Option<HookConfig>,
    pub on_client_disconnected: Option<HookConfig>,
    pub on_client_subscribe: Option<HookConfig>,
    pub on_client_unsubscribe: Option<HookConfig>,
    pub on_client_created: Option<HookConfig>,
    pub on_session_subscribed: Option<HookConfig>,
    pub on_session_unsubscribed: Option<HookConfig>,
    pub on_session_terminated: Option<HookConfig>,
    pub on_message_publish: Option<HookConfig>,
    pub on_message_delivered: Option<HookConfig>,
    pub on_message_acked: Option<HookConfig>,
}

impl Settings {
    pub fn loaded_hooks(&self) -> Vec<HookSpec> {
        let mut hooks = vec![
            HookSpec {
                name: "client.authenticate".to_string(),
                topics: vec![],
            },
            HookSpec {
                name: "client.check_acl".to_string(),
                topics: vec![],
            },
        ];
        if let Some(c) = &self.on_client_connect {
            parse_topics(c.filters.as_deref());
            hooks.push(HookSpec {
                name: "client.connect".to_string(),
                topics: parse_topics(c.filters.as_deref()),
            });
        }
        if let Some(c) = &self.on_client_connack {
            hooks.push(HookSpec {
                name: "client.connack".to_string(),
                topics: parse_topics(c.filters.as_deref()),
            });
        }
        if let Some(c) = &self.on_client_connected {
            hooks.push(HookSpec {
                name: "client.connected".to_string(),
                topics: parse_topics(c.filters.as_deref()),
            });
        }
        if let Some(c) = &self.on_client_disconnected {
            hooks.push(HookSpec {
                name: "client.disconnected".to_string(),
                topics: parse_topics(c.filters.as_deref()),
            });
        }
        if let Some(c) = &self.on_client_subscribe {
            hooks.push(HookSpec {
                name: "client.subscribe".to_string(),
                topics: parse_topics(c.filters.as_deref()),
            });
        }
        if let Some(c) = &self.on_client_unsubscribe {
            hooks.push(HookSpec {
                name: "client.unsubscribe".to_string(),
                topics: parse_topics(c.filters.as_deref()),
            });
        }
        if let Some(c) = &self.on_client_created {
            hooks.push(HookSpec {
                name: "client.created".to_string(),
                topics: parse_topics(c.filters.as_deref()),
            });
        }
        if let Some(c) = &self.on_session_subscribed {
            hooks.push(HookSpec {
                name: "session.subscribed".to_string(),
                topics: parse_topics(c.filters.as_deref()),
            });
        }
        if let Some(c) = &self.on_session_unsubscribed {
            hooks.push(HookSpec {
                name: "session.unsubscribed".to_string(),
                topics: parse_topics(c.filters.as_deref()),
            });
        }
        if let Some(c) = &self.on_session_terminated {
            hooks.push(HookSpec {
                name: "session.terminated".to_string(),
                topics: parse_topics(c.filters.as_deref()),
            });
        }
        if let Some(c) = &self.on_message_publish {
            hooks.push(HookSpec {
                name: "message.publish".to_string(),
                topics: parse_topics(c.filters.as_deref()),
            });
        }
        if let Some(c) = &self.on_message_acked {
            hooks.push(HookSpec {
                name: "message.acked".to_string(),
                topics: parse_topics(c.filters.as_deref()),
            });
        }
        if let Some(c) = &self.on_message_delivered {
            hooks.push(HookSpec {
                name: "message.delivered".to_string(),
                topics: parse_topics(c.filters.as_deref()),
            });
        }
        hooks
    }
    pub fn new() -> Result<Self, ConfigError> {
        let mut settings = Config::default();
        settings.merge(Environment::with_prefix("NEOIOT"))?;
        settings.try_into()
    }
}

fn parse_topics(s: Option<&str>) -> Vec<String> {
    s.unwrap_or("#").split(',').map(String::from).collect()
}
