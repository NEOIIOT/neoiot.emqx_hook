mod auth;
// mod proto;

pub mod proto {
    tonic::include_proto!("emqx.exhook.v1");
}

use proto::{
    hook_provider_server::HookProvider, hook_provider_server::HookProviderServer,
    ClientAuthenticateRequest, ClientCheckAclRequest, ClientConnackRequest, ClientConnectRequest,
    ClientConnectedRequest, ClientDisconnectedRequest, ClientSubscribeRequest,
    ClientUnsubscribeRequest, EmptySuccess, HookSpec, LoadedResponse, MessageAckedRequest,
    MessageDeliveredRequest, MessageDroppedRequest, MessagePublishRequest, ProviderLoadedRequest,
    ProviderUnloadedRequest, SessionCreatedRequest, SessionDiscardedRequest, SessionResumedRequest,
    SessionSubscribedRequest, SessionTakeoveredRequest, SessionTerminatedRequest,
    SessionUnsubscribedRequest, ValuedResponse,
};

use crate::auth::AuthPostgres;
use crate::proto::valued_response::{ResponsedType, Value};
use chrono::{TimeZone, Utc};
use rdkafka::{
    producer::{FutureProducer, FutureRecord},
    ClientConfig,
};
use serde_json::json;
use std::{collections::HashMap, env, sync::Arc, time::Duration};
use tonic::{
    transport::{NamedService, Server},
    Request, Response, Status,
};

const AVAILABLE_HOOKS: [&str; 13] = [
    "ON_CLIENT_CONNECT",
    "ON_CLIENT_CONNACK",
    "ON_CLIENT_CONNECTED",
    "ON_CLIENT_DISCONNECTED",
    "ON_CLIENT_SUBSCRIBE",
    "ON_CLIENT_UNSUBSCRIBE",
    "ON_SESSION_CREATED",
    "ON_SESSION_SUBSCRIBED",
    "ON_SESSION_UNSUBSCRIBED",
    "ON_SESSION_TERMINATED",
    "ON_MESSAGE_PUBLISH",
    "ON_MESSAGE_DELIVERED",
    "ON_MESSAGE_ACKED",
    // "ON_SESSION_RESUMED",
    // "ON_SESSION_DISCARDED",
    // "ON_SESSION_TAKEOVERED",
    // "ON_MESSAGE_DROPPED",
];

struct HookProviderService {
    loaded_hooks: Arc<HashMap<String, KafkaConfig>>,
    producer: FutureProducer,
    auth: AuthPostgres,
}

impl HookProviderService {
    async fn new() -> HookProviderService {
        let brokers = env::var("KAFKA_BROKERS").expect("KAFKA_BROKERS must set");
        println!("brokers: {:?}", brokers);
        let producer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("message.timeout.ms", "5000")
            .create()
            .expect("Producer creation error");
        HookProviderService {
            loaded_hooks: Arc::new(Self::load_hooks()),
            producer,
            auth: AuthPostgres::new().await,
        }
    }
    async fn publish(&self, hook: &str, data: &serde_json::Value) {
        let payload = data.to_string();
        if let Some(config) = self.loaded_hooks.get(hook) {
            let record: FutureRecord<String, String> =
                FutureRecord::to(&config.topic).payload(&payload);
            let status = self.producer.send(record, Duration::from_secs(5)).await;
            match status {
                Ok(_) => {
                    println!("{} delivered success", &config.topic)
                }
                Err((err, _)) => {
                    println!(
                        "message deliver failed to {}, err: {}",
                        config.topic,
                        err.to_string()
                    )
                }
            }
        }
    }
    fn load_hooks() -> HashMap<String, KafkaConfig> {
        let mut result = HashMap::new();
        for &hook in AVAILABLE_HOOKS.iter() {
            if let Ok(topic) = env::var(format!("{}_TO_TOPIC", hook)) {
                let action = hook[3..].replace("_", ".").to_lowercase();
                let filters = env::var(format!("{}_FILTERS", hook))
                    .unwrap_or_else(|_| "#".to_string())
                    .split(',')
                    .map(String::from)
                    .collect();
                result.insert(action, KafkaConfig { topic, filters });
            }
        }
        result
    }
}

#[tonic::async_trait]
impl HookProvider for HookProviderService {
    async fn on_provider_loaded(
        &self,
        request: Request<ProviderLoadedRequest>,
    ) -> Result<Response<LoadedResponse>, Status> {
        let broker = request.into_inner().broker.unwrap();
        println!("broker connected = {:?}", broker.sysdescr);
        let mut hook_specs = vec![
            HookSpec {
                name: "client.authenticate".to_string(),
                topics: vec![],
            },
            HookSpec {
                name: "client.check_acl".to_string(),
                topics: vec![],
            },
        ];
        for (hook, config) in self.loaded_hooks.iter() {
            hook_specs.push(HookSpec {
                name: hook.clone(),
                topics: config.filters.clone(),
            })
        }
        Ok(Response::new(LoadedResponse { hooks: hook_specs }))
    }

    async fn on_provider_unloaded(
        &self,
        _: Request<ProviderUnloadedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_client_connect(
        &self,
        request: Request<ClientConnectRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        if let Some(conn_info) = request.into_inner().conninfo {
            let data = json!({
                "node": conn_info.node,
                "client_id": conn_info.clientid,
                "username": conn_info.username,
                "ip_address": conn_info.peerhost,
                "proto_name": conn_info.proto_name,
                "proto_version": conn_info.proto_ver,
                "keepalive": conn_info.keepalive,
            });
            self.publish("client.connect", &data).await;
        };
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_client_connack(
        &self,
        request: Request<ClientConnackRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        let req = request.into_inner();
        if let Some(conn_info) = req.conninfo {
            let data = json!({
                "node": conn_info.node,
                "client_id": conn_info.clientid,
                "username": conn_info.username,
                "ip_address": conn_info.peerhost,
                "proto_name": conn_info.proto_name,
                "proto_version": conn_info.proto_ver,
                "conn_ack": req.result_code,
            });
            self.publish("client.connack", &data).await;
        }
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_client_connected(
        &self,
        request: Request<ClientConnectedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        let req = request.into_inner();
        if let Some(conn_info) = req.clientinfo {
            let data = json!({
                "node": conn_info.node.clone(),
                "client_id": conn_info.clientid,
                "username": conn_info.username,
                "ip_address": conn_info.peerhost,
                "protocol": conn_info.protocol,
                "connected_at": chrono::Utc::now().to_rfc3339(),
            });
            self.publish("client.connected", &data).await;
        }
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_client_disconnected(
        &self,
        request: Request<ClientDisconnectedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        let req = request.into_inner();
        if let Some(conn_info) = req.clientinfo {
            let data = json!({
                "node": conn_info.node,
                "client_id": conn_info.clientid,
                "username": conn_info.username,
                "disconnected_at": chrono::Utc::now().to_rfc3339(),
                "reason": req.reason,
            });
            self.publish("client.disconnected", &data).await;
        }
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_client_authenticate(
        &self,
        request: Request<ClientAuthenticateRequest>,
    ) -> Result<Response<ValuedResponse>, Status> {
        if let Some(client_info) = request.into_inner().clientinfo {
            let verified = self
                .auth
                .authenticate(&client_info.username, &client_info.password)
                .await;
            if verified {
                return Ok(Response::new(ValuedResponse {
                    r#type: ResponsedType::StopAndReturn as i32,
                    value: Some(Value::BoolResult(true)),
                }));
            };
        }
        Ok(Response::new(ValuedResponse {
            r#type: ResponsedType::StopAndReturn as i32,
            value: Some(Value::BoolResult(false)),
        }))
    }

    async fn on_client_check_acl(
        &self,
        request: Request<ClientCheckAclRequest>,
    ) -> Result<Response<ValuedResponse>, Status> {
        let req = request.into_inner();
        let username = req.clientinfo.unwrap().username;
        let passed = self.auth.check_acl(&username, req.r#type, &req.topic).await;
        if passed {
            Ok(Response::new(ValuedResponse {
                r#type: ResponsedType::StopAndReturn as i32,
                value: Some(Value::BoolResult(true)),
            }))
        } else {
            Ok(Response::new(ValuedResponse {
                r#type: ResponsedType::StopAndReturn as i32,
                value: Some(Value::BoolResult(false)),
            }))
        }
    }

    async fn on_client_subscribe(
        &self,
        request: Request<ClientSubscribeRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        let req = request.into_inner();
        if let Some(conn_info) = req.clientinfo {
            let data = json!({
                "node": conn_info.node,
                "client_id": conn_info.clientid,
                "username": conn_info.username,
                "topic_filters": req.topic_filters
                    .iter()
                    .map(|t| json!({"name": t.name, "qos": t.qos}))
                    .collect::<Vec<_>>(),
            });
            self.publish("client.subscribe", &data).await;
        };
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_client_unsubscribe(
        &self,
        request: Request<ClientUnsubscribeRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        let req = request.into_inner();
        if let Some(conn_info) = req.clientinfo {
            let data = json!({
                "node": conn_info.node,
                "client_id": conn_info.clientid,
                "username": conn_info.username,
                "topic_filters": req
                    .topic_filters
                    .iter()
                    .map(|t| json!({"name": t.name, "qos": t.qos}))
                    .collect::<Vec<_>>(),
            });
            self.publish("client.unsubscribe", &data).await;
        };
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_session_created(
        &self,
        request: Request<SessionCreatedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        let req = request.into_inner();
        if let Some(client_info) = req.clientinfo {
            let data = json!({
                "node": client_info.node,
                "client_id": client_info.clientid,
                "username": client_info.username,
            });
            self.publish("session.created", &data).await;
        }
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_session_subscribed(
        &self,
        request: Request<SessionSubscribedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        let req = request.into_inner();
        if let Some(client_info) = req.clientinfo {
            let mut data = json!({
                "node": client_info.node,
                "client_id": client_info.clientid,
                "username": client_info.username,
                "topic": req.topic,
            });
            if let Some(opts) = req.subopts {
                data["sub_opts"] = json!({
                    "qos": opts.qos,
                    "share": opts.share,
                    "rh": opts.rh,
                    "rap": opts.rap,
                    "nl": opts.nl,
                })
            }
            self.publish("session.subscribed", &data).await;
        }
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_session_unsubscribed(
        &self,
        request: Request<SessionUnsubscribedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        let req = request.into_inner();
        if let Some(client_info) = req.clientinfo {
            let data = json!({
                "node": client_info.node,
                "client_id": client_info.clientid,
                "username": client_info.username,
                "topic": req.topic,
            });
            self.publish("session.unsubscribed", &data).await;
        }
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_session_resumed(
        &self,
        _request: Request<SessionResumedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_session_discarded(
        &self,
        _request: Request<SessionDiscardedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_session_takeovered(
        &self,
        _request: Request<SessionTakeoveredRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_session_terminated(
        &self,
        request: Request<SessionTerminatedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        let req = request.into_inner();
        if let Some(client_info) = req.clientinfo {
            let data = json!({
                "node": client_info.node,
                "client_id": client_info.clientid,
                "username": client_info.username,
                "reason": req.reason,
            });
            self.publish("client.terminated", &data).await;
        }
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_message_publish(
        &self,
        request: Request<MessagePublishRequest>,
    ) -> Result<Response<ValuedResponse>, Status> {
        let req = request.into_inner();
        if let Some(message) = req.message {
            let encoding;
            let payload;
            match String::from_utf8(message.payload.clone()) {
                Ok(payload_str) => {
                    encoding = "plain";
                    payload = payload_str;
                }
                Err(_) => {
                    encoding = "base64";
                    payload = base64::encode(message.payload);
                }
            }
            let data = json!({
                "node": message.node,
                "id": message.id,
                "qos": message.qos,
                "from_client_id": message.from,
                "topic": message.topic,
                "encoding": encoding,
                "payload": payload,
                "time": Utc.timestamp_millis(message.timestamp as i64).to_rfc3339()
            });
            self.publish("message.publish", &data).await;
        }
        Ok(Response::new(ValuedResponse {
            r#type: 0,
            value: None,
        }))
    }

    async fn on_message_delivered(
        &self,
        request: Request<MessageDeliveredRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        let req = request.into_inner();
        if let Some(message) = req.message {
            let mut data = json!({
                "client_id": "",
                "username": "",
                "node": message.node,
                "id": message.id,
                "qos": message.qos,
                "from": message.from,
                "topic": message.topic,
                "payload": message.payload,
                "time": Utc.timestamp_millis(message.timestamp as i64).to_rfc3339()}
            );
            if let Some(client_info) = req.clientinfo {
                data["client_id"] = json!(client_info.clientid);
                data["username"] = json!(client_info.username);
            }
            self.publish("message.delivered", &data).await;
        }
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_message_dropped(
        &self,
        _request: Request<MessageDroppedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_message_acked(
        &self,
        request: Request<MessageAckedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        let req = request.into_inner();
        if let Some(message) = req.message {
            let mut data = json!({
                "node": message.node,
                "id": message.id,
                "qos": message.qos,
                "from": message.from,
                "topic": message.topic,
                "payload": message.payload,
                "time": Utc.timestamp_millis(message.timestamp as i64).to_rfc3339()
            }
            );
            if let Some(client_info) = req.clientinfo {
                data["client_id"] = json!(client_info.clientid);
                data["username"] = json!(client_info.username);
            }
            self.publish("message.acked", &data).await;
        }
        Ok(Response::new(EmptySuccess {}))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<HookProviderServer<HookProviderService>>()
        .await;
    let service_name = <HookProviderServer<HookProviderService> as NamedService>::NAME;
    println!("{}", service_name);

    let svc = HookProviderServer::new(HookProviderService::new().await);
    let addr = "0.0.0.0:10000".parse().unwrap();

    println!("HealthServer + HookProviderServer listening on {}", addr);
    Server::builder()
        .add_service(svc)
        .add_service(health_service)
        .serve(addr)
        .await?;
    Ok(())
}

#[derive(Debug)]
struct KafkaConfig {
    pub topic: String,
    pub filters: Vec<String>,
}
