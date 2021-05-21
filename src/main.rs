mod auth;
mod config;
mod metric;

pub mod proto {
    tonic::include_proto!("emqx.exhook.v1");
}

use proto::{
    hook_provider_server::HookProvider, hook_provider_server::HookProviderServer,
    ClientAuthenticateRequest, ClientCheckAclRequest, ClientConnackRequest, ClientConnectRequest,
    ClientConnectedRequest, ClientDisconnectedRequest, ClientSubscribeRequest,
    ClientUnsubscribeRequest, EmptySuccess, LoadedResponse, MessageAckedRequest,
    MessageDeliveredRequest, MessageDroppedRequest, MessagePublishRequest, ProviderLoadedRequest,
    ProviderUnloadedRequest, SessionCreatedRequest, SessionDiscardedRequest, SessionResumedRequest,
    SessionSubscribedRequest, SessionTakeoveredRequest, SessionTerminatedRequest,
    SessionUnsubscribedRequest, ValuedResponse,
};

use crate::{
    auth::AuthPostgres,
    config::Settings,
    proto::valued_response::{ResponsedType, Value},
};
use chrono::{TimeZone, Utc};
use rdkafka::{
    producer::{FutureProducer, FutureRecord},
    ClientConfig,
};
use serde_json::json;
use tokio::time::Duration;
use tonic::{transport::Server, Request, Response, Status};

struct HookProviderService {
    settings: Settings,
    kafka_producer: FutureProducer,
    auth: AuthPostgres,
}

impl HookProviderService {
    async fn new() -> HookProviderService {
        let settings = Settings::new().unwrap();
        println!("settings: {:#?}", settings);
        let producer = ClientConfig::new()
            .set("bootstrap.servers", &settings.kafka_brokers)
            .set("message.timeout.ms", "5000")
            .create()
            .expect("Producer creation error");
        HookProviderService {
            auth: AuthPostgres::new(&settings.postgres_url, settings.acl_cache_ttl).await,
            kafka_producer: producer,
            settings: settings.clone(),
        }
    }
    async fn publish(&self, topic: &str, data: &serde_json::Value) {
        metric::send(&format!("kafka.{}", topic)).await;
        let payload = &data.to_string();
        let record: FutureRecord<String, String> = FutureRecord::to(&topic).payload(payload);
        let status = self
            .kafka_producer
            .send(record, Duration::from_secs(5))
            .await;
        if let Err((err, _)) = status {
            println!("message deliver failed to {}: {}", topic, err.to_string())
        }
    }
}

#[tonic::async_trait]
impl HookProvider for HookProviderService {
    async fn on_provider_loaded(
        &self,
        request: Request<ProviderLoadedRequest>,
    ) -> Result<Response<LoadedResponse>, Status> {
        metric::send("hook.on_provider_loaded").await;
        let broker = request.into_inner().broker.unwrap();
        println!("broker connected = {:?}", broker.sysdescr);
        Ok(Response::new(LoadedResponse {
            hooks: self.settings.loaded_hooks(),
        }))
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
        metric::send("hook.on_client_connect").await;
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
            self.publish(
                &self.settings.on_client_connect.as_ref().unwrap().topic,
                &data,
            )
            .await;
        };
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_client_connack(
        &self,
        request: Request<ClientConnackRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_client_connack").await;
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
            self.publish(
                &self.settings.on_client_connack.as_ref().unwrap().topic,
                &data,
            )
            .await;
        }
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_client_connected(
        &self,
        request: Request<ClientConnectedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_client_connected").await;
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
            self.publish(
                &self.settings.on_client_connected.as_ref().unwrap().topic,
                &data,
            )
            .await;
        }
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_client_disconnected(
        &self,
        request: Request<ClientDisconnectedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_client_disconnected").await;
        let req = request.into_inner();
        if let Some(conn_info) = req.clientinfo {
            let data = json!({
                "node": conn_info.node,
                "client_id": conn_info.clientid,
                "username": conn_info.username,
                "disconnected_at": chrono::Utc::now().to_rfc3339(),
                "reason": req.reason,
            });
            self.auth.clear_cache(&conn_info.username).await;
            self.publish(
                &self.settings.on_client_disconnected.as_ref().unwrap().topic,
                &data,
            )
            .await;
        }
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_client_authenticate(
        &self,
        request: Request<ClientAuthenticateRequest>,
    ) -> Result<Response<ValuedResponse>, Status> {
        metric::send("hook.on_client_authenticate").await;
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
        metric::send("hook.on_client_check_acl").await;
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
        metric::send("hook.on_client_subscribe").await;
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
            self.publish(
                &self.settings.on_client_subscribe.as_ref().unwrap().topic,
                &data,
            )
            .await;
        };
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_client_unsubscribe(
        &self,
        request: Request<ClientUnsubscribeRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_client_unsubscribe").await;
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
            self.publish(
                &self.settings.on_client_unsubscribe.as_ref().unwrap().topic,
                &data,
            )
            .await;
        };
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_session_created(
        &self,
        request: Request<SessionCreatedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_session_created").await;
        let req = request.into_inner();
        if let Some(client_info) = req.clientinfo {
            let data = json!({
                "node": client_info.node,
                "client_id": client_info.clientid,
                "username": client_info.username,
            });
            self.publish(
                &self.settings.on_client_created.as_ref().unwrap().topic,
                &data,
            )
            .await;
        }
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_session_subscribed(
        &self,
        request: Request<SessionSubscribedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_session_subscribed").await;
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
            self.publish(
                &self.settings.on_session_subscribed.as_ref().unwrap().topic,
                &data,
            )
            .await;
        }
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_session_unsubscribed(
        &self,
        request: Request<SessionUnsubscribedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_session_unsubscribed").await;
        let req = request.into_inner();
        if let Some(client_info) = req.clientinfo {
            let data = json!({
                "node": client_info.node,
                "client_id": client_info.clientid,
                "username": client_info.username,
                "topic": req.topic,
            });
            self.publish(
                &self
                    .settings
                    .on_session_unsubscribed
                    .as_ref()
                    .unwrap()
                    .topic,
                &data,
            )
            .await;
        }
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_session_resumed(
        &self,
        _request: Request<SessionResumedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_session_resumed").await;
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_session_discarded(
        &self,
        _request: Request<SessionDiscardedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_session_discarded").await;
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_session_takeovered(
        &self,
        _request: Request<SessionTakeoveredRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_session_takeovered").await;
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_session_terminated(
        &self,
        request: Request<SessionTerminatedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_session_terminated").await;
        let req = request.into_inner();
        if let Some(client_info) = req.clientinfo {
            let data = json!({
                "node": client_info.node,
                "client_id": client_info.clientid,
                "username": client_info.username,
                "reason": req.reason,
            });
            self.publish(
                &self.settings.on_session_terminated.as_ref().unwrap().topic,
                &data,
            )
            .await;
        }
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_message_publish(
        &self,
        request: Request<MessagePublishRequest>,
    ) -> Result<Response<ValuedResponse>, Status> {
        metric::send("hook.on_message_publish").await;
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
            self.publish(
                &self.settings.on_message_publish.as_ref().unwrap().topic,
                &data,
            )
            .await;
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
        metric::send("hook.on_message_delivered").await;
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
            self.publish(
                &self.settings.on_message_delivered.as_ref().unwrap().topic,
                &data,
            )
            .await;
        }
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_message_dropped(
        &self,
        _request: Request<MessageDroppedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_message_dropped").await;
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_message_acked(
        &self,
        request: Request<MessageAckedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_message_acked").await;
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
            self.publish(
                &self.settings.on_message_acked.as_ref().unwrap().topic,
                &data,
            )
            .await;
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
    let svc = HookProviderService::new().await;
    let addr = "0.0.0.0:10000".parse().unwrap();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            ticker.tick().await;
            println!("metrics: {:#?}", metric::read_all().await)
        }
    });

    println!("HealthServer + HookProviderServer listening on {}", addr);
    Server::builder()
        .add_service(HookProviderServer::new(svc))
        .add_service(health_service)
        .serve(addr)
        .await?;
    Ok(())
}
