#[macro_use]
extern crate serde;

use std::{collections::HashMap, sync::Arc};

use serde::Serialize;
use tokio::sync::Mutex;
use tonic::{transport::Server, Request, Response, Status};

use proto::{
    hook_provider_server::HookProvider,
    hook_provider_server::HookProviderServer,
    valued_response::{ResponsedType, Value},
    ClientAuthenticateRequest, ClientCheckAclRequest, ClientConnackRequest, ClientConnectRequest,
    ClientConnectedRequest, ClientDisconnectedRequest, ClientSubscribeRequest,
    ClientUnsubscribeRequest, EmptySuccess, LoadedResponse, MessageAckedRequest,
    MessageDeliveredRequest, MessageDroppedRequest, MessagePublishRequest, ProviderLoadedRequest,
    ProviderUnloadedRequest, SessionCreatedRequest, SessionDiscardedRequest, SessionResumedRequest,
    SessionSubscribedRequest, SessionTakeoveredRequest, SessionTerminatedRequest,
    SessionUnsubscribedRequest, ValuedResponse,
};

use crate::{auth::AuthPostgres, config::Settings};
use pulsar::{Producer, Pulsar, TokioExecutor};

mod auth;
mod config;
mod metric;
#[path = "emqx.exhook.v1.rs"]
pub mod proto;

struct HookProviderService {
    settings: Settings,
    producers: Arc<Mutex<HashMap<String, Producer<TokioExecutor>>>>,
    pulsar: Pulsar<TokioExecutor>,
    auth: AuthPostgres,
}

impl HookProviderService {
    async fn new() -> HookProviderService {
        let settings = Settings::new().unwrap();
        println!("settings: {:#?}", settings);
        let pulsar = Pulsar::builder(&settings.pulsar_url, TokioExecutor)
            .build()
            .await
            .unwrap();

        HookProviderService {
            producers: Arc::new(Mutex::new(HashMap::new())),
            pulsar,
            auth: AuthPostgres::new(&settings.postgres_url, settings.acl_cache_ttl).await,
            settings: settings.clone(),
        }
    }

    async fn publish<T: ?Sized + Serialize>(&self, topic: &str, data: &T) {
        metric::send(&format!("pulsar.{}", topic)).await;
        let payload = serde_json::to_string(data).unwrap();

        let mut producers = self.producers.lock().await;
        if !producers.contains_key(topic) {
            let producer = self
                .pulsar
                .producer()
                .with_topic(topic)
                .with_name("exhook")
                .build()
                .await
                .unwrap();
            producers.insert(topic.into(), producer);
        }
        let _ = producers
            .get_mut(topic)
            .unwrap()
            .send(payload)
            .await
            .unwrap()
            .await
            .unwrap();
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
        let data = request.into_inner();
        self.publish(
            &self.settings.on_client_connect.as_ref().unwrap().topic,
            &data,
        )
        .await;
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_client_connack(
        &self,
        request: Request<ClientConnackRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_client_connack").await;
        let req = request.into_inner();
        self.publish(
            &self.settings.on_client_connack.as_ref().unwrap().topic,
            &req,
        )
        .await;
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_client_connected(
        &self,
        request: Request<ClientConnectedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_client_connected").await;
        let req = request.into_inner();
        self.publish(
            &self.settings.on_client_connected.as_ref().unwrap().topic,
            &req,
        )
        .await;
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_client_disconnected(
        &self,
        request: Request<ClientDisconnectedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_client_disconnected").await;
        let req = request.into_inner();
        if let Some(ref conn_info) = req.clientinfo {
            self.auth.clear_cache(&conn_info.username).await;
        }
        self.publish(
            &self.settings.on_client_disconnected.as_ref().unwrap().topic,
            &req,
        )
        .await;
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_client_authenticate(
        &self,
        request: Request<ClientAuthenticateRequest>,
    ) -> Result<Response<ValuedResponse>, Status> {
        metric::send("hook.on_client_authenticate").await;
        let mut verified = false;
        if let Some(client_info) = request.into_inner().clientinfo {
            verified = self
                .auth
                .authenticate(&client_info.username, &client_info.password)
                .await;
        }
        Ok(Response::new(ValuedResponse {
            r#type: ResponsedType::StopAndReturn as i32,
            value: Some(Value::BoolResult(verified)),
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
        Ok(Response::new(ValuedResponse {
            r#type: ResponsedType::StopAndReturn as i32,
            value: Some(Value::BoolResult(passed)),
        }))
    }

    async fn on_client_subscribe(
        &self,
        request: Request<ClientSubscribeRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_client_subscribe").await;
        let req = request.into_inner();
        self.publish(
            &self.settings.on_client_subscribe.as_ref().unwrap().topic,
            &req,
        )
        .await;
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_client_unsubscribe(
        &self,
        request: Request<ClientUnsubscribeRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_client_unsubscribe").await;
        let req = request.into_inner();
        self.publish(
            &self.settings.on_client_unsubscribe.as_ref().unwrap().topic,
            &req,
        )
        .await;
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_session_created(
        &self,
        request: Request<SessionCreatedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_session_created").await;
        let req = request.into_inner();
        self.publish(
            &self.settings.on_client_created.as_ref().unwrap().topic,
            &req,
        )
        .await;
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_session_subscribed(
        &self,
        request: Request<SessionSubscribedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_session_subscribed").await;
        let req = request.into_inner();
        self.publish(
            &self.settings.on_session_subscribed.as_ref().unwrap().topic,
            &req,
        )
        .await;
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_session_unsubscribed(
        &self,
        request: Request<SessionUnsubscribedRequest>,
    ) -> Result<Response<EmptySuccess>, Status> {
        metric::send("hook.on_session_unsubscribed").await;
        let req = request.into_inner();
        self.publish(
            &self
                .settings
                .on_session_unsubscribed
                .as_ref()
                .unwrap()
                .topic,
            &req,
        )
        .await;
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
        self.publish(
            &self.settings.on_session_terminated.as_ref().unwrap().topic,
            &req,
        )
        .await;
        Ok(Response::new(EmptySuccess {}))
    }

    async fn on_message_publish(
        &self,
        request: Request<MessagePublishRequest>,
    ) -> Result<Response<ValuedResponse>, Status> {
        metric::send("hook.on_message_publish").await;
        let req = request.into_inner().clone();
        self.publish(
            &self.settings.on_message_publish.as_ref().unwrap().topic,
            &req,
        )
        .await;
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
        self.publish(
            &self.settings.on_message_delivered.as_ref().unwrap().topic,
            &req,
        )
        .await;
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
        self.publish(
            &self.settings.on_message_acked.as_ref().unwrap().topic,
            &req,
        )
        .await;
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
