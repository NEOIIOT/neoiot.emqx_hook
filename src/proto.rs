//------------------------------------------------------------------------------
// Request & Response
//------------------------------------------------------------------------------

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProviderLoadedRequest {
    #[prost(message, optional, tag = "1")]
    pub broker: ::core::option::Option<BrokerInfo>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LoadedResponse {
    #[prost(message, repeated, tag = "1")]
    pub hooks: ::prost::alloc::vec::Vec<HookSpec>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProviderUnloadedRequest {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientConnectRequest {
    #[prost(message, optional, tag = "1")]
    pub conninfo: ::core::option::Option<ConnInfo>,
    /// MQTT CONNECT packet's properties (MQTT v5.0)
    ///
    /// It should be empty on MQTT v3.1.1/v3.1 or others protocol
    #[prost(message, repeated, tag = "2")]
    pub props: ::prost::alloc::vec::Vec<Property>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientConnackRequest {
    #[prost(message, optional, tag = "1")]
    pub conninfo: ::core::option::Option<ConnInfo>,
    #[prost(string, tag = "2")]
    pub result_code: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "3")]
    pub props: ::prost::alloc::vec::Vec<Property>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientConnectedRequest {
    #[prost(message, optional, tag = "1")]
    pub clientinfo: ::core::option::Option<ClientInfo>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientDisconnectedRequest {
    #[prost(message, optional, tag = "1")]
    pub clientinfo: ::core::option::Option<ClientInfo>,
    #[prost(string, tag = "2")]
    pub reason: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientAuthenticateRequest {
    #[prost(message, optional, tag = "1")]
    pub clientinfo: ::core::option::Option<ClientInfo>,
    #[prost(bool, tag = "2")]
    pub result: bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientCheckAclRequest {
    #[prost(message, optional, tag = "1")]
    pub clientinfo: ::core::option::Option<ClientInfo>,
    #[prost(enumeration = "client_check_acl_request::AclReqType", tag = "2")]
    pub r#type: i32,
    #[prost(string, tag = "3")]
    pub topic: ::prost::alloc::string::String,
    #[prost(bool, tag = "4")]
    pub result: bool,
}
/// Nested message and enum types in `ClientCheckAclRequest`.
pub mod client_check_acl_request {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum AclReqType {
        Publish = 0,
        Subscribe = 1,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientSubscribeRequest {
    #[prost(message, optional, tag = "1")]
    pub clientinfo: ::core::option::Option<ClientInfo>,
    #[prost(message, repeated, tag = "2")]
    pub props: ::prost::alloc::vec::Vec<Property>,
    #[prost(message, repeated, tag = "3")]
    pub topic_filters: ::prost::alloc::vec::Vec<TopicFilter>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientUnsubscribeRequest {
    #[prost(message, optional, tag = "1")]
    pub clientinfo: ::core::option::Option<ClientInfo>,
    #[prost(message, repeated, tag = "2")]
    pub props: ::prost::alloc::vec::Vec<Property>,
    #[prost(message, repeated, tag = "3")]
    pub topic_filters: ::prost::alloc::vec::Vec<TopicFilter>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionCreatedRequest {
    #[prost(message, optional, tag = "1")]
    pub clientinfo: ::core::option::Option<ClientInfo>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionSubscribedRequest {
    #[prost(message, optional, tag = "1")]
    pub clientinfo: ::core::option::Option<ClientInfo>,
    #[prost(string, tag = "2")]
    pub topic: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "3")]
    pub subopts: ::core::option::Option<SubOpts>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionUnsubscribedRequest {
    #[prost(message, optional, tag = "1")]
    pub clientinfo: ::core::option::Option<ClientInfo>,
    #[prost(string, tag = "2")]
    pub topic: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionResumedRequest {
    #[prost(message, optional, tag = "1")]
    pub clientinfo: ::core::option::Option<ClientInfo>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionDiscardedRequest {
    #[prost(message, optional, tag = "1")]
    pub clientinfo: ::core::option::Option<ClientInfo>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionTakeoveredRequest {
    #[prost(message, optional, tag = "1")]
    pub clientinfo: ::core::option::Option<ClientInfo>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionTerminatedRequest {
    #[prost(message, optional, tag = "1")]
    pub clientinfo: ::core::option::Option<ClientInfo>,
    #[prost(string, tag = "2")]
    pub reason: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MessagePublishRequest {
    #[prost(message, optional, tag = "1")]
    pub message: ::core::option::Option<Message>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MessageDeliveredRequest {
    #[prost(message, optional, tag = "1")]
    pub clientinfo: ::core::option::Option<ClientInfo>,
    #[prost(message, optional, tag = "2")]
    pub message: ::core::option::Option<Message>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MessageDroppedRequest {
    #[prost(message, optional, tag = "1")]
    pub message: ::core::option::Option<Message>,
    #[prost(string, tag = "2")]
    pub reason: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MessageAckedRequest {
    #[prost(message, optional, tag = "1")]
    pub clientinfo: ::core::option::Option<ClientInfo>,
    #[prost(message, optional, tag = "2")]
    pub message: ::core::option::Option<Message>,
}
//------------------------------------------------------------------------------
// Basic data types
//------------------------------------------------------------------------------

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EmptySuccess {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ValuedResponse {
    #[prost(enumeration = "valued_response::ResponsedType", tag = "1")]
    pub r#type: i32,
    #[prost(oneof = "valued_response::Value", tags = "3, 4")]
    pub value: ::core::option::Option<valued_response::Value>,
}
/// Nested message and enum types in `ValuedResponse`.
pub mod valued_response {
    /// The responsed value type
    ///  - ignore: Ignore the responsed value
    ///  - contiune: Use the responsed value and execute the next hook
    ///  - stop_and_return: Use the responsed value and stop the chain executing
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum ResponsedType {
        Ignore = 0,
        Continue = 1,
        StopAndReturn = 2,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Value {
        /// Boolean result, used on the 'client.authenticate', 'client.check_acl' hooks
        #[prost(bool, tag = "3")]
        BoolResult(bool),
        /// Message result, used on the 'message.*' hooks
        #[prost(message, tag = "4")]
        Message(super::Message),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BrokerInfo {
    #[prost(string, tag = "1")]
    pub version: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub sysdescr: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub uptime: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub datetime: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HookSpec {
    /// The registered hooks name
    ///
    /// Available value:
    ///   "client.connect",      "client.connack"
    ///   "client.connected",    "client.disconnected"
    ///   "client.authenticate", "client.check_acl"
    ///   "client.subscribe",    "client.unsubscribe"
    ///
    ///   "session.created",      "session.subscribed"
    ///   "session.unsubscribed", "session.resumed"
    ///   "session.discarded",    "session.takeovered"
    ///   "session.terminated"
    ///
    ///   "message.publish", "message.delivered"
    ///   "message.acked",   "message.dropped"
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    /// The topic filters for message hooks
    #[prost(string, repeated, tag = "2")]
    pub topics: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConnInfo {
    #[prost(string, tag = "1")]
    pub node: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub clientid: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub username: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub peerhost: ::prost::alloc::string::String,
    #[prost(uint32, tag = "5")]
    pub sockport: u32,
    #[prost(string, tag = "6")]
    pub proto_name: ::prost::alloc::string::String,
    #[prost(string, tag = "7")]
    pub proto_ver: ::prost::alloc::string::String,
    #[prost(uint32, tag = "8")]
    pub keepalive: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientInfo {
    #[prost(string, tag = "1")]
    pub node: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub clientid: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub username: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub password: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub peerhost: ::prost::alloc::string::String,
    #[prost(uint32, tag = "6")]
    pub sockport: u32,
    #[prost(string, tag = "7")]
    pub protocol: ::prost::alloc::string::String,
    #[prost(string, tag = "8")]
    pub mountpoint: ::prost::alloc::string::String,
    #[prost(bool, tag = "9")]
    pub is_superuser: bool,
    #[prost(bool, tag = "10")]
    pub anonymous: bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Message {
    #[prost(string, tag = "1")]
    pub node: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub id: ::prost::alloc::string::String,
    #[prost(uint32, tag = "3")]
    pub qos: u32,
    #[prost(string, tag = "4")]
    pub from: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub topic: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "6")]
    pub payload: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "7")]
    pub timestamp: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Property {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub value: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TopicFilter {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(uint32, tag = "2")]
    pub qos: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubOpts {
    /// The QoS level
    #[prost(uint32, tag = "1")]
    pub qos: u32,
    /// The group name for shared subscription
    #[prost(string, tag = "2")]
    pub share: ::prost::alloc::string::String,
    /// The Retain Handling option (MQTT v5.0)
    ///
    ///  0 = Send retained messages at the time of the subscribe
    ///  1 = Send retained messages at subscribe only if the subscription does
    ///       not currently exist
    ///  2 = Do not send retained messages at the time of the subscribe
    #[prost(uint32, tag = "3")]
    pub rh: u32,
    /// The Retain as Published option (MQTT v5.0)
    ///
    ///  If 1, Application Messages forwarded using this subscription keep the
    ///        RETAIN flag they were published with.
    ///  If 0, Application Messages forwarded using this subscription have the
    ///        RETAIN flag set to 0.
    /// Retained messages sent when the subscription is established have the RETAIN flag set to 1.
    #[prost(uint32, tag = "4")]
    pub rap: u32,
    /// The No Local option (MQTT v5.0)
    ///
    /// If the value is 1, Application Messages MUST NOT be forwarded to a
    /// connection with a ClientID equal to the ClientID of the publishing
    #[prost(uint32, tag = "5")]
    pub nl: u32,
}
#[doc = r" Generated client implementations."]
pub mod hook_provider_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    pub struct HookProviderClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl HookProviderClient<tonic::transport::Channel> {
        #[doc = r" Attempt to create a new client by connecting to a given endpoint."]
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> HookProviderClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        pub async fn on_provider_loaded(
            &mut self,
            request: impl tonic::IntoRequest<super::ProviderLoadedRequest>,
        ) -> Result<tonic::Response<super::LoadedResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnProviderLoaded",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_provider_unloaded(
            &mut self,
            request: impl tonic::IntoRequest<super::ProviderUnloadedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnProviderUnloaded",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_client_connect(
            &mut self,
            request: impl tonic::IntoRequest<super::ClientConnectRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnClientConnect",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_client_connack(
            &mut self,
            request: impl tonic::IntoRequest<super::ClientConnackRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnClientConnack",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_client_connected(
            &mut self,
            request: impl tonic::IntoRequest<super::ClientConnectedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnClientConnected",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_client_disconnected(
            &mut self,
            request: impl tonic::IntoRequest<super::ClientDisconnectedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnClientDisconnected",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_client_authenticate(
            &mut self,
            request: impl tonic::IntoRequest<super::ClientAuthenticateRequest>,
        ) -> Result<tonic::Response<super::ValuedResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnClientAuthenticate",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_client_check_acl(
            &mut self,
            request: impl tonic::IntoRequest<super::ClientCheckAclRequest>,
        ) -> Result<tonic::Response<super::ValuedResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnClientCheckAcl",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_client_subscribe(
            &mut self,
            request: impl tonic::IntoRequest<super::ClientSubscribeRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnClientSubscribe",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_client_unsubscribe(
            &mut self,
            request: impl tonic::IntoRequest<super::ClientUnsubscribeRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnClientUnsubscribe",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_session_created(
            &mut self,
            request: impl tonic::IntoRequest<super::SessionCreatedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnSessionCreated",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_session_subscribed(
            &mut self,
            request: impl tonic::IntoRequest<super::SessionSubscribedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnSessionSubscribed",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_session_unsubscribed(
            &mut self,
            request: impl tonic::IntoRequest<super::SessionUnsubscribedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnSessionUnsubscribed",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_session_resumed(
            &mut self,
            request: impl tonic::IntoRequest<super::SessionResumedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnSessionResumed",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_session_discarded(
            &mut self,
            request: impl tonic::IntoRequest<super::SessionDiscardedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnSessionDiscarded",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_session_takeovered(
            &mut self,
            request: impl tonic::IntoRequest<super::SessionTakeoveredRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnSessionTakeovered",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_session_terminated(
            &mut self,
            request: impl tonic::IntoRequest<super::SessionTerminatedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnSessionTerminated",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_message_publish(
            &mut self,
            request: impl tonic::IntoRequest<super::MessagePublishRequest>,
        ) -> Result<tonic::Response<super::ValuedResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnMessagePublish",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_message_delivered(
            &mut self,
            request: impl tonic::IntoRequest<super::MessageDeliveredRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnMessageDelivered",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_message_dropped(
            &mut self,
            request: impl tonic::IntoRequest<super::MessageDroppedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/emqx.exhook.v1.HookProvider/OnMessageDropped",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn on_message_acked(
            &mut self,
            request: impl tonic::IntoRequest<super::MessageAckedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/emqx.exhook.v1.HookProvider/OnMessageAcked");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for HookProviderClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for HookProviderClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "HookProviderClient {{ ... }}")
        }
    }
}
#[doc = r" Generated server implementations."]
pub mod hook_provider_server {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    #[doc = "Generated trait containing gRPC methods that should be implemented for use with HookProviderServer."]
    #[async_trait]
    pub trait HookProvider: Send + Sync + 'static {
        async fn on_provider_loaded(
            &self,
            request: tonic::Request<super::ProviderLoadedRequest>,
        ) -> Result<tonic::Response<super::LoadedResponse>, tonic::Status>;
        async fn on_provider_unloaded(
            &self,
            request: tonic::Request<super::ProviderUnloadedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status>;
        async fn on_client_connect(
            &self,
            request: tonic::Request<super::ClientConnectRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status>;
        async fn on_client_connack(
            &self,
            request: tonic::Request<super::ClientConnackRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status>;
        async fn on_client_connected(
            &self,
            request: tonic::Request<super::ClientConnectedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status>;
        async fn on_client_disconnected(
            &self,
            request: tonic::Request<super::ClientDisconnectedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status>;
        async fn on_client_authenticate(
            &self,
            request: tonic::Request<super::ClientAuthenticateRequest>,
        ) -> Result<tonic::Response<super::ValuedResponse>, tonic::Status>;
        async fn on_client_check_acl(
            &self,
            request: tonic::Request<super::ClientCheckAclRequest>,
        ) -> Result<tonic::Response<super::ValuedResponse>, tonic::Status>;
        async fn on_client_subscribe(
            &self,
            request: tonic::Request<super::ClientSubscribeRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status>;
        async fn on_client_unsubscribe(
            &self,
            request: tonic::Request<super::ClientUnsubscribeRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status>;
        async fn on_session_created(
            &self,
            request: tonic::Request<super::SessionCreatedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status>;
        async fn on_session_subscribed(
            &self,
            request: tonic::Request<super::SessionSubscribedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status>;
        async fn on_session_unsubscribed(
            &self,
            request: tonic::Request<super::SessionUnsubscribedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status>;
        async fn on_session_resumed(
            &self,
            request: tonic::Request<super::SessionResumedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status>;
        async fn on_session_discarded(
            &self,
            request: tonic::Request<super::SessionDiscardedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status>;
        async fn on_session_takeovered(
            &self,
            request: tonic::Request<super::SessionTakeoveredRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status>;
        async fn on_session_terminated(
            &self,
            request: tonic::Request<super::SessionTerminatedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status>;
        async fn on_message_publish(
            &self,
            request: tonic::Request<super::MessagePublishRequest>,
        ) -> Result<tonic::Response<super::ValuedResponse>, tonic::Status>;
        async fn on_message_delivered(
            &self,
            request: tonic::Request<super::MessageDeliveredRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status>;
        async fn on_message_dropped(
            &self,
            request: tonic::Request<super::MessageDroppedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status>;
        async fn on_message_acked(
            &self,
            request: tonic::Request<super::MessageAckedRequest>,
        ) -> Result<tonic::Response<super::EmptySuccess>, tonic::Status>;
    }
    #[derive(Debug)]
    pub struct HookProviderServer<T: HookProvider> {
        inner: _Inner<T>,
    }
    struct _Inner<T>(Arc<T>, Option<tonic::Interceptor>);
    impl<T: HookProvider> HookProviderServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, None);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, Some(interceptor.into()));
            Self { inner }
        }
    }
    impl<T, B> Service<http::Request<B>> for HookProviderServer<T>
    where
        T: HookProvider,
        B: HttpBody + Send + Sync + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = Never;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/emqx.exhook.v1.HookProvider/OnProviderLoaded" => {
                    #[allow(non_camel_case_types)]
                    struct OnProviderLoadedSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider> tonic::server::UnaryService<super::ProviderLoadedRequest>
                        for OnProviderLoadedSvc<T>
                    {
                        type Response = super::LoadedResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ProviderLoadedRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_provider_loaded(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnProviderLoadedSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnProviderUnloaded" => {
                    #[allow(non_camel_case_types)]
                    struct OnProviderUnloadedSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider>
                        tonic::server::UnaryService<super::ProviderUnloadedRequest>
                        for OnProviderUnloadedSvc<T>
                    {
                        type Response = super::EmptySuccess;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ProviderUnloadedRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_provider_unloaded(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnProviderUnloadedSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnClientConnect" => {
                    #[allow(non_camel_case_types)]
                    struct OnClientConnectSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider> tonic::server::UnaryService<super::ClientConnectRequest>
                        for OnClientConnectSvc<T>
                    {
                        type Response = super::EmptySuccess;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ClientConnectRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_client_connect(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnClientConnectSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnClientConnack" => {
                    #[allow(non_camel_case_types)]
                    struct OnClientConnackSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider> tonic::server::UnaryService<super::ClientConnackRequest>
                        for OnClientConnackSvc<T>
                    {
                        type Response = super::EmptySuccess;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ClientConnackRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_client_connack(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnClientConnackSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnClientConnected" => {
                    #[allow(non_camel_case_types)]
                    struct OnClientConnectedSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider> tonic::server::UnaryService<super::ClientConnectedRequest>
                        for OnClientConnectedSvc<T>
                    {
                        type Response = super::EmptySuccess;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ClientConnectedRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_client_connected(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnClientConnectedSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnClientDisconnected" => {
                    #[allow(non_camel_case_types)]
                    struct OnClientDisconnectedSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider>
                        tonic::server::UnaryService<super::ClientDisconnectedRequest>
                        for OnClientDisconnectedSvc<T>
                    {
                        type Response = super::EmptySuccess;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ClientDisconnectedRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_client_disconnected(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnClientDisconnectedSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnClientAuthenticate" => {
                    #[allow(non_camel_case_types)]
                    struct OnClientAuthenticateSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider>
                        tonic::server::UnaryService<super::ClientAuthenticateRequest>
                        for OnClientAuthenticateSvc<T>
                    {
                        type Response = super::ValuedResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ClientAuthenticateRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_client_authenticate(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnClientAuthenticateSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnClientCheckAcl" => {
                    #[allow(non_camel_case_types)]
                    struct OnClientCheckAclSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider> tonic::server::UnaryService<super::ClientCheckAclRequest>
                        for OnClientCheckAclSvc<T>
                    {
                        type Response = super::ValuedResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ClientCheckAclRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_client_check_acl(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnClientCheckAclSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnClientSubscribe" => {
                    #[allow(non_camel_case_types)]
                    struct OnClientSubscribeSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider> tonic::server::UnaryService<super::ClientSubscribeRequest>
                        for OnClientSubscribeSvc<T>
                    {
                        type Response = super::EmptySuccess;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ClientSubscribeRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_client_subscribe(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnClientSubscribeSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnClientUnsubscribe" => {
                    #[allow(non_camel_case_types)]
                    struct OnClientUnsubscribeSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider>
                        tonic::server::UnaryService<super::ClientUnsubscribeRequest>
                        for OnClientUnsubscribeSvc<T>
                    {
                        type Response = super::EmptySuccess;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ClientUnsubscribeRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_client_unsubscribe(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnClientUnsubscribeSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnSessionCreated" => {
                    #[allow(non_camel_case_types)]
                    struct OnSessionCreatedSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider> tonic::server::UnaryService<super::SessionCreatedRequest>
                        for OnSessionCreatedSvc<T>
                    {
                        type Response = super::EmptySuccess;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SessionCreatedRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_session_created(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnSessionCreatedSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnSessionSubscribed" => {
                    #[allow(non_camel_case_types)]
                    struct OnSessionSubscribedSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider>
                        tonic::server::UnaryService<super::SessionSubscribedRequest>
                        for OnSessionSubscribedSvc<T>
                    {
                        type Response = super::EmptySuccess;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SessionSubscribedRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_session_subscribed(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnSessionSubscribedSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnSessionUnsubscribed" => {
                    #[allow(non_camel_case_types)]
                    struct OnSessionUnsubscribedSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider>
                        tonic::server::UnaryService<super::SessionUnsubscribedRequest>
                        for OnSessionUnsubscribedSvc<T>
                    {
                        type Response = super::EmptySuccess;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SessionUnsubscribedRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut =
                                async move { (*inner).on_session_unsubscribed(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnSessionUnsubscribedSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnSessionResumed" => {
                    #[allow(non_camel_case_types)]
                    struct OnSessionResumedSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider> tonic::server::UnaryService<super::SessionResumedRequest>
                        for OnSessionResumedSvc<T>
                    {
                        type Response = super::EmptySuccess;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SessionResumedRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_session_resumed(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnSessionResumedSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnSessionDiscarded" => {
                    #[allow(non_camel_case_types)]
                    struct OnSessionDiscardedSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider>
                        tonic::server::UnaryService<super::SessionDiscardedRequest>
                        for OnSessionDiscardedSvc<T>
                    {
                        type Response = super::EmptySuccess;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SessionDiscardedRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_session_discarded(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnSessionDiscardedSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnSessionTakeovered" => {
                    #[allow(non_camel_case_types)]
                    struct OnSessionTakeoveredSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider>
                        tonic::server::UnaryService<super::SessionTakeoveredRequest>
                        for OnSessionTakeoveredSvc<T>
                    {
                        type Response = super::EmptySuccess;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SessionTakeoveredRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_session_takeovered(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnSessionTakeoveredSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnSessionTerminated" => {
                    #[allow(non_camel_case_types)]
                    struct OnSessionTerminatedSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider>
                        tonic::server::UnaryService<super::SessionTerminatedRequest>
                        for OnSessionTerminatedSvc<T>
                    {
                        type Response = super::EmptySuccess;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SessionTerminatedRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_session_terminated(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnSessionTerminatedSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnMessagePublish" => {
                    #[allow(non_camel_case_types)]
                    struct OnMessagePublishSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider> tonic::server::UnaryService<super::MessagePublishRequest>
                        for OnMessagePublishSvc<T>
                    {
                        type Response = super::ValuedResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::MessagePublishRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_message_publish(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnMessagePublishSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnMessageDelivered" => {
                    #[allow(non_camel_case_types)]
                    struct OnMessageDeliveredSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider>
                        tonic::server::UnaryService<super::MessageDeliveredRequest>
                        for OnMessageDeliveredSvc<T>
                    {
                        type Response = super::EmptySuccess;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::MessageDeliveredRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_message_delivered(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnMessageDeliveredSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnMessageDropped" => {
                    #[allow(non_camel_case_types)]
                    struct OnMessageDroppedSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider> tonic::server::UnaryService<super::MessageDroppedRequest>
                        for OnMessageDroppedSvc<T>
                    {
                        type Response = super::EmptySuccess;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::MessageDroppedRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_message_dropped(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnMessageDroppedSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/emqx.exhook.v1.HookProvider/OnMessageAcked" => {
                    #[allow(non_camel_case_types)]
                    struct OnMessageAckedSvc<T: HookProvider>(pub Arc<T>);
                    impl<T: HookProvider> tonic::server::UnaryService<super::MessageAckedRequest>
                        for OnMessageAckedSvc<T>
                    {
                        type Response = super::EmptySuccess;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::MessageAckedRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).on_message_acked(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = OnMessageAckedSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(200)
                        .header("grpc-status", "12")
                        .header("content-type", "application/grpc")
                        .body(tonic::body::BoxBody::empty())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: HookProvider> Clone for HookProviderServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self { inner }
        }
    }
    impl<T: HookProvider> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone(), self.1.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: HookProvider> tonic::transport::NamedService for HookProviderServer<T> {
        const NAME: &'static str = "emqx.exhook.v1.HookProvider";
    }
}
