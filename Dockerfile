FROM ekidd/rust-musl-builder:stable as builder

RUN USER=root cargo new --bin neoiot_emqx_hook

ENV GRPC_HEALTH_PROBE_VERSION=v0.4.1
ADD https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64 /grpc_health_probe

WORKDIR ./neoiot_emqx_hook
COPY ./Cargo.toml ./Cargo.toml
RUN cargo build --release
RUN rm src/*.rs

ADD . ./

RUN rm ./target/x86_64-unknown-linux-musl/release/deps/neoiot_emqx_hook*
RUN cargo build --release

FROM alpine:latest

ARG APP=/usr/src/app

EXPOSE 10000

ENV TZ=Etc/UTC \
  APP_USER=appuser

RUN addgroup -S $APP_USER \
  && adduser -S -g $APP_USER $APP_USER

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
RUN apk update \
  && apk add --no-cache ca-certificates tzdata \
  && rm -rf /var/cache/apk/*

COPY --from=builder /grpc_health_probe /bin/grpc_health_probe
RUN chmod +x /bin/grpc_health_probe
COPY --from=builder /home/rust/src/neoiot_emqx_hook/target/x86_64-unknown-linux-musl/release/neoiot_emqx_hook ${APP}/neoiot_emqx_hook
RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

CMD ["./neoiot_emqx_hook"]
