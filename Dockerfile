FROM rust:slim-buster as builder
RUN rustup component add rustfmt
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list \
  && sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list \
  && apt-get update && apt-get install -y build-essential cmake \
  && apt-get autoremove -y && apt-get autoclean -y && rm -rf /var/lib/apt/lists/*
RUN cargo 

WORKDIR ./neoiot_emqx_hook
COPY . .

RUN cargo install --path .

FROM debian:slim-buster

ENV TZ=Etc/UTC \
  APP_USER=appuser

COPY --from=builder /usr/local/cargo/bin/neoiot_emqx_hook /usr/local/bin/neoiot_emqx_hook
CMD ["./neoiot_emqx_hook"]
