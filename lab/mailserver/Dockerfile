FROM debian@sha256:1a8a211e4f451f165e8a60dbb6be669d0d3839213bc8939c381c850a12e3e2c6

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    postfix \
    dovecot-core \
    dovecot-imapd \
    dovecot-pop3d \
    sasl2-bin \
    libsasl2-modules \
    openssl \
    ca-certificates \
    net-tools \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 25 465 587 110 995 143 993

ENTRYPOINT ["/entrypoint.sh"]
