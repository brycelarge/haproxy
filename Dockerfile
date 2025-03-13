FROM alpine:3.20 AS openssl-builder

ENV OPENSSL_URL=https://github.com/quictls/openssl/archive/refs/tags/openssl-3.1.7-quic1.tar.gz

RUN apk add --no-cache curl build-base make autoconf automake gcc libc-dev linux-headers && \
    curl -sfSL "${OPENSSL_URL}" -o openssl.tar.gz && \
    mkdir -p /tmp/openssl && \
    tar -xzf openssl.tar.gz -C /tmp/openssl --strip-components=1 && \
    rm -f openssl.tar.gz && \
    cd /tmp/openssl && \
    ./config --libdir=lib --prefix=/opt/quictls && \
    make -j $(nproc) && \
    make install && \
    rm -rf /tmp/openssl

RUN \
    mkdir -p /opt/quictls/ssl && \
    rm -rf /opt/quictls/ssl/certs && \
    ln -s /etc/ssl/certs /opt/quictls/ssl/certs

FROM alpine:3.20 AS haproxy-builder
COPY --from=openssl-builder /opt/quictls /opt/quictls

# haproxy build environment variables
ENV HAPROXY_BRANCH=3.1 \
    HAPROXY_MINOR=3.1.0 \
    HAPROXY_SHA256=56409bea917ae89fab663cdff5d0935b455611d59227a217c237b67050a12cea \
    HAPROXY_SRC_URL=https://github.com/haproxy/haproxy/archive/refs/tags \
    HAPROXY_MAKE_OPTS=' \
    TARGET=linux-musl \
    # Core functionality
    USE_GETADDRINFO=1 \
    USE_ACCEPT4=1 \
    USE_LINUX_TPROXY=1 \
    USE_THREAD=1 \
    USE_CPU_AFFINITY=1 \
    # SSL/TLS & QUIC
    USE_OPENSSL=1 \
    USE_QUIC=1 \
    SSL_INC=/opt/quictls/include \
    SSL_LIB=/opt/quictls/lib \
    # Performance
    USE_NS=1 \
    USE_TFO=1 \
    USE_LINUX_SPLICE=1 \
    USE_NETFILTER=1 \
    # Other haproxy options
    USE_SLZ=1 \
    USE_PCRE2=1 \
    USE_PCRE2_JIT=1 \
    USE_LUA=1 \
    LUA_INC=/usr/include/lua5.4 \
    LUA_LIB=/usr/lib/lua5.4 \
    USE_PROMEX=1 \
    LDFLAGS="-L/opt/quictls/lib -Wl,-rpath,/opt/quictls/lib -L/usr/lib" \
    EXTRA_OBJS='

RUN \
    echo "**** Install haproxy build packages ****" && \
    apk add --no-cache \
        build-base \
        libc-dev \
        linux-headers \
        lua5.4-dev \
        openssl \
        openssl-dev \
        pcre2-dev \
        curl \
        zlib-dev && \
    echo "**** Install Haproxy ****" && \
    curl -sfL "${HAPROXY_SRC_URL}/v${HAPROXY_MINOR}.tar.gz" -o haproxy.tar.gz && \
    echo "$HAPROXY_SHA256 *haproxy.tar.gz" | sha256sum -c - && \
    mkdir -p /usr/src && \
    tar -xzf haproxy.tar.gz -C /usr/src && \
    mv /usr/src/haproxy-* /usr/src/haproxy && \
    rm haproxy.tar.gz && \
    echo "**** Cleanup ****" && \
    rm -rf /tmp/*

RUN \
    echo "**** Compiling Haproxy from source ****" && \
    cd /usr/src/haproxy && \
    set -eux && \
    nproc="$(getconf _NPROCESSORS_ONLN)" && \
    PKG_CONFIG_PATH=/usr/lib/pkgconfig && \
    LD_LIBRARY_PATH="/usr/lib" && \
    eval "make -C /usr/src/haproxy -j '$nproc' all $HAPROXY_MAKE_OPTS" && \
    eval "make -C /usr/src/haproxy install-bin $HAPROXY_MAKE_OPTS" && \
    make -C /usr/src/haproxy TARGET=linux2628 install-bin install-man

# start from fresh to remove all build layers and packages
FROM brycelarge/alpine-baseimage:latest
COPY --from=haproxy-builder /usr/local/sbin/haproxy /usr/local/sbin/haproxy
COPY --from=haproxy-builder /opt/quictls /opt/quictls

# Create HAProxy directories and copy error pages in final stage
RUN mkdir -p /etc/haproxy/errors /etc/haproxy/certs
COPY errors/ /etc/haproxy/errors/

# Copy the custom scripts
COPY ./conf.d/logrotate.d/haproxy /etc/logrotate.d/haproxy
COPY ./conf.d/rsyslog.d/haproxy.conf /etc/rsyslog.d/49-haproxy.conf
COPY ./conf.d/rsyslog.conf /etc/rsyslog.conf
COPY ./conf.d/network.conf /etc/sysctl.d/network.conf
COPY ./scripts/healthcheck.sh /usr/local/bin/healthcheck.sh
COPY scripts/ /scripts/

RUN \
    echo "**** Install runtime packages ****" && \
    apk add --no-cache \
        lua5.4 \
        openssl \
        pcre2 \
        readline \
        libcrypto3 \
        libssl3 \
        rsyslog \
        inotify-tools \
        socat \
        libcap \
        tzdata && \
    echo "**** Make rsyslog diretory ****" && \
    mkdir -p \
        /var/spool/rsyslog \
        /scripts && \
    echo "**** Create Haproxy user and make our folders ****" && \
    set -eux && \
    addgroup --gid 99 --system haproxy && \
    adduser \
        --disabled-password \
        --home /var/lib/haproxy \
        --ingroup haproxy \
        --no-create-home \
        --system \
        --uid 99 \
        haproxy && \
    mkdir -p \
        /var/lib/haproxy \
        /var/run/haproxy \
        /var/lib/haproxy/dev && \
    chmod 770 /usr/local/bin/healthcheck.sh && \
    chown haproxy:haproxy /var/lib/haproxy && \
    chown haproxy:haproxy /var/run/haproxy && \
    chown haproxy:haproxy /etc/haproxy && \
    chmod 775 /var/lib/haproxy && \
    chmod 775 /var/run/haproxy && \
    chmod 775 /scripts && \
    chmod +x /scripts/*.sh && \
    chown -R haproxy:haproxy /scripts && \
    chmod 755 /var/lib/haproxy/dev && \
    chown haproxy:haproxy /var/lib/haproxy/dev && \
    touch /var/lib/haproxy/dev/log && \
    chown haproxy:haproxy /var/lib/haproxy/dev/log && \
    chmod 755 /var/lib/haproxy/dev/log && \
    setcap 'cap_net_bind_service=+ep' /usr/local/sbin/haproxy && \
    echo "**** add acme user and add to haproxy group for serving certificates ****" && \
    addgroup -g 1000 -S acme && \
    adduser \
        --disabled-password \
        --home /config/acme \
        --ingroup acme \
        --no-create-home \
        --system \
        --uid 1000 \
        acme && \
    adduser acme haproxy && \
    echo "**** Add the tzdata package and configure for EST timezone ****" && \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

ENV CONFIG_DIR=/config \
    CONFIG_AUTO_GENERATE=false \
    DEV_MODE=false \
    DEBUG=false

COPY root/ /
COPY scripts/ /scripts/

RUN chmod +x /scripts/*.sh && \
    chown -R haproxy:haproxy /scripts && \
    chmod 775 /scripts

VOLUME ["/config"]
EXPOSE 80 443 8404

# https://github.com/docker-library/haproxy/issues/200
WORKDIR /var/lib/haproxy

# ports and volumes
EXPOSE 80/tcp 443/tcp 443/udp
VOLUME /config
VOLUME /var/log/haproxy
VOLUME /etc/haproxy/certs

# https://www.haproxy.org/download/1.8/doc/management.txt
# "4. Stopping and restarting HAProxy"
# "when the SIGTERM signal is sent to the haproxy process, it immediately quits and all established connections are closed"
# "graceful stop is triggered when the SIGUSR1 signal is sent to the haproxy process"
STOPSIGNAL SIGUSR1

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD /usr/local/bin/healthcheck.sh