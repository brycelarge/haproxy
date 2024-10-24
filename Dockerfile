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
    HAPROXY_MINOR=3.1-dev10 \
    HAPROXY_SHA256=185b85db5092bc6dfbc4ab2e221c867caef5479bb623cc25f9d3c865b8d0be3f \
    HAPROXY_SRC_URL=http://www.haproxy.org/download \
    HAPROXY_MAKE_OPTS=' \
    TARGET=linux-musl \
    USE_GETADDRINFO=1 \
    USE_OPENSSL=1 \
    USE_SLZ=1 \
    USE_PCRE2=1 USE_PCRE2_JIT=1 \
    LDFLAGS="-L/opt/quictls/lib -Wl,-rpath,/opt/quictls/lib" \
    SSL_INC=/opt/quictls/include SSL_LIB=/opt/quictls/lib USE_QUIC=1 \
    USE_LUA=1 LUA_INC=/usr/include/lua5.4 LUA_LIB=/usr/lib/lua5.4 \
    USE_PROMEX=1 \
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
    echo "**** Make haproxy directories ****" && \
    mkdir -p \
        /etc/haproxy \
        /etc/haproxy/errors \
        /etc/haproxy/certs \
    echo "**** Install Haproxy ****" && \
    curl -sfSL "${HAPROXY_SRC_URL}/${HAPROXY_BRANCH}/src/devel/haproxy-${HAPROXY_MINOR}.tar.gz" -o haproxy.tar.gz && \
    echo "$HAPROXY_SHA256 *haproxy.tar.gz" | sha256sum -c - && \
    mkdir -p /usr/src/haproxy && \
    tar -xzf haproxy.tar.gz -C /usr/src/haproxy --strip-components=1 && \
    rm haproxy.tar.gz && \
    cp -R /usr/src/haproxy/examples/errorfiles /etc/haproxy/errors && \
    echo "**** Cleanup ****" && \
    rm -rf \
      /tmp/*

RUN echo "**** Compiling Haproxy from source ****" && \
    set -eux && \
	nproc="$(getconf _NPROCESSORS_ONLN)" && \
	eval "make -C /usr/src/haproxy -j '$nproc' all $HAPROXY_MAKE_OPTS" && \
	eval "make -C /usr/src/haproxy install-bin $HAPROXY_MAKE_OPTS" && \
    echo "**** Setting up Haproxy folders and cleaning up ****" && \
    make -C /usr/src/haproxy TARGET=linux2628 install-bin install-man

# start from fresh to remove all build layers and packages
FROM brycelarge/alpine-baseimage:latest
COPY --from=haproxy-builder /usr/local/sbin/haproxy /usr/local/sbin/haproxy
COPY --from=haproxy-builder /etc/haproxy /etc/haproxy
COPY --from=haproxy-builder /opt/quictls /opt/quictls

# Copy the custom scripts
COPY ./conf.d/logrotate.d/haproxy /etc/logrotate.d/haproxy
# Replace the file at 49-haproxy.conf that's pre-existing
COPY ./conf.d/rsyslog.d/haproxy.conf /etc/rsyslog.d/49-haproxy.conf
COPY ./conf.d/rsyslog.conf /etc/rsyslog.conf

# Add in some performance tuning for high-volume network connections
# For a great primer @see https://levelup.gitconnected.com/linux-kernel-tuning-for-high-performance-networking-high-volume-incoming-connections-196e863d458a
COPY ./conf.d/network.conf /etc/sysctl.d/network.conf

# Copy the healthcheck script
COPY ./scripts/healthcheck.sh /usr/local/bin/healthcheck.sh

# make haproxy's directories
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
    mkdir -p /var/spool/rsyslog \
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
        /etc/haproxy/errors \
        /var/lib/haproxy/dev/ && \
    chmod 770 /usr/local/bin/healthcheck.sh && \
    chown haproxy:haproxy /var/lib/haproxy && \
    chown haproxy:haproxy /var/run/haproxy && \
    chown haproxy:haproxy /etc/haproxy && \
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

ENV CONFIG_AUTO_GENERATE=false \
    ACME_EMAIL=\
    HA_DEBUG=false

COPY root/ /
COPY scripts/ /scripts/

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