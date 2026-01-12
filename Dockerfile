FROM alpine:3.21 AS openssl-builder

ENV OPENSSL_URL=https://github.com/quictls/openssl/archive/refs/tags/openssl-3.3.0-quic1.tar.gz
ENV OPENSSL_SHA1SUM="1a2d16f2d6bad19ba0f62f3cde5efb1bd982c07e"

# OpenSSL build configuration
# Features
ARG OPENSSL_OPTS_FEATURES="no-tests enable-tls1_3"
# Compiler / hardening flags
ARG OPENSSL_OPTS_CFLAGS="-g -O3 -fstack-protector-strong -Wformat -Werror=format-security"
# Preprocessor / build defines
# -DOPENSSL_TLS_SECURITY_LEVEL=2: default min security policy (e.g. rejects weak keys/ciphers)
# -DOPENSSL_USE_NODELETE: keep libcrypto/libssl loaded to avoid unload/reload issues (plugins/forked procs)
# -DL_ENDIAN: explicitly assume little-endian target
# -DOPENSSL_PIC: build position-independent code (shared libs)
# -DOPENSSL_CPUID_OBJ: enable runtime CPU feature detection
# ASM toggles: force-enable common fast paths (AESNI, SHA*, GHASH, X25519/X448, etc.)
# -DNDEBUG: disable asserts
# -D_FORTIFY_SOURCE=2: extra libc bounds checking (effective with optimizations)
ARG OPENSSL_OPTS_DEFINES="-DOPENSSL_TLS_SECURITY_LEVEL=2 -DOPENSSL_USE_NODELETE -DL_ENDIAN \
    -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 \
    -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m \
    -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DKECCAK1600_ASM -DMD5_ASM \
    -DAESNI_ASM -DVPAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DX25519_ASM \
    -DX448_ASM -DPOLY1305_ASM -DNDEBUG -Wdate-time -D_FORTIFY_SOURCE=2"

RUN apk add --no-cache curl build-base make autoconf automake gcc libc-dev linux-headers && \
    mkdir -p /tmp/openssl && \
    curl -sfSL "${OPENSSL_URL}" -o openssl.tar.gz && \
    echo "${OPENSSL_SHA1SUM}  openssl.tar.gz" | sha1sum -c - && \
    tar -xzf openssl.tar.gz -C /tmp/openssl --strip-components=1 && \
    rm -f openssl.tar.gz && \
    cd /tmp/openssl && \
    ./config --libdir=lib --prefix=/opt/quictls ${OPENSSL_OPTS_FEATURES} ${OPENSSL_OPTS_CFLAGS} ${OPENSSL_OPTS_DEFINES} && \
    nproc="$(command -v getconf >/dev/null 2>&1 && getconf _NPROCESSORS_ONLN || grep -c ^processor /proc/cpuinfo || echo 1)" && \
    make -j "$nproc" build_sw && \
    make install_sw && \
    rm -rf /tmp/openssl && \
    OPENSSL_MODULES=/opt/quictls/lib/ossl-modules \
    LD_LIBRARY_PATH=/opt/quictls/lib \
    /opt/quictls/bin/openssl version -a

RUN \
    mkdir -p /opt/quictls/ssl && \
    rm -rf /opt/quictls/ssl/certs && \
    ln -s /etc/ssl/certs /opt/quictls/ssl/certs

FROM alpine:3.21 AS haproxy-builder
COPY --from=openssl-builder /opt/quictls /opt/quictls

# haproxy build environment variables
ARG HAPROXY_BRANCH=3.3
ARG HAPROXY_MINOR=3.3.0
ARG HAPROXY_SHA256=922a7ec28772ccb88d4f70b4139299cf2375ed9806789356ecf06e0c953ed0e4

# Set ENV variables from ARGs for use in RUN commands
ENV HAPROXY_BRANCH=3.3
ENV HAPROXY_MINOR=3.3.0
ENV HAPROXY_SHA256=922a7ec28772ccb88d4f70b4139299cf2375ed9806789356ecf06e0c953ed0e4
ENV HAPROXY_SRC_URL=https://github.com/haproxy/haproxy/archive/refs/tags

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
    nproc="$(command -v getconf >/dev/null 2>&1 && getconf _NPROCESSORS_ONLN || grep -c ^processor /proc/cpuinfo || echo 1)" && \
    PKG_CONFIG_PATH=/opt/quictls/lib/pkgconfig:/usr/lib/pkgconfig && \
    LD_LIBRARY_PATH="/usr/lib" && \
    # Core functionality
    # USE_GETADDRINFO=1 \
    # USE_THREAD=1 \
    # SSL/TLS & QUIC
    # Performance
    # USE_TFO=1 \
    # USE_EPOOL=1 \
    # Lua
    # Network namespace
    # USE_NS=1 \
    # Prometheus
    # Regex
    # Compression
    # USE_ZLIB=1 \
    # Link flags
    HAPROXY_MAKE_ARGS='\
        TARGET=linux-musl \
        USE_OPENSSL=1 \
        USE_LIBCRYPT=1 \
        USE_QUIC=1 \
        SSL_INC=/opt/quictls/include \
        SSL_LIB=/opt/quictls/lib \
        USE_LUA=1 \
        LUA_INC=/usr/include/lua5.4 \
        LUA_LIB=/usr/lib/lua5.4 \
        USE_PROMEX=1 \
        USE_PCRE2=1 \
        USE_PCRE2_JIT=1 \
        LDFLAGS="-L/opt/quictls/lib -Wl,-rpath,/opt/quictls/lib -L/usr/lib" \
        EXTRA_OBJS=\
    ' && \
    eval "make -C /usr/src/haproxy -j $nproc all $HAPROXY_MAKE_ARGS" && \
    eval "make -C /usr/src/haproxy install-bin $HAPROXY_MAKE_ARGS" && \
    make -C /usr/src/haproxy TARGET=linux2628 install-bin install-man

# start from fresh to remove all build layers and packages
FROM brycelarge/alpine-baseimage:3.21

ARG HAPROXY_MINOR=3.3.0

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

# Set timezone environment variable
ENV TZ=EST

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
        iptables \
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
    CONFIG_AUTO_GENERATE=true \
    FRONTEND_IP_PROTECTION=false \
    DEV_MODE=false \
    DEBUG=false

COPY root/ /
COPY scripts/ /scripts/

RUN chmod +x /scripts/*.sh && \
    chown -R haproxy:haproxy /scripts && \
    chmod 775 /scripts

LABEL maintainer="Bryce Large" \
      org.opencontainers.image.title="HAProxy with ACME" \
      org.opencontainers.image.description="HAProxy with Lua ACME HTTP-01 challenge support" \
      org.opencontainers.image.version="${HAPROXY_MINOR}" \
      org.opencontainers.image.source="https://github.com/brycelarge/haproxy"

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