# Stage 1: Build environment
FROM alpine:3.19 AS builder

ARG VERSION=dev

RUN apk add --no-cache \
    gcc musl-dev make pkgconfig \
    glib-dev glib-static \
    json-glib-dev \
    openssl-dev openssl-libs-static \
    linux-headers \
    zlib-static \
    libmicrohttpd-dev libmicrohttpd-static

WORKDIR /build
COPY . .

RUN make UI=1 VERSION=${VERSION}

# Stage 2: Minimal runtime
FROM alpine:3.19

RUN apk add --no-cache \
        json-glib \
        glib-networking \
        ca-certificates \
        openssl \
        libmicrohttpd && \
    adduser -D -s /sbin/nologin deadlight && \
    mkdir -p \
        /etc/deadlight \
        /var/log/deadlight \
        /var/cache/deadlight \
        /tmp/deadlight_certs \
        /tmp/deadlight_cache && \
    chown -R deadlight:deadlight \
        /etc/deadlight \
        /var/log/deadlight \
        /var/cache/deadlight \
        /tmp/deadlight_certs \
        /tmp/deadlight_cache && \
    openssl req -new -x509 -days 3650 -nodes \
        -subj "/C=US/ST=State/L=City/O=Deadlight/CN=Deadlight Root CA" \
        -keyout /etc/deadlight/ca.key \
        -out /etc/deadlight/ca.crt && \
    chmod 644 /etc/deadlight/ca.crt && \
    chmod 600 /etc/deadlight/ca.key && \
    chown deadlight:deadlight /etc/deadlight/ca.key /etc/deadlight/ca.crt

# Copy binary and config
COPY --from=builder /build/bin/deadlight /usr/local/bin/proxy
COPY --from=builder /build/deadlight.conf.docker /etc/deadlight/deadlight.conf
RUN chown deadlight:deadlight /etc/deadlight/deadlight.conf

COPY --from=builder /build/bin/plugins/ /usr/local/lib/deadlight/plugins/

USER deadlight

EXPOSE 8080 8081

ENTRYPOINT ["/usr/local/bin/proxy"]
CMD ["-v", "-c", "/etc/deadlight/deadlight.conf"]

# Export stage — used by CI release workflow only
FROM scratch AS export
COPY --from=builder /build/bin/deadlight /deadlight