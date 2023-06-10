FROM alpine:3 as certs

RUN apk add --no-cache ca-certificates

FROM scratch

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY external-dns-provider-adguard /

ENTRYPOINT [ "/external-dns-provider-adguard" ]
