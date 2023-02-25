FROM scratch

COPY external-dns-provider-adguard /

ENTRYPOINT [ "/external-dns-provider-adguard" ]
