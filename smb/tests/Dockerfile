FROM ghcr.io/servercontainers/samba:smbd-only-latest

ENV NETBIOS_DISABLE=1
ENV AVAHI_DISABLE=1
ENV WSDD2_DISABLE=1

RUN mkdir -p /shares/public /shares/MyShare /shares/private && \
    chmod -R 777 /shares
