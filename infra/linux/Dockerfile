FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server procps iproute2 curl python3 ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash analyst && echo 'analyst:SWEETBERRY_CANARY_DECOY_LabOnly!' | chpasswd \
    && mkdir -p /run/sshd /srv/corp && chown analyst:analyst /srv/corp \
    && printf 'PasswordAuthentication yes\nPermitRootLogin no\nAllowUsers analyst\nAllowTcpForwarding no\nPermitTunnel no\nX11Forwarding no\n' > /etc/ssh/sshd_config.d/sweetberry.conf
COPY entrypoint.sh /entrypoint.sh
COPY integrity.py /opt/sweetberry/integrity.py
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
