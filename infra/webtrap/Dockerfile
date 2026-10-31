FROM php:8.3-cli-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends curl git procps iproute2 python3 ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 support && mkdir -p /srv/app/uploads /srv/corp && chown -R support:support /srv/app/uploads
COPY index.php upload.php /srv/app/
COPY trace.php /opt/trace.php
COPY operations.txt /srv/corp/operations.txt
COPY start.sh /opt/start.sh
USER support
WORKDIR /srv/app
CMD ["sh", "/opt/start.sh"]
