FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home decoy && mkdir -p /srv/data /var/log/lure \
    && chown -R decoy:decoy /srv/data /var/log/lure
COPY server.py mutate.py /opt/lures/
USER 10001:10001
WORKDIR /srv/data
CMD ["python3", "/opt/lures/server.py"]
