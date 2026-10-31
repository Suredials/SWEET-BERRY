FROM python:3.12-slim-bookworm
RUN pip install --no-cache-dir requests && useradd -m -u 10001 edge && mkdir -p /var/log/lure/quarantine && chown -R edge:edge /var/log/lure
COPY server.py /opt/edge/server.py
USER edge
CMD ["python", "/opt/edge/server.py"]
