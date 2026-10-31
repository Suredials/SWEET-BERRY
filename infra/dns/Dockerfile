FROM python:3.12-slim-bookworm
RUN useradd -m -u 10001 dnslog
COPY server.py /opt/dns/server.py
USER dnslog
CMD ["python", "-u", "/opt/dns/server.py"]
