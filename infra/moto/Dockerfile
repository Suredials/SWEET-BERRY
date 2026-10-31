FROM python:3.12-slim-bookworm
RUN pip install --no-cache-dir 'moto[server]==5.2.5' boto3 && useradd -m -u 10001 cloud && mkdir -p /srv/data && chown cloud:cloud /srv/data
COPY seed.py /opt/cloud/seed.py
USER cloud
CMD ["moto_server", "-H", "0.0.0.0", "-p", "5000"]
