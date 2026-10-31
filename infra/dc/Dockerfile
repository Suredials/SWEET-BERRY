FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends samba samba-ad-provision samba-dsdb-modules samba-vfs-modules winbind krb5-user smbclient ldap-utils dnsutils python3 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
COPY mutate.py /opt/sweetberry/mutate.py
COPY seed_company.py /opt/sweetberry/seed_company.py
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
