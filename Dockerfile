FROM python:3.12-slim-bookworm
WORKDIR /opt/sweetberry
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SWEETBERRY_LIVE=false
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home --uid 10001 sweetberry
COPY --chown=sweetberry:sweetberry app/ app/
COPY --chown=sweetberry:sweetberry dashboard/ dashboard/
COPY --chown=sweetberry:sweetberry scripts/configure.py scripts/configure.py
COPY --chown=sweetberry:sweetberry scenarios/ scenarios/
COPY --chown=sweetberry:sweetberry ops/docker-demo.sh ops/docker-demo.sh
RUN chown sweetberry:sweetberry /opt/sweetberry
USER sweetberry
EXPOSE 8501
CMD ["sh", "ops/docker-demo.sh"]
