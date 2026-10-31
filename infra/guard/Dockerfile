FROM python:3.12-slim-bookworm
RUN pip install --no-cache-dir llm-guard==0.3.16 torch==2.6.0 fastapi uvicorn \
    && useradd -m -u 10001 guard && mkdir -p /home/guard/.cache && chown -R guard:guard /home/guard
COPY server.py /opt/guard/server.py
USER guard
WORKDIR /opt/guard
ENV OMP_NUM_THREADS=2 TOKENIZERS_PARALLELISM=false
CMD ["python", "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
