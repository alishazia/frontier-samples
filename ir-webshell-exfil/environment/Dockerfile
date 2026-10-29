FROM python:3.12-slim-bookworm
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends file jq less xxd \
 && rm -rf /var/lib/apt/lists/* && useradd -m -s /bin/bash agent
WORKDIR /app
COPY gen_evidence.py /opt/gen_evidence.py
RUN python3 /opt/gen_evidence.py /app/evidence && rm -f /opt/gen_evidence.py \
 && chown -R root:root /app/evidence && chmod -R a+rX,go-w /app/evidence \
 && chown agent:agent /app && mkdir -p /logs/agent /logs/verifier
