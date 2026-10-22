FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONPATH=/app/src
ENV PATH=/opt/venv/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip adb openjdk-17-jre-headless \
    curl ca-certificates unzip xz-utils procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY backend ./backend
COPY .agents ./.agents

RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install -q -U pip \
    && /opt/venv/bin/pip install -q -e . \
    && /opt/venv/bin/pip install -q "frida==17.8.2" frida-tools

ARG JADX_URL=https://github.com/skylot/jadx/releases/download/v1.5.5/jadx-1.5.5.zip
ARG FRIDA_SERVER_URL=https://github.com/frida/frida/releases/download/17.8.2/frida-server-17.8.2-android-x86_64.xz

RUN mkdir -p /opt/apk-tools/jadx \
    && curl -fsSL "$JADX_URL" -o /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/apk-tools/jadx \
    && curl -fsSL "$FRIDA_SERVER_URL" -o /tmp/frida-server.xz \
    && xz -d -c /tmp/frida-server.xz > /opt/apk-tools/frida-server \
    && chmod +x /opt/apk-tools/frida-server

ENV APU_JADX_JAR=/opt/apk-tools/jadx/lib/jadx-gui-1.5.5-all.jar
ENV APU_FRIDA_SERVER=/opt/apk-tools/frida-server
ENV APU_JAVA=/usr/bin/java
ENV APU_WEB_DATA_DIR=/data

EXPOSE 8080
CMD ["/opt/venv/bin/python", "-m", "backend", "serve"]
