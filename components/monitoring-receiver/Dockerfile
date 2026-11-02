FROM python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2
ARG VCS_REF
ARG SOURCE_URL
ARG VERSION
LABEL org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.source=$SOURCE_URL \
      org.opencontainers.image.version=$VERSION
RUN pip install --no-cache-dir fastapi==0.141.1 starlette==1.6.0 uvicorn==0.52.4
# Preserve the immutable Python/Bookworm base; apply only signed Debian security fixes.
RUN apt-get update \
    && apt-get install --no-install-recommends --only-upgrade -y \
       libpcre2-8-0=10.42-1+deb12u2 \
       libssl3=3.0.22-1~deb12u2 \
       perl-base=5.36.0-7+deb12u4 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY app.py /app/app.py
USER 65532:65532
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8080","--no-access-log"]
