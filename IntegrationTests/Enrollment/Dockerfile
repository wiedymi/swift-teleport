ARG DEBIAN_IMAGE
FROM ${DEBIAN_IMAGE}
ARG DEBIAN_SNAPSHOT
RUN rm -f /etc/apt/sources.list.d/debian.sources && \
    printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s/ bookworm main\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s/ bookworm-security main\n' "$DEBIAN_SNAPSHOT" "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list && \
    apt-get update -qq && \
    apt-get install -y --no-install-recommends ca-certificates chromium libnss3-tools nodejs npm zbar-tools && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /opt/enrollment
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force
COPY enroll.mjs ./
ENV HOME=/tmp/browser
ENTRYPOINT ["node", "/opt/enrollment/enroll.mjs"]
