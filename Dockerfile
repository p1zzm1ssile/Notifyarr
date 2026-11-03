FROM python:3.13-alpine
# Pure standard-library Python: no pip packages. tzdata for TZ=..., the rest is optional tooling.
RUN apk add --no-cache tzdata
WORKDIR /app
COPY app/ /app/
COPY config/config.toml config/trusted_ips.txt /app/defaults/
ENV CONFIG_FILE=/config/config.toml
VOLUME /config
EXPOSE 8484
LABEL org.opencontainers.image.source="https://github.com/p1zzm1ssile/Notifyarr" \
      org.opencontainers.image.description="Alerts for Docker containers and Unraid via Telegram and email" \
      org.opencontainers.image.licenses="MIT" \
      notifyarr.enable="false"
CMD ["python", "-u", "/app/watcher.py"]
