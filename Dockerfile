FROM python:3.11-slim

LABEL org.opencontainers.image.title="Blockchain-Lite" \
      org.opencontainers.image.description="Educational from-scratch blockchain ledger and digital wallet (COEP). Not for real assets." \
      org.opencontainers.image.source="https://github.com/thecodex110/Blockchain" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

RUN useradd --create-home --shell /usr/sbin/nologin appuser

WORKDIR /app
COPY --chown=appuser:appuser . /app

USER appuser

# Verify the tree before shipping it (runs as the unprivileged user).
RUN python run_tests.py

# The web app. Inside a container the bridge must listen on all interfaces so a
# published port can reach it; publish it only to your own machine:
#   docker run --rm -p 127.0.0.1:8080:8080 <image>
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/state' % os.environ.get('PORT', '8080'), timeout=4)"

ENTRYPOINT ["python"]
# The port comes from $PORT when the host sets it (Render does), else 8080.
CMD ["-m", "web.bridge", "--host", "0.0.0.0"]
