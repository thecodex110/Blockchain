# ==============================================================================
# Blockchain-Lite Ledger & Digital Wallet - container image (TERMINAL ONLY)
#
# Zero third-party dependencies: the build needs no network beyond pulling the
# base image. The full test-suite runs during the build, so a broken tree never
# produces an image.
# ==============================================================================

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

RUN useradd --create-home --shell /usr/sbin/nologin appuser

WORKDIR /app
COPY --chown=appuser:appuser . /app

USER appuser

# Verify the tree before shipping it (runs as the unprivileged user).
RUN python run_tests.py

ENTRYPOINT ["python"]
CMD ["run_terminal.py"]
