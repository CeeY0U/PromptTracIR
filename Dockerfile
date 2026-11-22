# PromptTracIR analyst UI and CLI.
#
#   docker build -t prompttracir:0.8.0 .
#   docker run --rm -p 127.0.0.1:8000:8000 -v "$PWD/cases/demo:/case" prompttracir:0.8.0
#
# Or use docker-compose.yml, which also starts the pinned local model (profile "llm").
# The case is mounted read-write: `ptir verify` and the UI's "Verify hashes" add chain-of-custody
# entries. Preserved evidence files keep their read-only mode inside the case.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# configs/ sits next to the package (llm.py reads configs/local-model.json from the repo root),
# so the package is installed in editable mode from /app.
COPY pyproject.toml README.md ./
COPY prompttracir ./prompttracir
COPY configs ./configs
COPY samples ./samples
RUN pip install -e ".[evtx,stix]"

EXPOSE 8000
VOLUME ["/case"]
CMD ["ptir", "serve", "/case", "--host", "0.0.0.0", "--port", "8000"]
