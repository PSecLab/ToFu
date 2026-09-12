# VIPER-MCP evaluation sandbox — separate image from tofu-sandbox because Viper
# needs CodeQL (~1.1GB) + langchain, which ToFu does not. Runs untrusted MCP
# servers (Phase II fuzzes them) so it must be confined like the ToFu image.
FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates build-essential \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && cp -L /root/.local/bin/uv /usr/local/bin/uv && chmod 0755 /usr/local/bin/uv

# CodeQL bundle (native linux-arm64), pinned to the same version as the host
# (codeql-bundle-v2.27.0). The BUNDLE includes the standard query libraries Viper's ql packs
# depend on, so no  (which would need to write into the
# read-only repo mount at run time).
RUN curl -fsSL -o /tmp/codeql.tar.gz \
      "https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.0/codeql-bundle-linux-arm64.tar.gz" \
    && mkdir -p /opt && tar -xzf /tmp/codeql.tar.gz -C /opt && rm /tmp/codeql.tar.gz \
    && ln -sf /opt/codeql/codeql /usr/local/bin/codeql \
    && codeql version --format=terse

# Viper's Linux venv (langchain etc.) from its requirements.txt.
ENV VIPER_VENV=/opt/viper-venv
COPY Benchmarks/Viper-MCP/requirements.txt /tmp/viper-requirements.txt
RUN uv venv "$VIPER_VENV" --python 3.11 \
    && uv pip install --python "$VIPER_VENV/bin/python" -r /tmp/viper-requirements.txt \
    && "$VIPER_VENV/bin/python" -c "import langchain_mcp_adapters, yaml, openai; print('viper deps OK')"

# The repo is mounted at /work at run time (mounting it at its own
# /Users/... path collides with Docker Desktop's auto-shared /Users and
# yields an EMPTY mount). Bake a symlink so the absolute paths in
# prepared.jsonl (/Users/.../eval/targets/...) still resolve -> /work.
ARG REPO_PATH=/Users/nazmulislamananto/pseclab/ToFu
RUN mkdir -p "$(dirname "$REPO_PATH")" && ln -sfn /work "$REPO_PATH"

RUN useradd -m -u 1000 tofu
USER tofu
ENV PATH="/opt/viper-venv/bin:${PATH}" PYTHONUNBUFFERED=1
WORKDIR /work
CMD ["/bin/bash"]
