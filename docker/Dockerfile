# syntax=docker/dockerfile:1
# ARGs used in FROM must be declared before the first FROM
ARG LITELLM_IMAGE=ghcr.io/berriai/litellm:main-stable

# Stage 1 — build the KawalLM wheel
FROM python:3.12-slim AS build
WORKDIR /src
RUN pip install --no-cache-dir build
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN python -m build --wheel --outdir /dist

# Stage 2 — LiteLLM Proxy + KawalLM
FROM ${LITELLM_IMAGE}
# The upstream image ships its dependencies in /app/.venv (built with uv) and has no pip,
# so install the wheel with uv into the same interpreter that runs the proxy.
COPY --from=ghcr.io/astral-sh/uv:0.11.7 /uv /tmp/uv
COPY --from=build /dist/*.whl /tmp/
RUN /tmp/uv pip install --no-cache --python "$(command -v python)" /tmp/kawallm-*.whl \
 && rm -f /tmp/uv /tmp/kawallm-*.whl \
 && python -c "import kawallm.integrations.litellm as m; print('kawallm ok', m.KawalLMGuardrail)"
COPY docker/litellm_config.yaml /app/config.yaml
EXPOSE 4000
CMD ["--config", "/app/config.yaml", "--port", "4000"]
