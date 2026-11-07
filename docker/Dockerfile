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
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/kawallm-*.whl && rm -f /tmp/kawallm-*.whl \
 && python -c "import kawallm.integrations.litellm as m; print('kawallm ok', m.KawalLMGuardrail)"
COPY docker/litellm_config.yaml /app/config.yaml
EXPOSE 4000
CMD ["--config", "/app/config.yaml", "--port", "4000"]
