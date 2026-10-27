FROM python:3.12-slim
WORKDIR /app
COPY server.py targets.json policy.json ./
RUN useradd -r appuser && mkdir -p data && chown -R appuser /app
USER appuser
ENTRYPOINT ["python", "server.py"]
