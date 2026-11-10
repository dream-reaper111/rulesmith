FROM python:3.12-slim
WORKDIR /app
RUN useradd --system --create-home appuser
COPY pyproject.toml ./
COPY rulesmith ./rulesmith
RUN pip install --no-cache-dir .
USER appuser
CMD ["uvicorn", "rulesmith.api:app", "--host", "0.0.0.0", "--port", "8000"]
