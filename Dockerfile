FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY soc_agent/ soc_agent/

ENV PORT=8080
CMD ["sh", "-c", "uvicorn soc_agent.server:app --host 0.0.0.0 --port ${PORT}"]
