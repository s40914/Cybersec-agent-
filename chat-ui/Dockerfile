FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY static ./static
EXPOSE 8501
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8501", "--timeout-keep-alive", "900"]
