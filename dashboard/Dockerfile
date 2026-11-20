FROM python:3.12-alpine
ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir flask==3.0.3

WORKDIR /app
COPY app.py .
CMD ["python", "app.py"]