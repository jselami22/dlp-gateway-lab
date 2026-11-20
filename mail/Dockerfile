FROM python:3.12-alpine
ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir aiosmtpd==1.4.6

WORKDIR /app
COPY mailserver.py .
CMD ["python", "mailserver.py"]