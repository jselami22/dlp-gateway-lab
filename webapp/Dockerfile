FROM python:3.12-alpine

RUN apk add --no-cache iproute2
RUN pip install --no-cache-dir flask==3.0.3

WORKDIR /app
COPY app.py .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]