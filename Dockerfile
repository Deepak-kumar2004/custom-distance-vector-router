FROM alpine:latest

RUN apk add --no-cache python3 iproute2

WORKDIR /app
COPY router.py /app/router.py

CMD ["python3", "router.py"]
