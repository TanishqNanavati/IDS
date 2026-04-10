# Multi-stage build for optimized image
FROM alpine:latest AS builder

RUN apk add --no-cache cmake make build-base

WORKDIR /app
COPY . .

RUN rm -rf build && mkdir build && cd build && cmake .. && make

FROM alpine:latest

RUN apk add --no-cache libgcc

RUN addgroup -g 1000 ids && adduser -D -s /bin/sh -u 1000 -G ids ids

WORKDIR /app

COPY --from=builder /app/build/ids .
COPY ids.conf .

RUN mkdir -p logs && chown ids:ids logs

USER ids

VOLUME ["/app/logs"]
EXPOSE 9100

CMD ["./ids", "ids.conf"]


