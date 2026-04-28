# Stage 1: Build
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -o detector .

# Stage 2: Run
FROM alpine:3.19

RUN apk add --no-cache iptables ca-certificates

WORKDIR /app

COPY --from=builder /app/detector .
COPY --from=builder /app/config.yaml .

RUN mkdir -p /var/log/detector

EXPOSE 8080

CMD ["./detector"]
