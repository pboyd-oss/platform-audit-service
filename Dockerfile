FROM harbor.tuxgrid.com/docker.io/golang:1.26-alpine AS builder
ARG PLATFORM_CA_B64=""
RUN [ -z "$PLATFORM_CA_B64" ] || (printf '%s' "$PLATFORM_CA_B64" | base64 -d > /usr/local/share/ca-certificates/platform-build.crt && update-ca-certificates 2>/dev/null)
WORKDIR /src
COPY go.mod .
COPY main.go .
COPY ui/ ui/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o audit-service .

FROM scratch
COPY --from=builder /src/audit-service /audit-service
ENTRYPOINT ["/audit-service"]
