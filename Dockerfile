FROM harbor.tuxgrid.com/docker.io/golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod .
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o audit-service .

FROM scratch
COPY --from=builder /src/audit-service /audit-service
ENTRYPOINT ["/audit-service"]
