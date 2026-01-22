FROM golang:1.25-alpine AS builder

WORKDIR /usr/src/app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o mcp-server-wazuh ./cmd/mcp-server-wazuh

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /usr/src/app/mcp-server-wazuh /app/mcp-server-wazuh

RUN adduser -D -s /bin/sh wazuh
USER wazuh

# The Go app uses stdio transport, so no port exposure needed
# MCP servers communicate via stdin/stdout

CMD ["./mcp-server-wazuh"]
