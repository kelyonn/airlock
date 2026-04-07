FROM golang:1.25-alpine

# Install useful tools for debugging inside containers
RUN apk add --no-cache bash strace util-linux

WORKDIR /app

# Copy go.mod and go.sum first (for Docker layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN go build -o /usr/local/bin/airlock .

# Default: drop into a shell so you can run airlock manually
CMD ["/bin/bash"]
