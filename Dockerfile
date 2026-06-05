FROM golang:1.25-alpine

# Install tools needed for container runtime testing
# iptables, iproute2 = networking; strace = syscall tracing; util-linux = pivot_root etc.
RUN apk add --no-cache bash strace util-linux iptables iproute2 curl

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
