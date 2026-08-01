FROM golang:1.25-alpine

# Install tools needed for container runtime testing.
# iptables = airlock's own MASQUERADE/DNAT rules go through this binary via
#   go-iptables (bridge/veth/route setup itself is native netlink now, no
#   `ip`/`nsenter` binary needed for that — see container/network.go).
# iproute2 = kept for manual debugging (`ip addr`, `ip route`, etc. from a shell
#   inside this image) and for container images that configure their own
#   networking with it, not because airlock itself calls out to it anymore.
# strace = syscall tracing; util-linux = pivot_root etc.
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
