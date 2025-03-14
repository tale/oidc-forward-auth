FROM golang:1.23 AS builder
WORKDIR /app

# Install CA certificates
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y \
	--no-install-recommends ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

ARG GIT_COMMIT="unknown"
ARG GIT_TAG="dev"

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
	-ldflags "-s -w -extldflags '-static' -X main.GitCommit=${GIT_COMMIT} -X main.GitTag=${GIT_TAG}" \
	-o /app/oidc_forward_auth cmd/oidc_forward_auth.go

FROM scratch
USER 1000:1000

COPY --from=builder /app/oidc_forward_auth /oidc_forward_auth
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/oidc_forward_auth"]
