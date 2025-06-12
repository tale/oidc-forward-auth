# OIDC Forward Auth

This is a simple forward auth server that passes on authentication to an OIDC provider.
It's designed to be used with services that do not have built-in OIDC auth support.
I'm mostly making my own because all of the existing ones I found ended up being
seriously unmaintained to a degree.

## Warning
This is VERY early software and it's been built entirely to work in my Traefik v3 setup.
As I get the time, I'll document more features and add examples for other proxies.
I may also add simpler provider support beyond generic OIDC.

# Deployment
These instructions assume that you have a working OIDC provider and a working
Traefik (version 3) reverse-proxy setup. If you don't have that, you'll need to
set that up first.

Before you get started, you'll need to create a client in your OIDC provider:
- Ensure that PKCE (Proof Key for Code Exchange) is disabled (for now).
- Set the redirect URI to `https://your-gateway.example.com/oidc`
- Do not set the client type to "Public", we need an ID and secret.

This is deployed as a Docker container, here is a sample `docker-compose.yaml`:

```yaml
services:
  oidc-forward-auth:
    image: ghcr.io/tale/oidc-forward:latest
    port:
     - "4180:4180"
    labels:
      - traefik.enable=true
      - traefik.http.routers.oidc-forward.rule=Host(`forward.example.com`)
      - traefik.http.routers.oidc-forward.entrypoints=websecure
      - traefik.http.routers.oidc-forward.tls=true
      - traefik.http.routers.oidc-forward.tls.certresolver=letsencrypt
      - traefik.http.services.oidc-forward.loadbalancer.server.port=4180
    environment:
      COOKIE_SECRET: "some-random-32-character-string"
      # Publicly accessible URL of the forward auth server
      # This needs to be behind a reverse proxy to work at all
      GATEWAY_URL: "https://your-gateway.example.com"

      # OIDC provider configuration
      OIDC_ISSUER: "https://your-oidc-provider.example.com"
      OIDC_CLIENT_ID: "your-client-id"
      OIDC_CLIENT_SECRET: "your-client-secret"

      # Optionally enable debug logs, default false
      DEBUG: "true"

      # Optionally override the cookie domain
      # If not supplied, the domain is guessed from the GATEWAY_URL
      COOKIE_DOMAIN: ".example.com"

      # Optional cookie name, default is "_forward_oidc"
      # State cookie is the cookie while logging in
      COOKIE_NAME: "_forward_oidc"
      STATE_COOKIE_NAME: "_forward_oidc_state"

      # Optional expiry in minutes, default is 60
      COOKIE_EXPIRY: "60"

      # Optional port, default is 4180
      PORT: "4180"

      # Sets how long authentication waits in minutes, default is 2
      LOGIN_WINDOW: "2"
```

Once this is deployed, you can easily create a new Traefik middleware to protect
your services. Here is an example of how to protect a service with this forward auth in a `docker-compose.yaml`:

```yaml
services:
  whoami:
    image: traefik/whoami
    container_name: whoami
    labels:
      - traefik.enable=true
      - traefik.http.routers.whoami.rule=Host(`whoami.example.com`)
      - traefik.http.routers.whoami.entrypoints=websecure
      - traefik.http.routers.whoami.tls.certresolver=dev
      # Here we are defining the middleware, but you can put this anywhere
      # Just keep in mind this should be the same as GATEWAY_URL
      - traefik.http.middlewares.forward-auth.forwardauth.address=https://forward.example.com
      - traefik.http.routers.whoami.middlewares=forward-auth
```

> If you are running Traefik behind Cloudflare, it will not pass any
> forwarded headers by default. You will need to set this in your entrypoints
> by setting: `entryPoints.<name>.forwardedHeaders.insecure = true` or by
> whitelisting the Cloudflare IP ranges in your Traefik configuration.
