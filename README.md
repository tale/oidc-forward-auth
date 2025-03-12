# OIDC Forward Auth

This is a simple forward auth server that passes on authentication to an OIDC provider.
It's designed to be used with services that do not have built-in OIDC auth support.
I'm mostly making my own because all of the existing ones I found ended up being
seriously unmaintained to a degree.

## Warning
This is VERY early software and it's been built entirely to work in my Traefik v3 setup.
As I get the time, I'll document more features and add examples for other proxies.
I may also add simpler provider support beyond generic OIDC.
