# oidc-authenticator

## What is it?

`oidc-authenticator` is a tool to protect internal resources with an OpenID connect login. It works with [nginx auth_request module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) to selectively reverse-proxy only the requests that are properly authenticated.

## Why yet another authenticator?

There are many OAuth2 reverse proxies and authenticators out there, such as the excellent [oauth2_proxy](https://github.com/bitly/oauth2_proxy) and [BuzzFeed's SSO](https://github.com/buzzfeed/sso). So, why build another one from scratch?

- `oidc-authenticator` does not do reverse proxying itself by design. It is hard to build a performant reverse proxy that is compatible with all the HTTP upgrades such as WebSockets, SSE, the Docker/Kubernetes shell-over-HTTP. This task is better left to nginx.
- By using OpenID Connect, it is extremely easy to allow access to programmatic clients, such as desktop clients or service accounts. `oidc-authenticator` allows HTTP Bearer and Basic authentication in addition to HTTP cookies.
- Existing tools aim for extensive feature sets, thus increasing their complexity and making them difficult to audit. `oidc-authenticator` aims to do just one thing, and do it well. Therefore, is really slim, weighing just 300 lines of Go code.

## How it works

`oidc-authenticator` serves 3 endpoints.

- `/login`: redirects the user to the provider's OAuth flow.
- `/callback`: This is where the user is redirected when they finish the OAuth flow.
- `/auth`: Returns `200 OK` if the user is properly authenticated, and `401 Unauthorized` otherwise. This is set up as the URL used by nginx auth_request module.

The `/auth` endpoint accepts credentials in 3 forms:
- HTTP Cookie. This is the method that will be used when accessing protected resources with a web browser. The cookie contains the ID token, and the refresh token, so the ID token can be renewed on expiration without the user having to log in again.
- `Bearer` HTTP Authentication, with the OIDC ID Token as bearer token. This is intended for automated clients to access protected resources.
- `Basic` HTTP Authentication, with `_oidc` as username, and the OIDC ID Token as password. This is meant as a fallback for clients that can only use Basic authentication, such as Git.

## Deployment

Deployment is slightly different depending on whether you want to protect a single app (on a single domain), or multiple apps (on multiple domains or subdomains).

### Single domain

If you want to protect a single domain, you can do it by serving `oidc-authenticator` in a sub-path of the domain, such as `/_oidc`.

The relevant nginx settings would be:

- Reverse-proxy `https://echoserver.example.com/_oidc` to `oidc-authenticator`
- Reverse-proxy `https://echoserver.example.com/` to the application, with auth_request protection. On auth failure, redirect the user to `https://echoserver.example.com/_oidc/login`.

Configure `oidc-authenticator` like this:

- --cookie-domain=echoserver.example.com
- --cookie-secure=true
- --external-url=https://echoserver.example.com/_oidc

There is an example on how to deploy a protected `echoserver` with this setup in Kubernetes in `examples/kubernetes/single-domain`.

### Multiple domains

It is also possible to protect multiple applications with a single `oidc-authenticator` instance. To do so, all the applications must be hosted as subdomains under the same domain, so the authentication cookie can be shared between all of them.

This has the big advantage of requiring all users to login just once to access all the applications, while making deployment simpler.

To do this, you have to choose an additional subdomain for `oidc-authenticator`.

For example, if you're deploying `oidc-authenticator` to `https://auth.example.com`, and one of the applications you want to protect is at `https://echoserver.example.com`:

Configure `oidc-authenticator` like this. This will set the cookie for all subdomains of example.com

- --cookie-domain=.example.com
- --cookie-secure=true
- --external-url=https://auth.example.com

The relevant nginx settings would be:

- Reverse-proxy `https://auth.example.com` to `oidc-authenticator`
- Reverse-proxy `https://echoserver.example.com/` to the application, with auth_request protection. On auth failure, redirect the user to `https://auth.example.com/login`.

There is an example on how to do this in Kubernetes in `examples/kubernetes/multiple-domains`.

## Configuration

```
--issuer-url     URL to the OIDC provider. Default: https://accounts.google.com
--client-id      OIDC/OAuth Client ID
--client-secret  OIDC/OAuth Client Secret
--config-file    Path to YAML config file.
--external-url   URL where an external client can reach the oidc-authenticator instance. This is used to generate the callback URL for the
--cookie-name    Authentication cookie name. Default: _oidc
--cookie-domain  Authentication cookie domain
--cookie-path    Authentication cookie path. Default: /
--cookie-secure  Authentication cookie secure flag. Default: true.
```
