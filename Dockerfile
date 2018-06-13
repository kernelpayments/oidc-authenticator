FROM centurylink/ca-certs

COPY oidc-authenticator /

USER 1000
ENTRYPOINT ["/oidc-authenticator"]
