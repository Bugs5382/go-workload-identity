# go-workload-identity 🪪

> 🔐 Kubernetes workload identity for gRPC services: verify projected ServiceAccount tokens and enforce a per-method caller allow-list.

Services in one Kubernetes cluster often call each other over gRPC with no proof of who is
calling. `go-workload-identity` fixes that with the identity the cluster already hands every pod.
A caller sends its projected ServiceAccount token, minted for the callee's audience, as
`authorization: Bearer <token>` metadata. The callee checks it against the cluster issuer's JWKS,
matches the service account against an exact allow-list, maps it to a caller name, and checks a
per-method policy in code before the handler runs.

## ✨ What it does

- 🧾 **Verifies projected tokens:** RS256 or ES256 only, exact issuer, required audience, expiry,
  and a `kubernetes.io` claim that must match the subject.
- 📋 **Two allow-lists:** service accounts that may call the service at all, and a per-method
  `Policy` that says which callers may call which method.
- 👤 **Self or on behalf:** a `Self` caller acts only as itself, so a request from it that carries
  an `actor` field is refused; an `OnBehalf` caller may pass an end-user actor.
- 🔄 **Rotation-safe:** the client re-reads its token file on every call, the verifier refreshes
  the JWKS on a timer and once on an unknown key id, and a failed refresh keeps the last good set.
- 🚪 **Fail-closed:** no issuer means no start, unless authentication is switched off on purpose
  for local development.

## 📦 Install

```bash
go get github.com/Bugs5382/go-workload-identity
```

## 🚀 Usage

On the server, build a verifier from explicit config, keep its key set fresh, and install the
interceptors with a policy:

```go
import (
	log "github.com/Bugs5382/go-log"
	workloadidentity "github.com/Bugs5382/go-workload-identity"
	"google.golang.org/grpc"
)

cfg := workloadidentity.Config{
	Issuer:                 "https://kubernetes.default.svc.cluster.local",
	Audience:               "orders.example.org",
	AllowedServiceAccounts: []string{"shop/app-gateway", "shop/app-billing"},
	ServiceAccountPrefix:   "app-", // "app-gateway" is the caller "gateway"
}
v, err := workloadidentity.NewVerifier(cfg, logger)
if err != nil {
	return err
}
go v.Run(ctx) // loads the JWKS now, then every 15 minutes

policy := workloadidentity.Policy{
	"/orders.v1.Orders/GetOrder":    {"gateway": workloadidentity.OnBehalf, "billing": workloadidentity.Self},
	"/orders.v1.Orders/CancelOrder": {"gateway": workloadidentity.OnBehalf},
}
srv := grpc.NewServer(
	grpc.ChainUnaryInterceptor(workloadidentity.UnaryServerInterceptor(v, policy, logger,
		workloadidentity.WithDenyHook(audit))),
	grpc.ChainStreamInterceptor(workloadidentity.StreamServerInterceptor(v, policy, logger)),
)
```

A handler reads the verified caller with `workloadidentity.GrantFromContext(ctx)`. For a caller
name that a prefix can't express, set `Config.CallerName` to your own mapping function.

On the client, mount a projected token for the callee's audience and send it on every call:

```go
conn, err := grpc.NewClient("orders.shop.svc:8080",
	grpc.WithTransportCredentials(creds),
	grpc.WithPerRPCCredentials(workloadidentity.NewTokenCredentials("/var/run/secrets/tokens/orders")),
)
```

The matching pod spec mounts the token with the same audience the server requires:

```yaml
volumes:
  - name: orders-token
    projected:
      sources:
        - serviceAccountToken:
            audience: orders.example.org
            expirationSeconds: 3600
            path: orders
```

To configure both sides from the environment instead, use `ServerConfigFromEnv(os.Getenv)` on
the server and `DialOptionFromEnv(os.Getenv)` on the client.

## ⚙️ Configuration

`ServerConfigFromEnv` and `ConfigFromEnv` read these variables. A set issuer with a missing or
malformed value elsewhere is a start-up error.

| Variable | Side | Required | Meaning |
| --- | --- | --- | --- |
| `WORKLOAD_OIDC_ISSUER` | server | yes | Issuer URL, must equal the token's `iss`; `https` only |
| `WORKLOAD_AUDIENCE` | server | yes | Audience that must appear in the token's `aud`; no default |
| `WORKLOAD_ALLOWED_SERVICEACCOUNTS` | server | yes | Comma-separated `<namespace>/<serviceaccount>` entries allowed to call at all |
| `WORKLOAD_SERVICEACCOUNT_PREFIX` | server | no | Prefix stripped from the service account name to give the caller name |
| `WORKLOAD_OIDC_JWKS_URL` | server | no | JWKS URL, overriding discovery through `<issuer>/.well-known/openid-configuration` |
| `WORKLOAD_OIDC_CA_FILE` | server | no | Extra PEM bundle trusted for the discovery and JWKS fetch |
| `WORKLOAD_OIDC_BEARER_FILE` | server | no | Token sent on the discovery and JWKS fetch, re-read on every fetch |
| `WORKLOAD_AUTH` | server | no | `disabled` turns authentication off; any other value is an error |
| `WORKLOAD_TOKEN_FILE` | client | yes, to send a token | Path of the caller's projected token, re-read on every call |

## 🛡️ Security notes

- **Fail-closed start:** without `WORKLOAD_OIDC_ISSUER`, `ServerConfigFromEnv` returns
  `ErrNotConfigured`. Only `WORKLOAD_AUTH=disabled` turns authentication off, an issuer together
  with it is an error, and `WarnDisabled` logs a warning on a timer while it is off. Never set it
  outside local development.
- **No defaults that widen access:** the audience and the service-account allow-list are
  required, a method missing from the policy is refused, and so is a caller missing from a
  method's entry.
- **Readiness:** until the first JWKS load, every call fails with `Unavailable`. Wire
  `Verifier.Ready()` into the readiness check so the pod takes no traffic before then; it makes no
  network call, and a later failed refresh keeps the last good set.
- **Key sources:** the issuer, discovered `jwks_uri` and JWKS override must be `https`, RSA keys
  must be at least 2048 bits, EC keys must be P-256, and an unknown key id triggers at most one
  refresh every 30 seconds.
- **Logging:** tokens are never logged. Refusals are logged at `warn` with the method, caller and
  reason, and `WithDenyHook` hands each one to your audit trail.
- **Health is exempt:** `/grpc.health.v1.Health/` needs no token; `WithExempt` exempts more.

## 🛠️ Develop

```bash
task build    # go build ./...
task test     # go test ./...
task lint     # gofmt check + golangci-lint + yamllint
task license  # check MIT headers (golic)
```

## ⚖️ License

MIT (c) 2026 Shane. See [LICENSE](LICENSE).

## 🙏 Acknowledgements

go-workload-identity was originally written by [@Bugs5382](https://github.com/Bugs5382).
