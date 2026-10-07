# AGENTS.md - go-workload-identity

Guide for AI agents working in this repository. Pair with `CLAUDE.md` (the working agreement and
hook-enforced rules). Keep this file current when the build, layout, or public API changes.

## What this is

A Go library, package `workloadidentity`, that authenticates gRPC calls between services in one
Kubernetes cluster. A caller sends its projected ServiceAccount token; the callee verifies it
against the cluster issuer's JWKS, checks the service account against an allow-list, maps it to a
caller name, and checks a per-method `Policy` before the handler runs.

Two things to understand before changing it:

- It is a generic helper. No product names, service names, audiences or token paths are baked
  in: the caller supplies the issuer, audience, allow-list, token path and caller-name mapping.
  Keep it that way; a new default must never widen who is accepted.
- It fails closed. Missing config is a start-up error, a verifier with no key set refuses every
  call with `Unavailable`, and only `WORKLOAD_AUTH=disabled` turns authentication off.

## Using go-workload-identity

- Server: `NewVerifier(Config, logger)` (or `ServerConfigFromEnv`), run `Verifier.Run` in a
  goroutine, and install `UnaryServerInterceptor` / `StreamServerInterceptor` with a `Policy`.
  Gate readiness on `Verifier.Ready()`.
- Client: `NewTokenCredentials(path)` or `DialOptionFromEnv` as a per-RPC credential.
- Handlers read the verified caller with `GrantFromContext`.
- `Config.Audience` and `Config.AllowedServiceAccounts` are required. `Config.CallerName` wins
  over `Config.ServiceAccountPrefix`; with neither, the caller name is the service account name.
- The only contract with request messages is an optional top-level `actor` message field.

## Layout

- `doc.go` - package overview
- `config.go` - `Config`, the `WORKLOAD_*` environment variables, `ConfigFromEnv`
- `mode.go` - `ServerConfigFromEnv`, the fail-closed `WORKLOAD_AUTH` switch, `WarnDisabled`
- `verifier.go` - `Verifier`: token checks, allow-list, caller-name mapping, `Ready`
- `jwks.go` - discovery and JWKS fetch, key cache and refresh
- `policy.go` - `Policy`, `Access`, `Grant`, the `actor` check
- `interceptor.go` - the unary and stream server interceptors, deny hook, exemptions
- `client.go` - per-RPC token credentials and `DialOptionFromEnv`
- `*_test.go` - unit tests; `issuer_test.go` is a local TLS OIDC issuer with generated keys, and
  `example_test.go` holds the godoc examples

## Build, test, lint

- Build: `task build` (`go build ./...`)
- Test: `task test` (`go test ./...`); hermetic, no cluster or network needed
- Lint: `task lint` (gofmt check, `golangci-lint run`, `yamllint .`)
- License headers: `task license` (check) and `task license:fix` (inject the MIT header)

## Logging

Follow the logging rules in `CLAUDE.md`. In short:

- Log generously: entry and exit of significant operations, decisions and branches, retries, state
  changes, external calls (target, duration, outcome), and every error with its context.
- Levels: `trace` for step-by-step detail, `debug` for flow, `info` for lifecycle, `warn` and
  `error` for problems. The environment filters the volume, so err on the side of too much.
- The library logs through the `github.com/Bugs5382/go-log` logger it is given; a nil logger
  discards. It never sets a level or format itself.
- Never log tokens, secrets, or personal data, not even at `trace`. Log the caller name and
  service account instead.

## Conventions and gotchas

- See `CLAUDE.md` for the branch/commit/PR rules; they are enforced by the git hooks in
  `.claude/hooks` (run `bash .claude/hooks/install.sh` once per clone).
- Open every PR as a draft. CI skips drafts, so run the full checks locally, push once they pass,
  and mark the PR ready when the work is finished; see CLAUDE.md "CI and Actions minutes".
- Tests use neutral fixtures only (`apps/app-gateway`, `example.org`); never copy values from a
  real cluster.
- Behaviour, config or API changes update `README.md` (usage and the environment table) and
  `doc.go` in the same PR.
