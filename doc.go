// Package workloadidentity authenticates gRPC calls between services in a
// Kubernetes cluster with workload identity.
//
// A caller sends its projected ServiceAccount token, minted for the callee's
// audience, as "authorization: Bearer <token>" metadata, read from a file on
// every call so a token the kubelet rotates in place is picked up
// (NewTokenCredentials, DialOptionFromEnv). A callee verifies the token
// against the cluster issuer's JWKS (Verifier), checks the service account
// against an exact allow-list, maps it to a caller name (Config.CallerName or
// Config.ServiceAccountPrefix), and checks a per-method allow-list in code
// (Policy) before the handler runs (UnaryServerInterceptor,
// StreamServerInterceptor):
//
//   - a caller missing from a method's list is refused with PermissionDenied;
//   - a caller listed as Self acts only as itself, so a request from it that
//     carries an `actor` field is refused with PermissionDenied;
//   - a caller listed as OnBehalf may pass an end-user actor.
//
// Configuration fails closed: ServerConfigFromEnv refuses to start without an
// issuer unless WORKLOAD_AUTH=disabled is set on purpose, the audience and
// the service-account allow-list are required, and a verifier with no key set
// loaded refuses every call with Unavailable.
//
// The package imports no service code or protos; the only contract with the
// request messages is the optional top-level `actor` field.
package workloadidentity

/*
MIT License

Copyright (c) 2026 Shane

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
