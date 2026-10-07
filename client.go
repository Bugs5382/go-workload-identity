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

import (
	"context"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// tokenCredentials sends the caller's projected token on every call.
type tokenCredentials struct{ path string }

// NewTokenCredentials returns per-call credentials that read the token at path
// on every call, so a token the kubelet rotates in place is picked up, and
// send it as "authorization: Bearer <token>".
func NewTokenCredentials(path string) credentials.PerRPCCredentials {
	return tokenCredentials{path: path}
}

func (c tokenCredentials) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	tok, err := readToken(c.path)
	if err != nil {
		return nil, err
	}
	return map[string]string{"authorization": "Bearer " + tok}, nil
}

// RequireTransportSecurity is false so the token can ride in-cluster plaintext
// gRPC, where NetworkPolicies limit who can connect at all, as well as TLS.
func (tokenCredentials) RequireTransportSecurity() bool { return false }

func readToken(path string) (string, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
	if err != nil {
		return "", fmt.Errorf("workloadidentity: read %s: %w", EnvTokenFile, err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("workloadidentity: %s %q is empty", EnvTokenFile, path)
	}
	return tok, nil
}

// DialOptionFromEnv returns the dial option that sends the token named by
// WORKLOAD_TOKEN_FILE. ok is false when the variable is unset, so the caller
// sends no token. A set path that can't be read now is an error, so a missing
// mount fails start-up instead of every call.
func DialOptionFromEnv(getenv func(string) string) (opt grpc.DialOption, ok bool, err error) {
	path := strings.TrimSpace(getenv(EnvTokenFile))
	if path == "" {
		return nil, false, nil
	}
	if _, err := readToken(path); err != nil {
		return nil, false, err
	}
	return grpc.WithPerRPCCredentials(NewTokenCredentials(path)), true, nil
}
