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
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Environment variables read by ConfigFromEnv and DialOptionFromEnv.
const (
	EnvIssuer                 = "WORKLOAD_OIDC_ISSUER"
	EnvJWKSURL                = "WORKLOAD_OIDC_JWKS_URL"
	EnvCAFile                 = "WORKLOAD_OIDC_CA_FILE"
	EnvBearerFile             = "WORKLOAD_OIDC_BEARER_FILE" // #nosec G101 -- an environment variable name, not a credential
	EnvAudience               = "WORKLOAD_AUDIENCE"
	EnvAllowedServiceAccounts = "WORKLOAD_ALLOWED_SERVICEACCOUNTS"
	EnvTokenFile              = "WORKLOAD_TOKEN_FILE" // #nosec G101 -- an environment variable name, not a credential
	EnvServiceAccountPrefix   = "WORKLOAD_SERVICEACCOUNT_PREFIX"
)

// Config configures the Verifier.
type Config struct {
	// Issuer must equal the token's iss exactly.
	Issuer string
	// JWKSURL overrides discovery through <Issuer>/.well-known/openid-configuration.
	JWKSURL string
	// CAFile is an extra PEM bundle trusted for the discovery and JWKS fetch.
	CAFile string
	// BearerFile holds a token sent on the discovery and JWKS fetch. It is
	// re-read on every fetch because projected tokens rotate in place.
	BearerFile string
	// Audience must appear in the token's aud. Required: there is no default,
	// so a caller's token minted for another service is never accepted here.
	Audience string
	// AllowedServiceAccounts are the "<namespace>/<serviceaccount>" entries
	// that may call this service at all.
	AllowedServiceAccounts []string
	// ServiceAccountPrefix is stripped from the service account name to give
	// the caller name used in the Policy: with "app-", the service account
	// "app-gateway" is the caller "gateway". Empty keeps the name unchanged.
	ServiceAccountPrefix string
	// CallerName, when set, maps a verified namespace and service account to
	// the caller name instead of ServiceAccountPrefix.
	CallerName func(namespace, serviceAccount string) string
}

// ConfigFromEnv reads the WORKLOAD_* variables. ok is false when
// WORKLOAD_OIDC_ISSUER is unset, meaning workload authentication is not
// configured. A set issuer with a missing or malformed value elsewhere is an
// error, so a typo fails start-up instead of silently refusing every caller.
func ConfigFromEnv(getenv func(string) string) (cfg Config, ok bool, err error) {
	raw := strings.TrimSpace(getenv(EnvIssuer))
	if raw == "" {
		return Config{}, false, nil
	}
	cfg = Config{
		Issuer:     raw,
		JWKSURL:    strings.TrimSpace(getenv(EnvJWKSURL)),
		CAFile:     strings.TrimSpace(getenv(EnvCAFile)),
		BearerFile: strings.TrimSpace(getenv(EnvBearerFile)),
		Audience:   strings.TrimSpace(getenv(EnvAudience)),

		ServiceAccountPrefix: strings.TrimSpace(getenv(EnvServiceAccountPrefix)),
	}
	cfg.AllowedServiceAccounts, err = parseAllowed(getenv(EnvAllowedServiceAccounts))
	if err != nil {
		return Config{}, false, err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, false, err
	}
	return cfg, true, nil
}

func (c Config) validate() error {
	if err := requireHTTPS(EnvIssuer, c.Issuer); err != nil {
		return err
	}
	if c.JWKSURL != "" {
		if err := requireHTTPS(EnvJWKSURL, c.JWKSURL); err != nil {
			return err
		}
	}
	if c.Audience == "" {
		return fmt.Errorf("workloadidentity: %s is required when %s is set", EnvAudience, EnvIssuer)
	}
	if len(c.AllowedServiceAccounts) == 0 {
		return fmt.Errorf("workloadidentity: %s is required when %s is set", EnvAllowedServiceAccounts, EnvIssuer)
	}
	for _, e := range c.AllowedServiceAccounts {
		if err := checkEntry(e); err != nil {
			return err
		}
	}
	return nil
}

// requireHTTPS rejects plain-http key sources: whoever can rewrite the JWKS in
// transit can mint any caller identity.
func requireHTTPS(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("workloadidentity: %s must be an absolute https URL, got %q", name, raw)
	}
	return nil
}

func parseAllowed(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("workloadidentity: %s is required when %s is set", EnvAllowedServiceAccounts, EnvIssuer)
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if err := checkEntry(p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

var errEntry = errors.New("must be <namespace>/<serviceaccount>")

func checkEntry(e string) error {
	ns, sa, found := strings.Cut(e, "/")
	if !found || ns == "" || sa == "" || strings.ContainsAny(e, ": \t") || strings.Contains(sa, "/") {
		return fmt.Errorf("workloadidentity: %s entry %q %w", EnvAllowedServiceAccounts, e, errEntry)
	}
	return nil
}
