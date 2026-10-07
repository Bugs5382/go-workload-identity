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
	"errors"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/golang-jwt/jwt/v5"
)

const (
	testNS       = "apps"
	testAudience = "api.example.org"
	testPrefix   = "app-"
)

func newVerifier(t *testing.T, iss *testIssuer, allowed ...string) *Verifier {
	t.Helper()
	if len(allowed) == 0 {
		allowed = []string{testNS + "/app-gateway"}
	}
	return newVerifierWith(t, iss, Config{ServiceAccountPrefix: testPrefix, AllowedServiceAccounts: allowed})
}

// newVerifierWith fills in the test issuer and audience and loads the keys.
func newVerifierWith(t *testing.T, iss *testIssuer, cfg Config) *Verifier {
	t.Helper()
	cfg.Issuer, cfg.CAFile, cfg.Audience = iss.URL, iss.CAFile, testAudience
	v, err := NewVerifier(cfg, log.Nop())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	return v
}

func TestVerifyMapsServiceAccountToCallerName(t *testing.T) {
	iss := newTestIssuer(t)
	v := newVerifier(t, iss)
	for kid, alg := range map[string]jwt.SigningMethod{"rsa-1": jwt.SigningMethodRS256, "ec-1": jwt.SigningMethodES256} {
		tok := iss.sign(t, kid, kid, alg, saClaims(iss.URL, testAudience, testNS, "app-gateway", time.Now()))
		c, err := v.Verify(tok)
		if err != nil {
			t.Fatalf("%s: valid token rejected: %v", alg.Alg(), err)
		}
		if c.Name != "gateway" || c.ServiceAccount != testNS+"/app-gateway" {
			t.Fatalf("%s: caller %+v", alg.Alg(), c)
		}
	}
}

func TestVerifyRejectsBadTokens(t *testing.T) {
	iss := newTestIssuer(t)
	v := newVerifier(t, iss)
	now := time.Now()
	good := func() jwt.MapClaims { return saClaims(iss.URL, testAudience, testNS, "app-gateway", now) }
	cases := map[string]func(jwt.MapClaims){
		"wrong iss":         func(c jwt.MapClaims) { c["iss"] = iss.URL + "/other" },
		"wrong aud":         func(c jwt.MapClaims) { c["aud"] = []string{"other-audience"} },
		"expired":           func(c jwt.MapClaims) { c["exp"] = now.Add(-2 * time.Minute).Unix() },
		"no exp":            func(c jwt.MapClaims) { delete(c, "exp") },
		"nbf in the future": func(c jwt.MapClaims) { c["nbf"] = now.Add(2 * time.Minute).Unix() },
		"not a sa":          func(c jwt.MapClaims) { c["sub"] = "user:alice" },
		"sa not allowed": func(c jwt.MapClaims) {
			c["sub"] = "system:serviceaccount:" + testNS + ":app-mcp"
			c["kubernetes.io"] = map[string]any{"namespace": testNS, "serviceaccount": map[string]any{"name": "app-mcp"}}
		},
		"kubernetes claim mismatch": func(c jwt.MapClaims) {
			c["kubernetes.io"] = map[string]any{"namespace": "other", "serviceaccount": map[string]any{"name": "app-gateway"}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := good()
			mutate(c)
			_, err := v.Verify(iss.sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, c))
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("want ErrRejected, got %v", err)
			}
		})
	}
	t.Run("empty", func(t *testing.T) {
		if _, err := v.Verify(""); !errors.Is(err, ErrRejected) {
			t.Fatalf("want ErrRejected, got %v", err)
		}
	})
	t.Run("no kid", func(t *testing.T) {
		if _, err := v.Verify(iss.sign(t, "rsa-1", "", jwt.SigningMethodRS256, good())); !errors.Is(err, ErrRejected) {
			t.Fatalf("want ErrRejected, got %v", err)
		}
	})
	t.Run("hmac", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, good())
		tok.Header["kid"] = "rsa-1"
		s, err := tok.SignedString([]byte("shared"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(s); !errors.Is(err, ErrRejected) {
			t.Fatalf("want ErrRejected, got %v", err)
		}
	})
	t.Run("rsa token against ec key", func(t *testing.T) {
		if _, err := v.Verify(iss.sign(t, "rsa-1", "ec-1", jwt.SigningMethodRS256, good())); !errors.Is(err, ErrRejected) {
			t.Fatalf("want ErrRejected, got %v", err)
		}
	})
}

func TestVerifyUnavailableBeforeFirstLoad(t *testing.T) {
	iss := newTestIssuer(t)
	iss.fail.Store(true)
	v, err := NewVerifier(Config{Issuer: iss.URL, CAFile: iss.CAFile, Audience: testAudience, AllowedServiceAccounts: []string{testNS + "/app-gateway"}}, log.Nop())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(iss.token(t, testNS, "app-gateway")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestVerifyKeepsLastGoodKeysWhenIssuerFails(t *testing.T) {
	iss := newTestIssuer(t)
	v := newVerifier(t, iss)
	iss.fail.Store(true)
	if err := v.Refresh(context.Background()); err == nil {
		t.Fatal("refresh against a failing issuer should error")
	}
	if _, err := v.Verify(iss.token(t, testNS, "app-gateway")); err != nil {
		t.Fatalf("last good set dropped: %v", err)
	}
}

func TestCallerNameMapping(t *testing.T) {
	iss := newTestIssuer(t)
	allowed := []string{testNS + "/app-gateway", testNS + "/ops-tool"}
	cases := map[string]struct {
		cfg  Config
		want map[string]string
	}{
		"no mapping keeps the service account name": {
			cfg:  Config{},
			want: map[string]string{"app-gateway": "app-gateway", "ops-tool": "ops-tool"},
		},
		"prefix is stripped where present": {
			cfg:  Config{ServiceAccountPrefix: testPrefix},
			want: map[string]string{"app-gateway": "gateway", "ops-tool": "ops-tool"},
		},
		"mapping function wins over the prefix": {
			cfg:  Config{ServiceAccountPrefix: testPrefix, CallerName: func(ns, sa string) string { return ns + "." + sa }},
			want: map[string]string{"app-gateway": testNS + ".app-gateway", "ops-tool": testNS + ".ops-tool"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tc.cfg.AllowedServiceAccounts = allowed
			v := newVerifierWith(t, iss, tc.cfg)
			for sa, want := range tc.want {
				c, err := v.Verify(iss.token(t, testNS, sa))
				if err != nil {
					t.Fatalf("%s: %v", sa, err)
				}
				if c.Name != want || c.ServiceAccount != testNS+"/"+sa {
					t.Fatalf("%s: caller %+v, want name %q", sa, c, want)
				}
			}
		})
	}
}

func TestReadyReportsWhetherAKeySetIsLoaded(t *testing.T) {
	iss := newTestIssuer(t)
	iss.fail.Store(true)
	v, err := NewVerifier(Config{Issuer: iss.URL, CAFile: iss.CAFile, Audience: testAudience, AllowedServiceAccounts: []string{testNS + "/app-gateway"}}, log.Nop())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Ready(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("before the first load: %v, want ErrUnavailable", err)
	}
	iss.fail.Store(false)
	if err := v.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := v.Ready(); err != nil {
		t.Fatalf("after a load: %v", err)
	}
	iss.fail.Store(true)
	_ = v.Refresh(context.Background())
	if err := v.Ready(); err != nil {
		t.Fatalf("a failed refresh keeps the last good set, so it stays ready: %v", err)
	}
}
