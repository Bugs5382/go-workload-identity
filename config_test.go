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
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestConfigFromEnvUnsetIssuerIsOff(t *testing.T) {
	_, ok, err := ConfigFromEnv(envMap(nil))
	if ok || err != nil {
		t.Fatalf("ok=%v err=%v, want off", ok, err)
	}
}

func TestConfigFromEnvReadsAndTrims(t *testing.T) {
	cfg, ok, err := ConfigFromEnv(envMap(map[string]string{
		EnvIssuer:                 " https://issuer.example.org ",
		EnvAudience:               " api.example.org ",
		EnvServiceAccountPrefix:   " app- ",
		EnvAllowedServiceAccounts: "apps/app-gateway, apps/app-workflow",
	}))
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if cfg.Issuer != "https://issuer.example.org" || cfg.Audience != "api.example.org" || cfg.ServiceAccountPrefix != "app-" {
		t.Fatalf("cfg %+v", cfg)
	}
	if len(cfg.AllowedServiceAccounts) != 2 || cfg.AllowedServiceAccounts[1] != "apps/app-workflow" {
		t.Fatalf("allow-list %v", cfg.AllowedServiceAccounts)
	}
}

func TestConfigFromEnvRequiresAnAudience(t *testing.T) {
	_, _, err := ConfigFromEnv(envMap(map[string]string{
		EnvIssuer:                 "https://issuer.example.org",
		EnvAllowedServiceAccounts: "apps/app-gateway",
	}))
	if err == nil || !strings.Contains(err.Error(), EnvAudience) {
		t.Fatalf("err=%v, want a missing %s error", err, EnvAudience)
	}
}

func TestNewVerifierRequiresAnAudience(t *testing.T) {
	_, err := NewVerifier(Config{Issuer: "https://issuer.example.org", AllowedServiceAccounts: []string{"apps/app-gateway"}}, nil)
	if err == nil {
		t.Fatal("a config without an audience should be refused")
	}
}

func TestConfigFromEnvRejectsBadValues(t *testing.T) {
	base := map[string]string{
		EnvIssuer:                 "https://issuer.example.org",
		EnvAudience:               "api.example.org",
		EnvAllowedServiceAccounts: "apps/app-gateway",
	}
	cases := map[string]map[string]string{
		"http issuer":       {EnvIssuer: "http://issuer.example.org"},
		"http jwks":         {EnvJWKSURL: "http://issuer.example.org/jwks"},
		"blank audience":    {EnvAudience: " "},
		"no allow-list":     {EnvAllowedServiceAccounts: " "},
		"entry without ns":  {EnvAllowedServiceAccounts: "app-gateway"},
		"entry with colon":  {EnvAllowedServiceAccounts: "apps/app:gateway"},
		"empty entry":       {EnvAllowedServiceAccounts: "apps/app-gateway,,apps/app-workflow"},
		"unreadable bearer": {EnvBearerFile: "/nonexistent/token"},
	}
	for name, over := range cases {
		t.Run(name, func(t *testing.T) {
			m := map[string]string{}
			for k, v := range base {
				m[k] = v
			}
			for k, v := range over {
				m[k] = v
			}
			cfg, ok, err := ConfigFromEnv(envMap(m))
			if err == nil {
				_, err = NewVerifier(cfg, nil)
			}
			if err == nil {
				t.Fatalf("ok=%v: want an error", ok)
			}
			if !strings.Contains(err.Error(), "workloadidentity") {
				t.Fatalf("error %q should name the package", err)
			}
		})
	}
}
