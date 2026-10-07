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
	"fmt"
	"time"

	log "github.com/Bugs5382/go-log"
)

// EnvAuthMode turns authentication off when set to AuthDisabled. Nothing else
// does: an unset issuer without it is a start-up error.
const EnvAuthMode = "WORKLOAD_AUTH"

// AuthDisabled is the only accepted value of WORKLOAD_AUTH. Local development
// and mock tooling set it on purpose; a deployment never should.
const AuthDisabled = "disabled"

// DisabledWarnInterval is how often WarnDisabled repeats its warning.
const DisabledWarnInterval = 5 * time.Minute

// ErrNotConfigured means WORKLOAD_OIDC_ISSUER is unset and authentication
// wasn't explicitly disabled.
var ErrNotConfigured = errors.New("workloadidentity: " + EnvIssuer + " is not set; set it, or set " + EnvAuthMode + "=" + AuthDisabled + " for local development only")

// ServerConfigFromEnv is ConfigFromEnv for a callee, failing closed: with no
// issuer it returns ErrNotConfigured unless WORKLOAD_AUTH=disabled, in which
// case enabled is false. An issuer together with WORKLOAD_AUTH=disabled, or
// any other WORKLOAD_AUTH value, is an error.
func ServerConfigFromEnv(getenv func(string) string) (cfg Config, enabled bool, err error) {
	mode := getenv(EnvAuthMode)
	if mode != "" && mode != AuthDisabled {
		return Config{}, false, fmt.Errorf("workloadidentity: %s=%q: the only accepted value is %q", EnvAuthMode, mode, AuthDisabled)
	}
	cfg, ok, err := ConfigFromEnv(getenv)
	if err != nil {
		return Config{}, false, err
	}
	switch {
	case ok && mode == AuthDisabled:
		return Config{}, false, fmt.Errorf("workloadidentity: %s and %s=%s are both set; pick one", EnvIssuer, EnvAuthMode, AuthDisabled)
	case ok:
		return cfg, true, nil
	case mode == AuthDisabled:
		return Config{}, false, nil
	default:
		return Config{}, false, ErrNotConfigured
	}
}

// WarnDisabled logs that authentication is off now and every interval until
// ctx ends. Run it in its own goroutine when ServerConfigFromEnv reports
// authentication disabled.
func WarnDisabled(ctx context.Context, lg log.Logger, interval time.Duration) {
	warn := func() {
		lg.Warn("service-to-service authentication is DISABLED (" + EnvAuthMode + "=" + AuthDisabled + "): any caller that reaches this port is trusted; never run this outside local development")
	}
	warn()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			warn()
		}
	}
}
