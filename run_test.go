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
)

// newUnloadedVerifier builds a verifier against iss with fast first-load
// retries and loads no keys.
func newUnloadedVerifier(t *testing.T, iss *testIssuer) *Verifier {
	t.Helper()
	v, err := NewVerifier(Config{Issuer: iss.URL, CAFile: iss.CAFile, Audience: testAudience, AllowedServiceAccounts: []string{testNS + "/app-gateway"}}, log.Nop())
	if err != nil {
		t.Fatal(err)
	}
	v.retryInitial, v.retryMax = 10*time.Millisecond, 40*time.Millisecond
	return v
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The issuer refuses the first fetches (the pod network still coming up);
// Run keeps retrying and the verifier turns ready without a restart, long
// before the periodic refresh would have fired.
func TestRunRetriesUntilTheFirstKeySetLoads(t *testing.T) {
	iss := newTestIssuer(t)
	iss.refuse.Store(3)
	v := newUnloadedVerifier(t, iss)
	v.interval = time.Hour
	if err := v.Ready(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("before Run: %v, want ErrUnavailable", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go v.Run(ctx)

	waitFor(t, "the verifier to turn ready", func() bool { return v.Ready() == nil })
	if got := iss.discoveryHits.Load(); got != 4 {
		t.Fatalf("discovery requests = %d, want the 3 refused and 1 served", got)
	}
	if _, err := v.Verify(iss.token(t, testNS, "app-gateway")); err != nil {
		t.Fatalf("token after recovery: %v", err)
	}
}

// Once the set loads, the retries stop and the periodic refresh takes over.
func TestRunRefreshesPeriodicallyAfterTheKeysLoad(t *testing.T) {
	iss := newTestIssuer(t)
	iss.refuse.Store(2)
	v := newUnloadedVerifier(t, iss)
	v.interval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go v.Run(ctx)

	waitFor(t, "the verifier to turn ready", func() bool { return v.Ready() == nil })
	loadedAt := iss.jwksHits.Load()
	waitFor(t, "two periodic refreshes", func() bool { return iss.jwksHits.Load() >= loadedAt+2 })
	if err := v.Ready(); err != nil {
		t.Fatalf("after periodic refreshes: %v", err)
	}
}

// A cancelled context ends Run while it is still retrying the first load.
func TestRunStopsRetryingWhenCancelled(t *testing.T) {
	iss := newTestIssuer(t)
	iss.fail.Store(true)
	v := newUnloadedVerifier(t, iss)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { v.Run(ctx); close(done) }()

	waitFor(t, "a retry", func() bool { return iss.discoveryHits.Load() >= 2 })
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if err := v.Ready(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("after cancel: %v, want ErrUnavailable", err)
	}
}

// The retry delay doubles from the initial value and holds at the cap.
func TestFirstLoadBackoffDoublesToTheCap(t *testing.T) {
	got := []time.Duration{}
	d := time.Second
	for range 7 {
		got = append(got, d)
		d = nextRetry(d, 30*time.Second)
	}
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30}
	for i := range want {
		if got[i] != want[i]*time.Second {
			t.Fatalf("delays = %v, want %v seconds", got, want)
		}
	}
}
