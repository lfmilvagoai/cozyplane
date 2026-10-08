/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"

	"github.com/spf13/pflag"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

var fast = restartPolicy{min: time.Millisecond, max: 4 * time.Millisecond, settled: time.Hour}

// The regression: an exiting reconciler must come back, not leave the process up
// with nothing reconciling.
func TestRunWithRestartRestartsAfterError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var runs atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		runWithRestart(ctx, "test", fast, func(context.Context) error {
			if runs.Add(1) >= 3 {
				cancel() // third attempt: shut down so the loop returns
			}
			return errors.New("transient")
		}, quietLogger())
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runWithRestart did not return after ctx cancel")
	}
	if got := runs.Load(); got < 3 {
		t.Fatalf("run invoked %d times, want at least 3 (it did not restart)", got)
	}
}

// A clean return is still a restart while ctx lives: a reconciler that returns
// nil has stopped reconciling just as surely as one that errors.
func TestRunWithRestartRestartsOnNilError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var runs atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		runWithRestart(ctx, "test", fast, func(context.Context) error {
			if runs.Add(1) >= 2 {
				cancel()
			}
			return nil
		}, quietLogger())
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runWithRestart did not return after ctx cancel")
	}
	if got := runs.Load(); got < 2 {
		t.Fatalf("run invoked %d times, want at least 2", got)
	}
}

// An already-cancelled context must not start a run, and must not spin.
func TestRunWithRestartHonoursCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var runs atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		runWithRestart(ctx, "test", fast, func(context.Context) error {
			runs.Add(1)
			return errors.New("should not loop")
		}, quietLogger())
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runWithRestart kept looping on a cancelled context")
	}
	if got := runs.Load(); got > 1 {
		t.Fatalf("run invoked %d times on a cancelled context, want at most 1", got)
	}
}

// The backoff is capped: a tight crash loop must not grow its delay without
// bound, or recovery after a long outage takes longer than the outage.
func TestRunWithRestartCapsBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var runs atomic.Int32
	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runWithRestart(ctx, "test", fast, func(context.Context) error {
			if runs.Add(1) >= 12 {
				cancel()
			}
			return errors.New("transient")
		}, quietLogger())
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runWithRestart did not return")
	}
	// 12 runs capped at 4ms apiece is well under a second; uncapped doubling
	// from 1ms would already be past 4s by the twelfth.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("12 restarts took %v — the backoff is not capped", elapsed)
	}
}

// The endpoint the chart configures must reach this reconciler. It used to use
// InClusterConfig unconditionally, i.e. the kubernetes.default ClusterIP, which
// kpr itself is responsible for serving.
func TestAPIServerHost(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  []string
		want string
	}{
		{"talos kubeprism", []string{"https://localhost:7445"}, "https://localhost:7445"},
		{"bare host:port defaults to https", []string{"10.0.0.5:6443"}, "https://10.0.0.5:6443"},
		{"explicit http is kept", []string{"http://127.0.0.1:8080"}, "http://127.0.0.1:8080"},
		{"first non-empty wins", []string{"", "https://a:6443", "https://b:6443"}, "https://a:6443"},
		{"unset falls back to in-cluster", nil, ""},
		{"empty entries fall back", []string{"", ""}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
			fs.StringSlice(flagAPIServerURLs, nil, "")
			for _, v := range tc.set {
				if err := fs.Set(flagAPIServerURLs, v); err != nil {
					t.Fatalf("set: %v", err)
				}
			}
			got, err := apiServerHost(fs)
			if err != nil {
				t.Fatalf("apiServerHost: %v", err)
			}
			if got != tc.want {
				t.Errorf("apiServerHost = %q, want %q", got, tc.want)
			}
		})
	}
	// A FlagSet without the flag at all (no daemonk8s) must not panic.
	if got, err := apiServerHost(pflag.NewFlagSet("empty", pflag.ContinueOnError)); got != "" || err != nil {
		t.Errorf("missing flag: got %q, %v; want \"\", nil", got, err)
	}
	if got, err := apiServerHost(nil); got != "" || err != nil {
		t.Errorf("nil FlagSet: got %q, %v; want \"\", nil", got, err)
	}
}
