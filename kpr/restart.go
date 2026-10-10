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
	"log/slog"
	"time"
)

// restartPolicy bounds how fast a crashed long-runner is restarted. settled is
// how long a run must last before its exit is treated as a fresh failure rather
// than a continuation of a crash loop.
type restartPolicy struct {
	min, max, settled time.Duration
}

var defaultRestart = restartPolicy{min: time.Second, max: 30 * time.Second, settled: time.Minute}

// runWithRestart runs a long-runner until ctx is done, restarting it with capped
// exponential backoff whenever it returns.
//
// The alternative to this is what kpr used to do: log the error and leave the
// goroutine dead. The process stayed up, the pod stayed Ready, and the datapath
// kept whatever Service state it had at the moment of the exit -- for 25 hours,
// on a stand where the apiserver ClusterIP was briefly unreachable during boot.
// A transient apiserver error on startup is a retry, not a verdict.
func runWithRestart(ctx context.Context, what string, p restartPolicy,
	run func(context.Context) error, logger *slog.Logger) {
	delay := p.min
	for {
		started := time.Now()
		err := run(ctx)
		ran := time.Since(started)
		if ctx.Err() != nil {
			return // orderly shutdown, not a crash
		}
		if ran >= p.settled {
			delay = p.min // it was up and healthy; do not inherit an old backoff
		}
		logger.Error(what+" exited; restarting",
			"err", err, "ran_for", ran.Truncate(time.Millisecond), "restart_in", delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay *= 2; delay > p.max {
			delay = p.max
		}
	}
}
