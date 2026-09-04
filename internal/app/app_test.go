package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/config"
)

func TestSelectRoleDefinesExactProcessResponsibilities(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		role config.Role
		want roleSelection
	}{
		{role: config.RoleAPI, want: roleSelection{api: true}},
		{role: config.RoleWorker, want: roleSelection{worker: true}},
		{role: config.RoleAll, want: roleSelection{api: true, worker: true}},
	} {
		got, err := selectRole(test.role)
		if err != nil || got != test.want {
			t.Fatalf("selectRole(%q) = %#v, %v; want %#v", test.role, got, err, test.want)
		}
	}
	if _, err := selectRole(config.Role("unknown")); err == nil {
		t.Fatal("unknown role was accepted")
	}
}

func TestReservationConcurrencyPreservesRegularPoolHeadroom(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		regularConnections int32
		want               int64
	}{
		{regularConnections: 1, want: 1},
		{regularConnections: 2, want: 1},
		{regularConnections: 3, want: 1},
		{regularConnections: 4, want: 2},
		{regularConnections: 24, want: 12},
	} {
		if got := reservationConcurrency(test.regularConnections); got != test.want {
			t.Fatalf("reservationConcurrency(%d) = %d, want %d", test.regularConnections, got, test.want)
		}
	}
}

func TestRunRoleAPIStartsOnlyHTTP(t *testing.T) {
	t.Parallel()

	want := errors.New("HTTP stopped")
	api := &fakeAPIRuntime{run: func(context.Context, time.Duration) error { return want }}
	if err := runRole(context.Background(), config.RoleAPI, time.Second, api, nil); !errors.Is(err, want) {
		t.Fatalf("runRole() error = %v, want %v", err, want)
	}
	if got := api.calls(); got != 1 {
		t.Fatalf("HTTP calls = %d, want 1", got)
	}
	if err := runRole(context.Background(), config.RoleAPI, time.Second, api, &fakeWorkerRuntime{}); err == nil {
		t.Fatal("API role accepted worker dependencies")
	}
}

func TestRunRoleWorkerStartsOnlyJobs(t *testing.T) {
	t.Parallel()

	want := errors.New("worker stopped")
	jobs := &fakeWorkerRuntime{run: func(context.Context) error { return want }}
	if err := runRole(context.Background(), config.RoleWorker, time.Second, nil, jobs); !errors.Is(err, want) {
		t.Fatalf("runRole() error = %v, want %v", err, want)
	}
	if got := jobs.calls(); got != 1 {
		t.Fatalf("worker calls = %d, want 1", got)
	}
	if err := runRole(context.Background(), config.RoleWorker, time.Second, &fakeAPIRuntime{}, jobs); err == nil {
		t.Fatal("worker role accepted HTTP dependencies")
	}
}

func TestRunRoleTreatsUnpromptedStandaloneExitAsFatal(t *testing.T) {
	t.Parallel()

	if err := runRole(context.Background(), config.RoleAPI, time.Second, &fakeAPIRuntime{}, nil); err == nil ||
		!strings.Contains(err.Error(), "stopped unexpectedly") {
		t.Fatalf("API runRole() error = %v, want unexpected-stop failure", err)
	}
	if err := runRole(context.Background(), config.RoleWorker, time.Second, nil, &fakeWorkerRuntime{}); err == nil ||
		!strings.Contains(err.Error(), "stopped unexpectedly") {
		t.Fatalf("worker runRole() error = %v, want unexpected-stop failure", err)
	}
}

func TestRunRoleAllCancellationDrainsHTTPAndWorker(t *testing.T) {
	t.Parallel()

	apiStarted := make(chan struct{})
	apiStopped := make(chan struct{})
	workerStarted := make(chan struct{})
	workerStopped := make(chan struct{})
	api := &fakeAPIRuntime{run: func(ctx context.Context, _ time.Duration) error {
		close(apiStarted)
		<-ctx.Done()
		close(apiStopped)
		return nil
	}}
	jobs := &fakeWorkerRuntime{run: func(ctx context.Context) error {
		close(workerStarted)
		<-ctx.Done()
		close(workerStopped)
		return nil
	}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runRole(ctx, config.RoleAll, time.Second, api, jobs) }()
	waitSignal(t, apiStarted, "HTTP start")
	waitSignal(t, workerStarted, "worker start")
	cancel()
	if err := waitAppRuntime(t, done); err != nil {
		t.Fatalf("runRole() error = %v", err)
	}
	waitSignal(t, apiStopped, "HTTP drain")
	waitSignal(t, workerStopped, "worker stop")
}

func TestRunRoleAllWorkerFailureCancelsAndDrainsHTTP(t *testing.T) {
	t.Parallel()

	apiStarted := make(chan struct{})
	apiStopped := make(chan struct{})
	releaseWorker := make(chan struct{})
	api := &fakeAPIRuntime{run: func(ctx context.Context, _ time.Duration) error {
		close(apiStarted)
		<-ctx.Done()
		close(apiStopped)
		return nil
	}}
	want := errors.New("fatal worker infrastructure failure")
	jobs := &fakeWorkerRuntime{run: func(context.Context) error {
		<-releaseWorker
		return want
	}}

	done := make(chan error, 1)
	go func() {
		done <- runRole(context.Background(), config.RoleAll, time.Second, api, jobs)
	}()
	waitSignal(t, apiStarted, "HTTP start")
	close(releaseWorker)
	err := waitAppRuntime(t, done)
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "worker runtime") {
		t.Fatalf("runRole() error = %v, want wrapped worker failure", err)
	}
	waitSignal(t, apiStopped, "HTTP drain after worker failure")
}

func TestRunRoleAllReportsHTTPDrainDeadlineAfterParentCancellation(t *testing.T) {
	t.Parallel()

	apiStarted := make(chan struct{})
	workerStarted := make(chan struct{})
	drainFailure := fmt.Errorf("graceful shutdown: %w", context.DeadlineExceeded)
	api := &fakeAPIRuntime{run: func(ctx context.Context, _ time.Duration) error {
		close(apiStarted)
		<-ctx.Done()
		return drainFailure
	}}
	jobs := &fakeWorkerRuntime{run: func(ctx context.Context) error {
		close(workerStarted)
		<-ctx.Done()
		return nil
	}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runRole(ctx, config.RoleAll, time.Second, api, jobs) }()
	waitSignal(t, apiStarted, "HTTP start")
	waitSignal(t, workerStarted, "worker start")
	cancel()
	err := waitAppRuntime(t, done)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "HTTP runtime") {
		t.Fatalf("runRole() error = %v, want wrapped HTTP drain deadline", err)
	}
}

func TestRunRoleRejectsIncompleteOrCrossRoleDependencies(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	api := &fakeAPIRuntime{}
	jobs := &fakeWorkerRuntime{}
	for _, test := range []struct {
		name string
		role config.Role
		api  apiRuntime
		jobs workerRuntime
	}{
		{name: "API missing", role: config.RoleAPI},
		{name: "worker missing", role: config.RoleWorker},
		{name: "all missing API", role: config.RoleAll, jobs: jobs},
		{name: "all missing worker", role: config.RoleAll, api: api},
		{name: "unknown", role: config.Role("invalid"), api: api, jobs: jobs},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := runRole(ctx, test.role, time.Second, test.api, test.jobs); err == nil {
				t.Fatal("runRole() accepted invalid dependencies")
			}
		})
	}
}

type fakeAPIRuntime struct {
	mu       sync.Mutex
	run      func(context.Context, time.Duration) error
	runCalls int
}

func (runtime *fakeAPIRuntime) Run(ctx context.Context, timeout time.Duration) error {
	runtime.mu.Lock()
	runtime.runCalls++
	run := runtime.run
	runtime.mu.Unlock()
	if run == nil {
		return nil
	}
	return run(ctx, timeout)
}

func (runtime *fakeAPIRuntime) calls() int {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.runCalls
}

type fakeWorkerRuntime struct {
	mu       sync.Mutex
	run      func(context.Context) error
	runCalls int
}

func (runtime *fakeWorkerRuntime) Run(ctx context.Context) error {
	runtime.mu.Lock()
	runtime.runCalls++
	run := runtime.run
	runtime.mu.Unlock()
	if run == nil {
		return nil
	}
	return run(ctx)
}

func (runtime *fakeWorkerRuntime) calls() int {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.runCalls
}

func waitSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func waitAppRuntime(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatal("process runtime did not stop")
		return nil
	}
}
