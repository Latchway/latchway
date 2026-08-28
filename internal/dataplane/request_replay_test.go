package dataplane

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReplayableRequestProducesDetachedExactAttempts(t *testing.T) {
	t.Parallel()

	original := httptest.NewRequest(http.MethodPost, "https://gateway.example/v1/responses", strings.NewReader("exact-body"))
	original.Header["X-Test"] = []string{"one"}
	replay, err := captureReplayableRequest(original)
	if err != nil {
		t.Fatal(err)
	}
	first, err := replay.New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := replay.New(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	first.Header.Set("X-Test", "changed")
	first.URL.Path = "/provider/changed"
	firstBody, _ := io.ReadAll(first.Body)
	secondBody, _ := io.ReadAll(second.Body)
	originalBody, _ := io.ReadAll(original.Body)
	if string(firstBody) != "exact-body" || string(secondBody) != "exact-body" || string(originalBody) != "exact-body" {
		t.Fatalf("attempt/original bodies = %q/%q/%q", firstBody, secondBody, originalBody)
	}
	if second.Header.Get("X-Test") != "one" || second.URL.Path != "/v1/responses" ||
		original.Header.Get("X-Test") != "one" || original.URL.Path != "/v1/responses" {
		t.Fatalf("request snapshot aliases: first=%#v second=%#v original=%#v", first, second, original)
	}
	fromGetBody, err := second.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	defer fromGetBody.Close()
	got, _ := io.ReadAll(fromGetBody)
	if string(got) != "exact-body" {
		t.Fatalf("GetBody() = %q", got)
	}
}

func TestReplayableRequestHandlesEmptyBodiesAndCancellation(t *testing.T) {
	t.Parallel()

	original := httptest.NewRequest(http.MethodGet, "https://gateway.example/resource", nil)
	replay, err := captureReplayableRequest(original)
	if err != nil {
		t.Fatal(err)
	}
	request, err := replay.New(context.Background())
	if err != nil || request.Body != http.NoBody || request.ContentLength != 0 {
		t.Fatalf("empty replay = %#v, %v", request, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := replay.New(ctx); err == nil {
		t.Fatal("canceled replay context accepted")
	}
}
