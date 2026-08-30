package dataplane

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
)

// replayableRequest owns the exact client body and a detached request
// template after protocol inspection. Every physical attempt receives fresh
// URL, header, body-reader, and context state; provider rewrites can never
// bleed into a later route.
type replayableRequest struct {
	template *http.Request
	body     []byte
}

func captureReplayableRequest(request *http.Request) (replayableRequest, error) {
	if request == nil || request.URL == nil || request.Context() == nil {
		return replayableRequest{}, errInvalidConfiguration
	}
	var body []byte
	if request.Body != nil && request.Body != http.NoBody {
		limited := io.LimitReader(request.Body, maximumRequestBodyLimit+1)
		read, err := io.ReadAll(limited)
		if err != nil {
			return replayableRequest{}, err
		}
		if int64(len(read)) > maximumRequestBodyLimit {
			return replayableRequest{}, errors.New("request body exceeds replay limit")
		}
		body = append([]byte(nil), read...)
	}

	template := request.Clone(request.Context())
	requestURL := *request.URL
	template.URL = &requestURL
	template.Header = request.Header.Clone()
	template.Trailer = nil
	template.TransferEncoding = nil
	template.Body = http.NoBody
	template.GetBody = nil
	template.ContentLength = int64(len(body))

	// Reinstall an independent reader for any caller that still owns the
	// incoming request. The immutable snapshot retains a separate slice.
	reinstallRequestBody(request, body)
	return replayableRequest{template: template, body: body}, nil
}

func (replay replayableRequest) New(ctx context.Context) (*http.Request, error) {
	if replay.template == nil || replay.template.URL == nil || ctx == nil {
		return nil, errInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	request := replay.template.Clone(ctx)
	requestURL := *replay.template.URL
	request.URL = &requestURL
	request.Header = replay.template.Header.Clone()
	request.Trailer = nil
	request.TransferEncoding = nil
	reinstallRequestBody(request, replay.body)
	return request, nil
}

func reinstallRequestBody(request *http.Request, body []byte) {
	if len(body) == 0 {
		request.Body = http.NoBody
		request.ContentLength = 0
		request.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
}
