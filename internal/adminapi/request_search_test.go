package adminapi

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestParseRequestListFilterClientRequestID(t *testing.T) {
	t.Parallel()
	for value, valid := range map[string]bool{
		"order-2026.10:retry_1": true,
		"order/2026":            false,
		"abc":                   false,
		"-leading-dash":         false,
		"has space here":        false,
	} {
		request, err := http.NewRequest(http.MethodGet, "/admin/v1/requests?"+url.Values{"client_request_id": {value}}.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		filter, ok := parseRequestListFilter(request)
		if ok != valid || (ok && filter.clientRequest != value) {
			t.Fatalf("client_request_id %q ok=%t filter=%q", value, ok, filter.clientRequest)
		}
	}
}

// assertRequestSearch covers the client-request filter, platform and
// correlation fields, capped totals and facets against the shared fixture.
func assertRequestSearch(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	handler http.Handler,
	cookie *http.Cookie,
	baseQuery, environmentID, requestID, filteredQuery, start, end string,
) {
	t.Helper()
	if _, err := pool.Exec(ctx, `UPDATE logical_requests SET client_request_id = 'checkout:2026-10-08.a1'
		WHERE logical_request_id = $1`, requestID); err != nil {
		t.Fatal(err)
	}
	byClient := performGET(handler, "/admin/v1/requests"+baseQuery+"&client_request_id=checkout%3A2026-10-08.a1&include_total=true", cookie)
	if byClient.Code != http.StatusOK || !bytes.Contains(byClient.Body.Bytes(), []byte(requestID)) ||
		!bytes.Contains(byClient.Body.Bytes(), []byte(`"client_request_id":"checkout:2026-10-08.a1"`)) ||
		!bytes.Contains(byClient.Body.Bytes(), []byte(`"platform":"ios"`)) ||
		!bytes.Contains(byClient.Body.Bytes(), []byte(`"total":{"capped":false,"count":1}`)) {
		t.Fatalf("client request search status/body=%d %s", byClient.Code, byClient.Body.String())
	}
	otherClient := performGET(handler, "/admin/v1/requests"+baseQuery+"&client_request_id=checkout%3A2026-10-08.zz&include_total=true", cookie)
	if otherClient.Code != http.StatusOK || bytes.Contains(otherClient.Body.Bytes(), []byte(requestID)) ||
		!bytes.Contains(otherClient.Body.Bytes(), []byte(`"total":{"capped":false,"count":0}`)) {
		t.Fatalf("non-matching client request search status/body=%d %s", otherClient.Code, otherClient.Body.String())
	}
	filteredTotal := performGET(handler, "/admin/v1/requests"+filteredQuery+"&include_total=true", cookie)
	if filteredTotal.Code != http.StatusOK || !bytes.Contains(filteredTotal.Body.Bytes(), []byte(`"total":{"capped":false,"count":1}`)) {
		t.Fatalf("filtered request total status/body=%d %s", filteredTotal.Code, filteredTotal.Body.String())
	}
	for name, query := range map[string]string{
		"short client id":     "&client_request_id=abc",
		"unsafe client id":    "&client_request_id=" + url.QueryEscape("has space here"),
		"include_total false": "&include_total=false",
	} {
		if response := performGET(handler, "/admin/v1/requests"+baseQuery+query, cookie); response.Code != http.StatusBadRequest {
			t.Fatalf("%s status/body=%d %s", name, response.Code, response.Body.String())
		}
	}

	facetsQuery := "/admin/v1/requests/facets?" + url.Values{
		"environment_id": {environmentID}, "start": {start}, "end": {end},
	}.Encode()
	facets := performGET(handler, facetsQuery, cookie)
	if facets.Code != http.StatusOK {
		t.Fatalf("request facets status/body=%d %s", facets.Code, facets.Body.String())
	}
	var document requestFacetsDocument
	decodeResponse(t, facets, &document)
	facetValue := func(facet, value string) int64 {
		for _, item := range document.Facets[facet].Values {
			if item.Value == value {
				return item.Count
			}
		}
		return 0
	}
	if document.Requests != 1 || document.EnvironmentID != environmentID || len(document.Facets) != len(requestFacetNames) ||
		facetValue("status", "succeeded") != 1 || facetValue("feature", "assistant") != 1 ||
		facetValue("platform", "ios") != 1 || facetValue("upstream", "openai") != 1 ||
		facetValue("route", "primary") != 1 || facetValue("component_kind", "main_app") != 1 ||
		facetValue("trust_source", "debug") != 1 || len(document.Facets["error_code"].Values) != 0 {
		t.Fatalf("request facets = %s", facets.Body.String())
	}
	limited := performGET(handler, facetsQuery+"&limit=1", cookie)
	if limited.Code != http.StatusOK {
		t.Fatalf("limited request facets status/body=%d %s", limited.Code, limited.Body.String())
	}
	startTime, err := time.Parse(time.RFC3339, start)
	if err != nil {
		t.Fatal(err)
	}
	for name, query := range map[string]string{
		"missing start": "/admin/v1/requests/facets?" + url.Values{"environment_id": {environmentID}, "end": {end}}.Encode(),
		"too long": "/admin/v1/requests/facets?" + url.Values{
			"environment_id": {environmentID}, "start": {startTime.Add(-91 * 24 * time.Hour).Format(time.RFC3339)}, "end": {end},
		}.Encode(),
		"reversed": "/admin/v1/requests/facets?" + url.Values{"environment_id": {environmentID}, "start": {end}, "end": {start}}.Encode(),
		"limit":    facetsQuery + "&limit=0",
		"unknown":  facetsQuery + "&feature=assistant",
	} {
		if response := performGET(handler, query, cookie); response.Code != http.StatusBadRequest {
			t.Fatalf("%s facets status/body=%d %s", name, response.Code, response.Body.String())
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE logical_requests SET client_request_id = NULL
		WHERE logical_request_id = $1`, requestID); err != nil {
		t.Fatal(err)
	}
}
