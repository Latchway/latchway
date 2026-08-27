package configuration

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
)

func TestValidatorCompilesImmutablePricingCatalogs(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	configuration := configurationWithPricing(t)
	spec := objectValue(configuration, "spec")
	catalogs := objectArray(spec, "pricingCatalogs")
	firstEntry := objectArray(catalogs[0], "entries")[0]
	firstEntry["inputNanoUsdPerMillion"] = json.Number("1200.0")
	firstEntry["outputNanoUsdPerMillion"] = json.Number("4.096e3")
	delete(firstEntry, "requestNanoUsd")
	catalogs = append(catalogs, map[string]any{
		"id": "immediate", "currency": "USD",
		"entries": []any{map[string]any{
			"model": "fast", "inputNanoUsdPerMillion": json.Number("0e999"),
			"outputNanoUsdPerMillion": json.Number("1"),
			"requestNanoUsd":          json.Number("9223372036854775807"),
		}},
	})
	spec["pricingCatalogs"] = catalogs
	document, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(document, testEnvironment(), time.Unix(1, 0).UTC())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("pricing configuration rejected: report=%+v compiled=%s", report, compiled)
	}

	decoded, err := jsonsafe.Decode(compiled)
	if err != nil {
		t.Fatal(err)
	}
	compiledCatalogs := objectArray(objectValue(decoded.(map[string]any), "spec"), "pricingCatalogs")
	compiledEntry := objectArray(compiledCatalogs[0], "entries")[0]
	requestPrice, ok := compiledEntry["requestNanoUsd"].(json.Number)
	if !ok || requestPrice.String() != "0" {
		t.Fatalf("compiled request-price default = %#v", compiledEntry["requestNanoUsd"])
	}
	if stringValue(compiledCatalogs[0], "effectiveAt") != "2026-08-27T12:34:56+07:00" {
		t.Fatalf("compiled effectiveAt = %#v", compiledCatalogs[0]["effectiveAt"])
	}

	snapshot, err := newActiveSnapshot(
		"rev_00000000000000000000000000",
		"env_00000000000000000000000000",
		document,
		compiled,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog, ok := snapshot.PricingCatalog("standard")
	if !ok || catalog.ID != "standard" || catalog.Currency != "USD" || catalog.EffectiveAt == nil || len(catalog.Entries) != 1 {
		t.Fatalf("pricing catalog = %+v ok=%t", catalog, ok)
	}
	wantEffectiveAt, err := time.Parse(time.RFC3339, "2026-08-27T12:34:56+07:00")
	if err != nil {
		t.Fatal(err)
	}
	if !catalog.EffectiveAt.Equal(wantEffectiveAt) || catalog.EffectiveAt.Format(time.RFC3339) != "2026-08-27T12:34:56+07:00" {
		t.Fatalf("effectiveAt = %v", catalog.EffectiveAt)
	}
	entry, ok := catalog.Entry("fast")
	if !ok || entry.InputNanoUSDPerMillion != 1200 || entry.OutputNanoUSDPerMillion != 4096 || entry.RequestNanoUSD != 0 {
		t.Fatalf("pricing entry = %+v ok=%t", entry, ok)
	}
	entry, ok = snapshot.PricingEntry("standard", "fast")
	if !ok || entry.InputNanoUSDPerMillion != 1200 || entry.OutputNanoUSDPerMillion != 4096 {
		t.Fatalf("snapshot pricing entry = %+v ok=%t", entry, ok)
	}
	immediate, ok := snapshot.PricingCatalog("immediate")
	if !ok || immediate.EffectiveAt != nil || len(immediate.Entries) != 1 || immediate.Entries[0].RequestNanoUSD != int64(^uint64(0)>>1) {
		t.Fatalf("immediately effective catalog = %+v ok=%t", immediate, ok)
	}
	if _, ok := snapshot.PricingCatalog("missing"); ok {
		t.Fatal("unknown pricing catalog resolved")
	}
	if _, ok := snapshot.PricingEntry("standard", "missing"); ok {
		t.Fatal("unknown pricing entry resolved")
	}

	*catalog.EffectiveAt = time.Unix(0, 0).UTC()
	catalog.Entries[0].InputNanoUSDPerMillion = 1
	catalogAgain, _ := snapshot.PricingCatalog("standard")
	if !catalogAgain.EffectiveAt.Equal(wantEffectiveAt) || catalogAgain.Entries[0].InputNanoUSDPerMillion != 1200 {
		t.Fatalf("pricing catalog was mutable: %+v", catalogAgain)
	}
}

func TestValidatorRejectsInvalidPricingReferences(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		code   string
		mutate func(map[string]any)
	}{
		{
			name: "duplicate catalog identifier", code: "duplicate_identifier",
			mutate: func(spec map[string]any) {
				catalogs := objectArray(spec, "pricingCatalogs")
				spec["pricingCatalogs"] = append(catalogs, deepClone(catalogs[0]).(map[string]any))
			},
		},
		{
			name: "duplicate model entry", code: "duplicate_pricing_entry",
			mutate: func(spec map[string]any) {
				catalog := objectArray(spec, "pricingCatalogs")[0]
				entries := objectArray(catalog, "entries")
				catalog["entries"] = append(entries, deepClone(entries[0]).(map[string]any))
			},
		},
		{
			name: "entry references missing model", code: "model_reference_missing",
			mutate: func(spec map[string]any) {
				objectArray(objectArray(spec, "pricingCatalogs")[0], "entries")[0]["model"] = "missing"
			},
		},
		{
			name: "model references missing catalog", code: "pricing_reference_missing",
			mutate: func(spec map[string]any) {
				objectArray(spec, "models")[0]["pricingRef"] = "missing"
			},
		},
		{
			name: "catalog lacks referenced model", code: "pricing_entry_missing",
			mutate: func(spec map[string]any) {
				models := objectArray(spec, "models")
				second := deepClone(models[0]).(map[string]any)
				second["id"] = "other"
				delete(second, "pricingRef")
				spec["models"] = append(models, second)
				objectArray(objectArray(spec, "pricingCatalogs")[0], "entries")[0]["model"] = "other"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := configurationWithPricing(t)
			test.mutate(objectValue(configuration, "spec"))
			document, err := json.Marshal(configuration)
			if err != nil {
				t.Fatal(err)
			}
			report, compiled := validator.Validate(document, testEnvironment(), time.Unix(0, 0).UTC())
			if report.Valid || compiled != nil || !hasIssue(report.Issues, test.code) {
				t.Fatalf("invalid pricing reference compiled: report=%+v compiled=%s", report, compiled)
			}
		})
	}
}

func TestValidatorCompilesRFC3339PricingEffectiveTimes(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		raw              string
		want             string
		hasSubNanosecond bool
	}{
		{raw: "2026-08-27T12:34:56.123456789+07:00", want: "2026-08-27T05:34:56.123456789Z"},
		{
			raw: "2026-08-27T12:34:56.1234567891+07:00", want: "2026-08-27T05:34:56.123456789Z",
			hasSubNanosecond: true,
		},
		{raw: "2026-08-27T12:34:56.1234567890+07:00", want: "2026-08-27T05:34:56.123456789Z"},
		{raw: "2026-08-27t12:34:56z", want: "2026-08-27T12:34:56Z"},
		{raw: "2016-12-31T23:59:60Z", want: "2017-01-01T00:00:00Z"},
		{raw: "2017-01-01T06:59:60+07:00", want: "2017-01-01T00:00:00Z"},
		{
			raw: "2017-01-01T06:59:60.0000000001+07:00", want: "2017-01-01T00:00:00Z",
			hasSubNanosecond: true,
		},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			configuration := configurationWithPricing(t)
			spec := objectValue(configuration, "spec")
			objectArray(spec, "pricingCatalogs")[0]["effectiveAt"] = test.raw
			document, err := json.Marshal(configuration)
			if err != nil {
				t.Fatal(err)
			}
			report, compiled := validator.Validate(document, testEnvironment(), time.Unix(0, 0).UTC())
			if !report.Valid {
				t.Fatalf("schema-valid RFC3339 timestamp rejected: %+v", report.Issues)
			}
			snapshot, err := newActiveSnapshot("validation", "validation", document, compiled)
			if err != nil {
				t.Fatal(err)
			}
			catalog, ok := snapshot.PricingCatalog("standard")
			if !ok || catalog.EffectiveAt == nil || catalog.EffectiveAt.UTC().Format(time.RFC3339Nano) != test.want {
				t.Fatalf("effectiveAt = %v, want %s", catalog.EffectiveAt, test.want)
			}
			if catalog.effectiveAtRaw != test.raw || catalog.effectiveAtFloor != *catalog.EffectiveAt ||
				catalog.effectiveAtHasSubNanosecond != test.hasSubNanosecond {
				t.Fatalf(
					"exact effective metadata = {%q %v %t}",
					catalog.effectiveAtRaw, catalog.effectiveAtFloor, catalog.effectiveAtHasSubNanosecond,
				)
			}
			if got := catalog.EffectiveAfter(*catalog.EffectiveAt); got != test.hasSubNanosecond {
				t.Fatalf("EffectiveAfter(floor) = %t, want %t", got, test.hasSubNanosecond)
			}
			if catalog.EffectiveAfter(catalog.EffectiveAt.Add(time.Nanosecond)) {
				t.Fatal("EffectiveAfter(floor + 1ns) = true")
			}
		})
	}
}

func TestPricingEffectiveAtRuntimeMatchesConfiguredSchemaFormat(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"2026-08-27T12:34:56Z",
		"2026-08-27t12:34:56.123456789123z",
		"2017-01-01T06:59:60.1+07:00",
		"2016-12-31T16:59:60-07:00",
		"2026-08-27T+1:34:56Z",
		"2026-08-27T12:34:56,1Z",
		"2026-08-27T12:34:56+24:00",
		"2017-01-01T07:00:60+07:00",
		"2017-01-01T23:59:60-00:01",
		"2026-08-27T12:34:56.Z",
		"2026-08-27 12:34:56Z",
	} {
		t.Run(raw, func(t *testing.T) {
			configuration := configurationWithPricing(t)
			objectArray(objectValue(configuration, "spec"), "pricingCatalogs")[0]["effectiveAt"] = raw
			document, err := json.Marshal(configuration)
			if err != nil {
				t.Fatal(err)
			}
			schemaValid := len(validator.SchemaIssues(document)) == 0
			_, runtimeErr := parsePricingEffectiveAt(raw)
			if runtimeValid := runtimeErr == nil; runtimeValid != schemaValid {
				t.Fatalf("runtime validity = %t, schema validity = %t, error = %v", runtimeValid, schemaValid, runtimeErr)
			}
		})
	}
}

func TestValidatorRejectsInvalidPricingNumbers(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		value any
	}{
		{name: "quoted", value: "100"},
		{name: "fractional", value: json.Number("1.5")},
		{name: "negative", value: json.Number("-1")},
		{name: "overflow", value: json.Number("9223372036854775808")},
	} {
		t.Run(test.name, func(t *testing.T) {
			configuration := configurationWithPricing(t)
			spec := objectValue(configuration, "spec")
			objectArray(objectArray(spec, "pricingCatalogs")[0], "entries")[0]["inputNanoUsdPerMillion"] = test.value
			document, err := json.Marshal(configuration)
			if err != nil {
				t.Fatal(err)
			}
			report, compiled := validator.Validate(document, testEnvironment(), time.Unix(0, 0).UTC())
			if report.Valid || compiled != nil {
				t.Fatalf("invalid pricing number compiled: report=%+v compiled=%s", report, compiled)
			}
		})
	}
}

func TestActiveSnapshotRejectsCorruptPricingCatalogs(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	configuration := configurationWithPricing(t)
	document, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(document, testEnvironment(), time.Unix(0, 0).UTC())
	if !report.Valid {
		t.Fatalf("pricing configuration rejected: %+v", report.Issues)
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name:   "unknown catalog field",
			mutate: func(spec map[string]any) { objectArray(spec, "pricingCatalogs")[0]["future"] = true },
		},
		{
			name: "unknown entry field",
			mutate: func(spec map[string]any) {
				objectArray(objectArray(spec, "pricingCatalogs")[0], "entries")[0]["future"] = true
			},
		},
		{
			name:   "missing catalog identifier",
			mutate: func(spec map[string]any) { delete(objectArray(spec, "pricingCatalogs")[0], "id") },
		},
		{
			name:   "non USD currency",
			mutate: func(spec map[string]any) { objectArray(spec, "pricingCatalogs")[0]["currency"] = "EUR" },
		},
		{
			name:   "null effective time",
			mutate: func(spec map[string]any) { objectArray(spec, "pricingCatalogs")[0]["effectiveAt"] = nil },
		},
		{
			name:   "invalid effective time",
			mutate: func(spec map[string]any) { objectArray(spec, "pricingCatalogs")[0]["effectiveAt"] = "tomorrow" },
		},
		{
			name: "comma fractional effective time",
			mutate: func(spec map[string]any) {
				objectArray(spec, "pricingCatalogs")[0]["effectiveAt"] = "2026-08-27T12:34:56,1Z"
			},
		},
		{
			name: "invalid leap-second offset boundary",
			mutate: func(spec map[string]any) {
				objectArray(spec, "pricingCatalogs")[0]["effectiveAt"] = "2017-01-01T07:00:60+07:00"
			},
		},
		{
			name: "out-of-range effective-time offset",
			mutate: func(spec map[string]any) {
				objectArray(spec, "pricingCatalogs")[0]["effectiveAt"] = "2026-08-27T12:34:56+24:00"
			},
		},
		{
			name:   "empty entries",
			mutate: func(spec map[string]any) { objectArray(spec, "pricingCatalogs")[0]["entries"] = []any{} },
		},
		{
			name: "too many entries",
			mutate: func(spec map[string]any) {
				catalog := objectArray(spec, "pricingCatalogs")[0]
				entry := objectArray(catalog, "entries")[0]
				entries := make([]any, maximumPricingCatalogEntries+1)
				for index := range entries {
					entries[index] = deepClone(entry).(map[string]any)
				}
				catalog["entries"] = entries
			},
		},
		{
			name: "too many catalogs",
			mutate: func(spec map[string]any) {
				catalog := objectArray(spec, "pricingCatalogs")[0]
				catalogs := make([]any, maximumPricingCatalogs+1)
				for index := range catalogs {
					copy := deepClone(catalog).(map[string]any)
					copy["id"] = fmt.Sprintf("catalog_%02d", index)
					catalogs[index] = copy
				}
				spec["pricingCatalogs"] = catalogs
			},
		},
		{
			name: "duplicate catalog identifier",
			mutate: func(spec map[string]any) {
				catalogs := objectArray(spec, "pricingCatalogs")
				spec["pricingCatalogs"] = append(catalogs, deepClone(catalogs[0]).(map[string]any))
			},
		},
		{
			name: "duplicate model entry",
			mutate: func(spec map[string]any) {
				catalog := objectArray(spec, "pricingCatalogs")[0]
				entries := objectArray(catalog, "entries")
				catalog["entries"] = append(entries, deepClone(entries[0]).(map[string]any))
			},
		},
		{
			name: "entry references unknown model",
			mutate: func(spec map[string]any) {
				objectArray(objectArray(spec, "pricingCatalogs")[0], "entries")[0]["model"] = "missing"
			},
		},
		{
			name:   "model references unknown catalog",
			mutate: func(spec map[string]any) { objectArray(spec, "models")[0]["pricingRef"] = "missing" },
		},
		{
			name: "missing model entry",
			mutate: func(spec map[string]any) {
				models := objectArray(spec, "models")
				second := deepClone(models[0]).(map[string]any)
				second["id"] = "other"
				delete(second, "pricingRef")
				spec["models"] = append(models, second)
				objectArray(objectArray(spec, "pricingCatalogs")[0], "entries")[0]["model"] = "other"
			},
		},
		{
			name: "missing model field",
			mutate: func(spec map[string]any) {
				delete(objectArray(objectArray(spec, "pricingCatalogs")[0], "entries")[0], "model")
			},
		},
		{
			name: "missing input price",
			mutate: func(spec map[string]any) {
				delete(objectArray(objectArray(spec, "pricingCatalogs")[0], "entries")[0], "inputNanoUsdPerMillion")
			},
		},
		{
			name: "missing output price",
			mutate: func(spec map[string]any) {
				delete(objectArray(objectArray(spec, "pricingCatalogs")[0], "entries")[0], "outputNanoUsdPerMillion")
			},
		},
		{
			name: "missing normalized request price",
			mutate: func(spec map[string]any) {
				delete(objectArray(objectArray(spec, "pricingCatalogs")[0], "entries")[0], "requestNanoUsd")
			},
		},
		{
			name: "quoted integer",
			mutate: func(spec map[string]any) {
				objectArray(objectArray(spec, "pricingCatalogs")[0], "entries")[0]["inputNanoUsdPerMillion"] = "100"
			},
		},
		{
			name: "null integer",
			mutate: func(spec map[string]any) {
				objectArray(objectArray(spec, "pricingCatalogs")[0], "entries")[0]["inputNanoUsdPerMillion"] = nil
			},
		},
		{
			name: "fractional integer",
			mutate: func(spec map[string]any) {
				objectArray(objectArray(spec, "pricingCatalogs")[0], "entries")[0]["inputNanoUsdPerMillion"] = json.Number("1.5")
			},
		},
		{
			name: "negative integer",
			mutate: func(spec map[string]any) {
				objectArray(objectArray(spec, "pricingCatalogs")[0], "entries")[0]["inputNanoUsdPerMillion"] = json.Number("-1")
			},
		},
		{
			name: "integer overflow",
			mutate: func(spec map[string]any) {
				objectArray(objectArray(spec, "pricingCatalogs")[0], "entries")[0]["inputNanoUsdPerMillion"] = json.Number("9223372036854775808")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoded, decodeErr := jsonsafe.Decode(compiled)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			root := decoded.(map[string]any)
			test.mutate(objectValue(root, "spec"))
			corrupt, marshalErr := json.Marshal(root)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if _, snapshotErr := newActiveSnapshot(
				"rev_00000000000000000000000000",
				"env_00000000000000000000000000",
				document,
				corrupt,
			); snapshotErr == nil {
				t.Fatal("corrupt pricing catalog was accepted")
			}
		})
	}
}

func TestCompiledPricingRejectsDuplicateJSONMembers(t *testing.T) {
	t.Parallel()

	var catalog compiledPricingCatalog
	if err := json.Unmarshal([]byte(`{"id":"standard","id":"other","currency":"USD","entries":[]}`), &catalog); err == nil {
		t.Fatal("duplicate pricing catalog member was accepted")
	}
	var entry compiledPricingEntry
	if err := json.Unmarshal([]byte(`{"model":"fast","inputNanoUsdPerMillion":1,"inputNanoUsdPerMillion":2,"outputNanoUsdPerMillion":3,"requestNanoUsd":0}`), &entry); err == nil {
		t.Fatal("duplicate pricing entry member was accepted")
	}
}

func configurationWithPricing(t *testing.T) map[string]any {
	t.Helper()
	configuration := configurationObject(t)
	spec := objectValue(configuration, "spec")
	objectArray(spec, "models")[0]["pricingRef"] = "standard"
	spec["pricingCatalogs"] = []any{map[string]any{
		"id": "standard", "currency": "USD", "effectiveAt": "2026-08-27T12:34:56+07:00",
		"entries": []any{map[string]any{
			"model": "fast", "inputNanoUsdPerMillion": json.Number("1000"),
			"outputNanoUsdPerMillion": json.Number("2000"), "requestNanoUsd": json.Number("10"),
		}},
	}}
	return configuration
}
