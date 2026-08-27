package configuration

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
)

const (
	maximumPricingCatalogs       = 64
	maximumPricingCatalogEntries = 256
)

// compiledPricingCatalog and compiledPricingEntry retain enough information
// to recheck the normalized artifact independently at activation and read
// time. In particular, numeric JSON forms are never decoded through float64,
// and an omitted effectiveAt remains distinguishable from an explicit value.
type compiledPricingCatalog struct {
	ID             string
	Currency       string
	EffectiveAt    string
	hasEffectiveAt bool
	Entries        []compiledPricingEntry
}

type compiledPricingEntry struct {
	ModelID                 string
	InputNanoUSDPerMillion  int64
	OutputNanoUSDPerMillion int64
	RequestNanoUSD          int64
}

func (catalog *compiledPricingCatalog) UnmarshalJSON(encoded []byte) error {
	*catalog = compiledPricingCatalog{}
	fields, err := strictPricingObject(encoded, map[string]struct{}{
		"id": {}, "currency": {}, "effectiveAt": {}, "entries": {},
	})
	if err != nil {
		return err
	}
	for _, required := range []string{"id", "currency", "entries"} {
		if _, ok := fields[required]; !ok {
			return ErrInvalid
		}
	}
	if err := json.Unmarshal(fields["id"], &catalog.ID); err != nil {
		return ErrInvalid
	}
	if err := json.Unmarshal(fields["currency"], &catalog.Currency); err != nil {
		return ErrInvalid
	}
	if effectiveAt, ok := fields["effectiveAt"]; ok {
		catalog.hasEffectiveAt = true
		if err := json.Unmarshal(effectiveAt, &catalog.EffectiveAt); err != nil {
			return ErrInvalid
		}
	}
	if err := json.Unmarshal(fields["entries"], &catalog.Entries); err != nil {
		return ErrInvalid
	}
	return nil
}

func (entry *compiledPricingEntry) UnmarshalJSON(encoded []byte) error {
	*entry = compiledPricingEntry{}
	fields, err := strictPricingObject(encoded, map[string]struct{}{
		"model": {}, "inputNanoUsdPerMillion": {}, "outputNanoUsdPerMillion": {}, "requestNanoUsd": {},
	})
	if err != nil {
		return err
	}
	for _, required := range []string{"model", "inputNanoUsdPerMillion", "outputNanoUsdPerMillion", "requestNanoUsd"} {
		if _, ok := fields[required]; !ok {
			return ErrInvalid
		}
	}
	if err := json.Unmarshal(fields["model"], &entry.ModelID); err != nil {
		return ErrInvalid
	}
	var ok bool
	entry.InputNanoUSDPerMillion, ok = compiledPricingInteger(fields["inputNanoUsdPerMillion"])
	if !ok {
		return ErrInvalid
	}
	entry.OutputNanoUSDPerMillion, ok = compiledPricingInteger(fields["outputNanoUsdPerMillion"])
	if !ok {
		return ErrInvalid
	}
	entry.RequestNanoUSD, ok = compiledPricingInteger(fields["requestNanoUsd"])
	if !ok {
		return ErrInvalid
	}
	return nil
}

func strictPricingObject(encoded []byte, allowed map[string]struct{}) (map[string]json.RawMessage, error) {
	decoded, err := jsonsafe.Decode(encoded)
	if err != nil {
		return nil, ErrInvalid
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return nil, ErrInvalid
	}
	for field := range object {
		if _, ok := allowed[field]; !ok {
			return nil, ErrInvalid
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil || fields == nil {
		return nil, ErrInvalid
	}
	return fields, nil
}

func compiledPricingInteger(raw json.RawMessage) (int64, bool) {
	return compiledLimitInteger(raw, true)
}

func runtimePricingCatalog(raw compiledPricingCatalog, models map[string]Model) (PricingCatalog, error) {
	if !runtimeIdentifierPattern.MatchString(raw.ID) || raw.Currency != "USD" ||
		len(raw.Entries) == 0 || len(raw.Entries) > maximumPricingCatalogEntries {
		return PricingCatalog{}, ErrInvalid
	}
	catalog := PricingCatalog{
		ID: raw.ID, Currency: raw.Currency,
		Entries: make([]PricingEntry, 0, len(raw.Entries)),
	}
	if raw.hasEffectiveAt {
		effectiveAt, err := parsePricingEffectiveAt(raw.EffectiveAt)
		if err != nil {
			return PricingCatalog{}, ErrInvalid
		}
		catalog.EffectiveAt = &effectiveAt
	}
	seenModels := make(map[string]struct{}, len(raw.Entries))
	for _, rawEntry := range raw.Entries {
		if !runtimeIdentifierPattern.MatchString(rawEntry.ModelID) ||
			rawEntry.InputNanoUSDPerMillion < 0 || rawEntry.OutputNanoUSDPerMillion < 0 || rawEntry.RequestNanoUSD < 0 {
			return PricingCatalog{}, ErrInvalid
		}
		if _, ok := models[rawEntry.ModelID]; !ok {
			return PricingCatalog{}, ErrInvalid
		}
		if _, duplicate := seenModels[rawEntry.ModelID]; duplicate {
			return PricingCatalog{}, ErrInvalid
		}
		seenModels[rawEntry.ModelID] = struct{}{}
		catalog.Entries = append(catalog.Entries, PricingEntry{
			ModelID:                 rawEntry.ModelID,
			InputNanoUSDPerMillion:  rawEntry.InputNanoUSDPerMillion,
			OutputNanoUSDPerMillion: rawEntry.OutputNanoUSDPerMillion,
			RequestNanoUSD:          rawEntry.RequestNanoUSD,
		})
	}
	return catalog, nil
}

// parsePricingEffectiveAt accepts the complete RFC 3339 date-time surface
// admitted by the public schema, including lower-case t/z and leap seconds.
// Go's time parser does not represent leap seconds, so their effective instant
// is normalized to the first instant of the following minute.
func parsePricingEffectiveAt(raw string) (time.Time, error) {
	if len(raw) < len("2006-01-02T15:04:05Z") {
		return time.Time{}, ErrInvalid
	}
	normalized := raw
	if normalized[10] == 't' {
		normalized = normalized[:10] + "T" + normalized[11:]
	}
	if strings.HasSuffix(normalized, "z") {
		normalized = normalized[:len(normalized)-1] + "Z"
	}
	leapSecond := normalized[17:19] == "60"
	if leapSecond {
		normalized = normalized[:17] + "59" + normalized[19:]
	}
	effectiveAt, err := time.Parse(time.RFC3339, normalized)
	if err != nil {
		return time.Time{}, ErrInvalid
	}
	if leapSecond {
		utc := effectiveAt.UTC()
		if utc.Hour() != 23 || utc.Minute() != 59 {
			return time.Time{}, ErrInvalid
		}
		effectiveAt = effectiveAt.Add(time.Second)
	}
	return effectiveAt, nil
}
