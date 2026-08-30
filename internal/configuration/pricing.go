package configuration

import (
	"encoding/json"
	"fmt"
	"strconv"
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
		floor := effectiveAt.floor
		catalog.EffectiveAt = &floor
		catalog.effectiveAtRaw = effectiveAt.raw
		catalog.effectiveAtFloor = effectiveAt.floor
		catalog.effectiveAtHasSubNanosecond = effectiveAt.hasSubNanosecond
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
		catalog.Entries = append(catalog.Entries, PricingEntry(rawEntry))
	}
	return catalog, nil
}

type pricingEffectiveInstant struct {
	raw              string
	floor            time.Time
	hasSubNanosecond bool
}

// parsePricingEffectiveAt mirrors the configured JSON-Schema date-time format
// validator, including lower-case t/z, numeric offsets, arbitrary dot-separated
// fractional precision, and leap seconds. Go's time.Time stores the exact floor
// at nanosecond precision; raw plus hasSubNanosecond retain the remaining
// significance so callers never activate a catalog early.
func parsePricingEffectiveAt(raw string) (pricingEffectiveInstant, error) {
	lexeme, err := parsePricingDateTimeLexeme(raw)
	if err != nil {
		return pricingEffectiveInstant{}, err
	}
	second := lexeme.second
	if lexeme.leapSecond {
		second = 59
	}
	zone := "Z"
	if !lexeme.zulu {
		zone = fmt.Sprintf("%c%02d:%02d", lexeme.zoneSign, lexeme.zoneHour, lexeme.zoneMinute)
	}
	normalized := fmt.Sprintf(
		"%sT%02d:%02d:%02d", raw[:10], lexeme.hour, lexeme.minute, second,
	)
	if lexeme.fraction != "" {
		normalized += "." + lexeme.fraction
	}
	normalized += zone
	floor, parseErr := time.Parse(time.RFC3339, normalized)
	if parseErr != nil {
		return pricingEffectiveInstant{}, ErrInvalid
	}
	if lexeme.leapSecond {
		floor = floor.Add(time.Second)
	}
	hasSubNanosecond := false
	if len(lexeme.fraction) > 9 {
		for _, digit := range lexeme.fraction[9:] {
			if digit != '0' {
				hasSubNanosecond = true
				break
			}
		}
	}
	return pricingEffectiveInstant{
		raw: raw, floor: floor, hasSubNanosecond: hasSubNanosecond,
	}, nil
}

type pricingDateTimeLexeme struct {
	hour       int
	minute     int
	second     int
	fraction   string
	zulu       bool
	zoneSign   byte
	zoneHour   int
	zoneMinute int
	leapSecond bool
}

func parsePricingDateTimeLexeme(raw string) (pricingDateTimeLexeme, error) {
	if len(raw) < len("2006-01-02T15:04:05Z") || (raw[10] != 'T' && raw[10] != 't') {
		return pricingDateTimeLexeme{}, ErrInvalid
	}
	if _, err := time.Parse("2006-01-02", raw[:10]); err != nil {
		return pricingDateTimeLexeme{}, ErrInvalid
	}
	clock := raw[11:]
	if len(clock) < len("15:04:05Z") || clock[2] != ':' || clock[5] != ':' {
		return pricingDateTimeLexeme{}, ErrInvalid
	}
	fields := [3]int{}
	for index, token := range []string{clock[:2], clock[3:5], clock[6:8]} {
		value, err := strconv.Atoi(token)
		if err != nil || value < 0 {
			return pricingDateTimeLexeme{}, ErrInvalid
		}
		fields[index] = value
	}
	if fields[0] > 23 || fields[1] > 59 || fields[2] > 60 {
		return pricingDateTimeLexeme{}, ErrInvalid
	}
	lexeme := pricingDateTimeLexeme{
		hour: fields[0], minute: fields[1], second: fields[2],
		leapSecond: fields[2] == 60,
	}
	remainder := clock[8:]
	if strings.HasPrefix(remainder, ".") {
		digits := 0
		for digits+1 < len(remainder) && isASCIIDigit(remainder[digits+1]) {
			digits++
		}
		if digits == 0 {
			return pricingDateTimeLexeme{}, ErrInvalid
		}
		lexeme.fraction = remainder[1 : 1+digits]
		remainder = remainder[1+digits:]
	}
	if remainder == "Z" || remainder == "z" {
		lexeme.zulu = true
	} else {
		if len(remainder) != 6 || (remainder[0] != '+' && remainder[0] != '-') || remainder[3] != ':' {
			return pricingDateTimeLexeme{}, ErrInvalid
		}
		zoneHour, hourErr := strconv.Atoi(remainder[1:3])
		zoneMinute, minuteErr := strconv.Atoi(remainder[4:6])
		if hourErr != nil || minuteErr != nil || zoneHour < 0 || zoneHour > 23 || zoneMinute < 0 || zoneMinute > 59 {
			return pricingDateTimeLexeme{}, ErrInvalid
		}
		lexeme.zoneSign = remainder[0]
		lexeme.zoneHour = zoneHour
		lexeme.zoneMinute = zoneMinute
	}
	if lexeme.leapSecond {
		utcMinutes := lexeme.hour*60 + lexeme.minute
		if !lexeme.zulu {
			offset := lexeme.zoneHour*60 + lexeme.zoneMinute
			if lexeme.zoneSign == '+' {
				utcMinutes -= offset
			} else {
				utcMinutes += offset
			}
			if utcMinutes < 0 {
				utcMinutes += 24 * 60
			}
		}
		if utcMinutes/60 != 23 || utcMinutes%60 != 59 {
			return pricingDateTimeLexeme{}, ErrInvalid
		}
	}
	return lexeme, nil
}
