package id

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestGeneratorProducesCanonicalMonotonicIDs(t *testing.T) {
	t.Parallel()

	instant := time.Date(2026, time.August, 27, 9, 10, 11, 123_000_000, time.UTC)
	generator, err := NewGenerator(bytes.NewReader(make([]byte, 10)), func() time.Time { return instant })
	if err != nil {
		t.Fatalf("NewGenerator() error = %v", err)
	}

	first, err := generator.New(Organization)
	if err != nil {
		t.Fatalf("first New() error = %v", err)
	}
	second, err := generator.New(Organization)
	if err != nil {
		t.Fatalf("second New() error = %v", err)
	}
	if first >= second {
		t.Fatalf("IDs are not monotonic: %q >= %q", first, second)
	}

	parsed, err := Parse(first)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.Prefix != Organization {
		t.Fatalf("Prefix = %q, want %q", parsed.Prefix, Organization)
	}
	if !parsed.Timestamp.Equal(instant) {
		t.Fatalf("Timestamp = %s, want %s", parsed.Timestamp, instant)
	}
	if err := Validate(first, Organization); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if err := Validate(first, Application); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("Validate() wrong prefix error = %v", err)
	}
}

func TestContractExposedPrefixes(t *testing.T) {
	t.Parallel()

	for prefix, want := range map[Prefix]string{
		AdminUser:           "adm",
		AdminAPIToken:       "tok",
		ConfigRevision:      "rev",
		SessionChallenge:    "chl",
		InstallationFamily:  "fam",
		ClientComponent:     "cmp",
		ComponentKey:        "cky",
		ComponentDelegation: "dlg",
		ComponentSession:    "csf",
		ComponentRefresh:    "crf",
		RefreshRotation:     "rrs",
	} {
		if string(prefix) != want {
			t.Errorf("prefix = %q, want %q", prefix, want)
		}
	}
}

func TestGeneratorOrdersAcrossTimeAndClockRegression(t *testing.T) {
	t.Parallel()

	times := []time.Time{
		time.UnixMilli(200),
		time.UnixMilli(201),
		time.UnixMilli(199),
	}
	index := 0
	generator, err := NewGenerator(bytes.NewReader(make([]byte, 20)), func() time.Time {
		value := times[index]
		index++
		return value
	})
	if err != nil {
		t.Fatalf("NewGenerator() error = %v", err)
	}

	values := make([]string, 3)
	for i := range values {
		values[i], err = generator.New(Application)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
	}
	if !slices.IsSorted(values) || values[0] == values[1] || values[1] == values[2] {
		t.Fatalf("IDs are not strictly sorted: %v", values)
	}
	parsed, err := Parse(values[2])
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !parsed.Timestamp.Equal(time.UnixMilli(201)) {
		t.Fatalf("regressed timestamp = %s, want retained timestamp", parsed.Timestamp)
	}
}

func TestGeneratorConcurrentUniqueness(t *testing.T) {
	t.Parallel()

	const count = 1_000
	generator, err := NewGenerator(bytes.NewReader(make([]byte, 10)), func() time.Time {
		return time.UnixMilli(42)
	})
	if err != nil {
		t.Fatalf("NewGenerator() error = %v", err)
	}

	values := make(chan string, count)
	var wait sync.WaitGroup
	for range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			value, generateErr := generator.New(Environment)
			if generateErr != nil {
				t.Errorf("New() error = %v", generateErr)
				return
			}
			values <- value
		}()
	}
	wait.Wait()
	close(values)

	seen := make(map[string]struct{}, count)
	for value := range values {
		if _, exists := seen[value]; exists {
			t.Fatalf("duplicate identifier %q", value)
		}
		seen[value] = struct{}{}
	}
	if len(seen) != count {
		t.Fatalf("generated %d unique IDs, want %d", len(seen), count)
	}
}

func TestGeneratorRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		prefix Prefix
	}{
		{name: "empty", prefix: ""},
		{name: "uppercase", prefix: "Org"},
		{name: "leading digit", prefix: "1org"},
		{name: "separator", prefix: "org_id"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			generator, err := NewGenerator(bytes.NewReader(make([]byte, 10)), time.Now)
			if err != nil {
				t.Fatalf("NewGenerator() error = %v", err)
			}
			if _, err := generator.New(test.prefix); !errors.Is(err, ErrInvalidPrefix) {
				t.Fatalf("New() error = %v, want ErrInvalidPrefix", err)
			}
		})
	}

	invalidIDs := []string{
		"org",
		"org_",
		"org_0000000000000000000000000",
		"org_000000000000000000000000000",
		"org_0000000000000000000000000I",
		"org_0000000000000000000000000_",
	}
	for _, value := range invalidIDs {
		if _, err := Parse(value); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Parse(%q) error = %v, want ErrInvalidID", value, err)
		}
	}
}

func TestGeneratorPropagatesEntropyFailure(t *testing.T) {
	t.Parallel()

	generator, err := NewGenerator(errorReader{}, time.Now)
	if err != nil {
		t.Fatalf("NewGenerator() error = %v", err)
	}
	if _, err := generator.New(Organization); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("New() error = %v, want entropy failure", err)
	}
}

func TestGeneratorRejectsOutOfRangeTime(t *testing.T) {
	t.Parallel()

	generator, err := NewGenerator(bytes.NewReader(make([]byte, 10)), func() time.Time {
		return time.UnixMilli(-1)
	})
	if err != nil {
		t.Fatalf("NewGenerator() error = %v", err)
	}
	if _, err := generator.New(Organization); !errors.Is(err, ErrTimestampOutOfRange) {
		t.Fatalf("New() error = %v, want ErrTimestampOutOfRange", err)
	}
}

func TestGeneratorUsesCanonicalULIDBitLayout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		millis    int64
		entropy   []byte
		wantValue string
	}{
		{
			name:      "zero",
			millis:    0,
			entropy:   make([]byte, 10),
			wantValue: "org_00000000000000000000000000",
		},
		{
			name:      "maximum",
			millis:    int64(maxTimestamp),
			entropy:   bytes.Repeat([]byte{0xff}, 10),
			wantValue: "org_7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			generator, err := NewGenerator(bytes.NewReader(test.entropy), func() time.Time {
				return time.UnixMilli(test.millis)
			})
			if err != nil {
				t.Fatalf("NewGenerator() error = %v", err)
			}
			value, err := generator.New(Organization)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if value != test.wantValue {
				t.Fatalf("New() = %q, want %q", value, test.wantValue)
			}
			parsed, err := Parse(value)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if parsed.Timestamp.UnixMilli() != test.millis {
				t.Fatalf("timestamp = %d, want %d", parsed.Timestamp.UnixMilli(), test.millis)
			}
		})
	}
	if _, err := Parse("org_80000000000000000000000000"); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("Parse() noncanonical leading bits error = %v, want ErrInvalidID", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}
