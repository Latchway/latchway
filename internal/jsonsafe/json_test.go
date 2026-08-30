package jsonsafe

import (
	"strings"
	"testing"
)

func TestDecode(t *testing.T) {
	t.Parallel()

	value, err := Decode([]byte(`{"name":"latchway","values":[1,true,null]}`))
	if err != nil {
		t.Fatal(err)
	}
	object, ok := value.(map[string]any)
	if !ok || object["name"] != "latchway" {
		t.Fatalf("unexpected value: %#v", value)
	}
}

func TestDecodeRejectsDuplicateAndTrailingValues(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		`{"role":"viewer","role":"owner"}`,
		`{} {}`,
	} {
		if _, err := Decode([]byte(input)); err == nil {
			t.Fatalf("unsafe JSON accepted: %s", input)
		}
	}
}

func TestDecodeReaderLimit(t *testing.T) {
	t.Parallel()

	if _, err := DecodeReader(strings.NewReader(`{"large":true}`), 4); err == nil {
		t.Fatal("oversized JSON accepted")
	}
}
