package jsonsafe

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
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

func TestDecodePreservesLegacyValues(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		`null`, `true`, `false`, `""`, `[]`, `{}`, ` [ {} , [] , null ] `,
		`{"a":[1,true,null,{"text":"snowman ☃ / < > &"}]}`,
		`[9223372036854775807,9007199254740993,-9223372036854775808,-0,1.00,1e10000]`,
		`{"é":1,"e\u0301":2,"A":3,"a":4}`,
		`["\ud800","\udfff","\ud83d\ude00","\ufffd","\u0000"]`,
		`{"\ud800":1}`, `{"\udc00":1}`,
		"\n\t{\"line\":\"\u2028\u2029\"}\r\n",
	} {
		t.Run(input, func(t *testing.T) {
			got, err := Decode([]byte(input))
			want, oldErr := legacyDecode([]byte(input))
			if err != nil || oldErr != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("value changed: got %#v / %v; want %#v / %v", got, err, want, oldErr)
			}
		})
	}
	value, err := Decode([]byte(`9007199254740993`))
	if err != nil || value != json.Number("9007199254740993") {
		t.Fatalf("integer precision lost: %#v / %v", value, err)
	}
}

func TestDecodeRejectsMalformedDocuments(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		"", " \t\r\n", `{} {}`, `{} garbage`, `{} [`,
		`{"a":1,"\u0061":2}`, `{"outer":{"k":1,"k":2}}`,
		`{"\ud800":1,"\ufffd":2}`, `{"\ud800":1,"\udfff":2}`,
		`[1,]`, `{"a":1,}`, `{"a" 1}`, `{1:true}`, `{"a":}`, `[`, `]`,
		`01`, `+1`, `NaN`, `Infinity`, `1e`, `"\x00"`, "\"line\nfeed\"",
		"\xef\xbb\xbf{}", "\"\xff\"", "{\"\xed\xa0\x80\":1}",
	} {
		t.Run(fmt.Sprintf("%q", input), func(t *testing.T) {
			if _, err := Decode([]byte(input)); err == nil {
				t.Fatal("malformed JSON accepted")
			}
			if _, err := legacyDecode([]byte(input)); err == nil {
				t.Fatal("test input did not fail the previous decoder")
			}
		})
	}
}

func TestDecodeStructuralBoundaries(t *testing.T) {
	t.Parallel()
	array := func(depth int, leaf string) string {
		return strings.Repeat("[", depth) + leaf + strings.Repeat("]", depth)
	}
	for _, test := range []struct {
		name  string
		input string
		valid bool
	}{
		{"last scalar depth", array(maxDepth, "0"), true},
		{"scalar too deep", array(maxDepth+1, "0"), false},
		{"last empty container depth", array(maxDepth+1, ""), true},
		{"empty container too deep", array(maxDepth+2, ""), false},
		{"last node", "[" + strings.Repeat("0,", maxNodes-2) + "0]", true},
		{"too many nodes", "[" + strings.Repeat("0,", maxNodes-1) + "0]", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := Decode([]byte(test.input))
			want, oldErr := legacyDecode([]byte(test.input))
			if (err == nil) != test.valid || (oldErr == nil) != test.valid {
				t.Fatalf("boundary changed: current=%v previous=%v valid=%v", err, oldErr, test.valid)
			}
			if test.valid && !reflect.DeepEqual(got, want) {
				t.Fatal("boundary value changed")
			}
		})
	}
}

func TestDecodeObjectNamesAreNotStructuralNodes(t *testing.T) {
	t.Parallel()
	var input strings.Builder
	input.WriteByte('{')
	for i := 0; i < maxNodes-1; i++ {
		if i != 0 {
			input.WriteByte(',')
		}
		fmt.Fprintf(&input, `"%d":null`, i)
	}
	input.WriteByte('}')
	value, err := Decode([]byte(input.String()))
	if err != nil || len(value.(map[string]any)) != maxNodes-1 {
		t.Fatalf("object member budget changed: %v", err)
	}
}

func TestDecodeErrorsDoNotExposeInput(t *testing.T) {
	t.Parallel()
	const marker = "sensitive-member-do-not-log"
	for _, input := range []string{
		`{"` + marker + `":1,"` + marker + `":2}`,
		`{"` + marker + `":invalid}`,
		`{} "` + marker + `"`,
	} {
		_, err := Decode([]byte(input))
		if err == nil || strings.Contains(err.Error(), marker) {
			t.Fatalf("error leaked input: %v", err)
		}
	}
}

func TestDecodeReaderBoundariesAndErrors(t *testing.T) {
	t.Parallel()
	for _, limit := range []int64{-1, 0, math.MaxInt64} {
		if _, err := DecodeReader(strings.NewReader(`{}`), limit); err == nil {
			t.Fatalf("invalid size limit accepted: %d", limit)
		}
	}
	if _, err := DecodeReader(strings.NewReader(`{}`), 2); err != nil {
		t.Fatalf("exact size rejected: %v", err)
	}
	if _, err := DecodeReader(strings.NewReader(`{} `), 2); err == nil {
		t.Fatal("trailing whitespace bypassed byte bound")
	}
	if _, err := DecodeReader(errorReader{}, 8); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("reader error lost: %v", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func FuzzDecodeMatchesLegacy(f *testing.F) {
	for _, input := range []string{
		`null`, `{}`, `[]`, `{"a":[1,true,null]}`, `{"a":1,"\u0061":2}`,
		`{"\ud800":1,"\ufffd":2}`, `"\ud800"`, `9223372036854775807`,
		`-0`, `1e10000`, `{}[]`, "\"\xff\"", strings.Repeat("[", 65),
	} {
		f.Add([]byte(input))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 256*1024 {
			t.Skip()
		}
		got, err := Decode(input)
		want, oldErr := legacyDecode(input)
		if (err == nil) != (oldErr == nil) {
			t.Fatalf("acceptance changed: current=%v previous=%v", err, oldErr)
		}
		if err == nil && !reflect.DeepEqual(got, want) {
			t.Fatal("decoded value changed")
		}
	})
}

func BenchmarkDecode(b *testing.B) {
	input := []byte(`{"iss":"https://issuer.example","sub":"user","aud":["app"],"iat":1720000000,"exp":1720003600,"claims":{"roles":["member"],"enabled":true}}`)
	for _, test := range []struct {
		name   string
		decode func([]byte) (any, error)
	}{{"standard", Decode}, {"previous", legacyDecode}} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := test.decode(input); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
