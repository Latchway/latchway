package useroverride

import (
	"bytes"
	"errors"
	"testing"
)

func TestDocumentCanonicalRoundTrip(t *testing.T) {
	t.Parallel()

	encoded, err := Encode(Document{LimitPlan: "premium"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, []byte(`{"limit_plan":"premium"}`)) {
		t.Fatalf("Encode() = %s", encoded)
	}
	decoded, err := Decode([]byte(` { "limit_plan" : "premium" } `))
	if err != nil || decoded.LimitPlan != "premium" {
		t.Fatalf("Decode() = %#v, %v", decoded, err)
	}
}

func TestDocumentRejectsEveryUnsupportedShape(t *testing.T) {
	t.Parallel()

	tests := [][]byte{
		nil,
		[]byte(`null`),
		[]byte(`[]`),
		[]byte(`{}`),
		[]byte(`{"limit_plan":null}`),
		[]byte(`{"limit_plan":"Premium"}`),
		[]byte(`{"limit_plan":"premium","extra":true}`),
		[]byte(`{"limit_plan":"free","limit_plan":"premium"}`),
		bytes.Repeat([]byte(" "), maximumDocumentBytes+1),
	}
	for _, encoded := range tests {
		if _, err := Decode(encoded); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Decode(%q) error = %v", encoded, err)
		}
	}
	if _, err := Encode(Document{LimitPlan: "Premium"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Encode() error = %v", err)
	}
}

func TestSelectionValidation(t *testing.T) {
	t.Parallel()

	valid := Selection{ID: "uov_00000000000000000000000000", LimitPlan: "premium"}
	if err := valid.Validate(); err != nil || !valid.Present() {
		t.Fatalf("valid selection: present=%v err=%v", valid.Present(), err)
	}
	for _, selection := range []Selection{
		{},
		{ID: valid.ID},
		{LimitPlan: valid.LimitPlan},
		{ID: "invalid", LimitPlan: valid.LimitPlan},
		{ID: valid.ID, LimitPlan: "Premium"},
	} {
		err := selection.Validate()
		if selection == (Selection{}) {
			if err != nil || selection.Present() {
				t.Fatalf("zero selection: present=%v err=%v", selection.Present(), err)
			}
			continue
		}
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("selection %#v error = %v", selection, err)
		}
	}
}
