package session

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func FuzzPreflightAccessToken(f *testing.F) {
	validHeader := []byte(`{"alg":"ES256","kid":"gsk_fuzz-seed","typ":"JWT"}`)
	validPayload := []byte(`{"aud":"latchway-data-plane","cnf":{"jkt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"exp":1700000600,"iat":1700000000,"iss":"https://gateway.example.test","jti":"fuzz-seed","sub":"usr_01J00000000000000000000000"}`)
	validSignature := make([]byte, 64)
	valid := compactAccessTokenFuzzSeed(validHeader, validPayload, validSignature)

	f.Add(valid)
	f.Add(compactAccessTokenFuzzSeed(
		[]byte(`{"alg":"ES256","alg":"none","kid":"gsk_fuzz-seed","typ":"JWT"}`),
		validPayload,
		validSignature,
	))
	f.Add(compactAccessTokenFuzzSeed(
		[]byte(`{"alg":"none","kid":"gsk_fuzz-seed","typ":"JWT"}`),
		validPayload,
		validSignature,
	))
	f.Add(compactAccessTokenFuzzSeed(
		validHeader,
		[]byte(`{"cnf":{"jkt":"first","jkt":"second"}}`),
		validSignature,
	))
	f.Add(compactAccessTokenFuzzSeed(validHeader, validPayload, validSignature[:63]))
	f.Add(strings.Replace(valid, ".", "=.", 1))
	f.Add("e30.e30.AA")
	f.Add("not-a-compact-token")
	f.Add(strings.Repeat("A", maxAccessTokenBytes+1))

	f.Fuzz(func(t *testing.T, raw string) {
		header, payload, err := preflightAccessToken(raw)
		if err != nil {
			if !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("preflight returned an unsafe error for untrusted token input: %v", err)
			}
			if header != nil || payload != nil {
				t.Fatal("failed preflight returned partially decoded token data")
			}
			return
		}

		if header == nil || payload == nil {
			t.Fatal("successful preflight returned nil decoded data")
		}
		if _, err := NewAccessToken(raw); err != nil {
			t.Fatalf("preflight accepted a token rejected by the credential envelope: %v", err)
		}

		parts := strings.Split(raw, ".")
		if len(parts) != 3 {
			t.Fatalf("preflight accepted %d compact-token segments", len(parts))
		}
		decoded := make([][]byte, len(parts))
		for index, part := range parts {
			if part == "" || strings.Contains(part, "=") {
				t.Fatal("preflight accepted an empty or padded compact-token segment")
			}
			value, decodeErr := base64.RawURLEncoding.Strict().DecodeString(part)
			if decodeErr != nil || base64.RawURLEncoding.EncodeToString(value) != part {
				t.Fatalf("preflight accepted non-canonical base64url segment %d", index)
			}
			decoded[index] = value
		}
		if len(decoded[0]) > 4096 || len(decoded[1]) > 12<<10 || len(decoded[2]) != 64 {
			t.Fatalf("preflight accepted out-of-bounds segment sizes: %d, %d, %d", len(decoded[0]), len(decoded[1]), len(decoded[2]))
		}
		if len(header) != 3 || textMember(header, "alg") != "ES256" || textMember(header, "typ") != "JWT" || len(textMember(header, "kid")) < 8 {
			t.Fatalf("preflight accepted an unsafe protected header: %#v", header)
		}

		headerAgain, payloadAgain, err := preflightAccessToken(raw)
		if err != nil || !reflect.DeepEqual(headerAgain, header) || !reflect.DeepEqual(payloadAgain, payload) {
			t.Fatalf("preflight is not deterministic: header=%#v payload=%#v err=%v", headerAgain, payloadAgain, err)
		}
		if _, _, err := preflightAccessToken(parts[0] + "=." + parts[1] + "." + parts[2]); !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("preflight accepted padding added to a valid header: %v", err)
		}
		if _, _, err := preflightAccessToken(raw + ".extra"); !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("preflight accepted an extra compact-token segment: %v", err)
		}
	})
}

func compactAccessTokenFuzzSeed(header, payload, signature []byte) string {
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(signature)
}
