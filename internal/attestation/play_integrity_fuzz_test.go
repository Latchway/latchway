package attestation

import "testing"

func FuzzParsePlayIntegrityDecodeResponse(f *testing.F) {
	f.Add([]byte(`{"tokenPayloadExternal":{"requestDetails":{"requestPackageName":"com.example.app","timestampMillis":"1787903990000","requestHash":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"},"appIntegrity":{"appRecognitionVerdict":"PLAY_RECOGNIZED","packageName":"com.example.app","certificateSha256Digest":["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"],"versionCode":"1"},"deviceIntegrity":{"deviceRecognitionVerdict":["MEETS_DEVICE_INTEGRITY"]},"accountDetails":{"appLicensingVerdict":"LICENSED"}}}`))
	f.Add([]byte(`{"tokenPayloadExternal":{},"tokenPayloadExternal":{}}`))
	f.Add([]byte{0xff, 0x00, 0x01})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		payload, err := parsePlayIntegrityDecodeResponse(encoded)
		if err == nil {
			if payload.requestPackageName == "" || payload.appPackageName == "" ||
				payload.requestHash == "" || len(payload.certificateDigests) == 0 ||
				len(payload.deviceVerdicts) == 0 || payload.licensingVerdict == "" {
				t.Fatal("successful Play Integrity parse returned incomplete payload")
			}
		}
	})
}
