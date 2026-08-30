package attestation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	appAttestAuthenticatorHeaderBytes = 37
	appAttestCredentialIDBytes        = sha256.Size
	maxAppAttestAuthenticatorBytes    = 16 << 10
	maxAppAttestCertificateBytes      = 8 << 10
	maxAppAttestCertificates          = 5
	maxAppAttestReceiptBytes          = 32 << 10
	maxAppAttestCOSEKeyBytes          = 256
	maxAppAttestSignatureBytes        = 80

	// App Attest uses an exact flags byte of 0x40 for attestation and 0x00
	// for assertion. Apple's extension dictionary follows the credential or
	// assertion header without setting WebAuthn's ED flag.
	appAttestFlagAttestedData = byte(0x40)
)

var appAttestNonceOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

type appAttestationObjectWire struct {
	Format            string                      `cbor:"fmt"`
	Statement         appAttestationStatementWire `cbor:"attStmt"`
	AuthenticatorData []byte                      `cbor:"authData"`
}

type appAttestationStatementWire struct {
	Certificates [][]byte `cbor:"x5c"`
	// Receipt is deliberately opaque here. It cannot influence key/app trust;
	// a future fraud-risk adapter must independently validate it before use.
	Receipt []byte `cbor:"receipt"`
}

type appAttestAssertionWire struct {
	Signature         []byte `cbor:"signature"`
	AuthenticatorData []byte `cbor:"authenticatorData"`
}

type appAttestCOSEKeyWire struct {
	KeyType   int64  `cbor:"1,keyasint"`
	Algorithm int64  `cbor:"3,keyasint"`
	Curve     int64  `cbor:"-1,keyasint"`
	X         []byte `cbor:"-2,keyasint"`
	Y         []byte `cbor:"-3,keyasint"`
}

type appAttestExtensionsWire struct {
	ValidationCategory *[]byte `cbor:"apple_validation_category_01"`
	BundleVersion      *string `cbor:"apple_bundle_version_01"`
}

type appAttestExtensions struct {
	present            bool
	validationCategory uint32
	bundleVersion      string
}

type parsedAppAttestAuthenticator struct {
	rpIDHash      [sha256.Size]byte
	counter       uint32
	aaguid        [16]byte
	credentialID  [sha256.Size]byte
	publicKeyX963 []byte
	extensions    appAttestExtensions
}

type parsedAppAttestation struct {
	certificates      [][]byte
	authenticatorData []byte
	authenticator     parsedAppAttestAuthenticator
}

type parsedAppAttestAssertion struct {
	signature         []byte
	authenticatorData []byte
	rpIDHash          [sha256.Size]byte
	counter           uint32
	extensions        appAttestExtensions
}

var appAttestCBORMode, appAttestCBORModeError = newAppAttestCBORMode()

func newAppAttestCBORMode() (cbor.DecMode, error) {
	mode, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:   8,
		MaxArrayElements:  16,
		MaxMapPairs:       16,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
		MapKeyByteString:  cbor.MapKeyByteStringForbidden,
		NaN:               cbor.NaNDecodeForbidden,
		Inf:               cbor.InfDecodeForbidden,
	}.DecMode()
	if err != nil {
		return nil, err
	}
	return mode, nil
}

func parseAppAttestationObject(encoded []byte) (parsedAppAttestation, error) {
	if appAttestCBORModeError != nil || appAttestCBORMode == nil {
		return parsedAppAttestation{}, ErrConfiguration
	}
	if len(encoded) == 0 || len(encoded) > maxAppAttestAttestationBytes {
		return parsedAppAttestation{}, invalid("app attest attestation size")
	}
	var wire appAttestationObjectWire
	if err := appAttestCBORMode.Unmarshal(encoded, &wire); err != nil {
		return parsedAppAttestation{}, invalid("app attest attestation CBOR")
	}
	if wire.Format != "apple-appattest" || len(wire.Statement.Certificates) < 2 ||
		len(wire.Statement.Certificates) > maxAppAttestCertificates || len(wire.Statement.Receipt) == 0 ||
		len(wire.Statement.Receipt) > maxAppAttestReceiptBytes || len(wire.AuthenticatorData) == 0 ||
		len(wire.AuthenticatorData) > maxAppAttestAuthenticatorBytes {
		return parsedAppAttestation{}, invalid("app attest attestation shape")
	}
	certificates := make([][]byte, len(wire.Statement.Certificates))
	for index, certificate := range wire.Statement.Certificates {
		if len(certificate) == 0 || len(certificate) > maxAppAttestCertificateBytes {
			return parsedAppAttestation{}, invalid("app attest certificate size")
		}
		certificates[index] = append([]byte(nil), certificate...)
	}
	authenticator, err := parseAppAttestAttestationAuthenticator(wire.AuthenticatorData)
	if err != nil {
		return parsedAppAttestation{}, err
	}
	return parsedAppAttestation{
		certificates: certificates, authenticatorData: append([]byte(nil), wire.AuthenticatorData...),
		authenticator: authenticator,
	}, nil
}

func parseAppAttestAttestationAuthenticator(encoded []byte) (parsedAppAttestAuthenticator, error) {
	if appAttestCBORModeError != nil || appAttestCBORMode == nil {
		return parsedAppAttestAuthenticator{}, ErrConfiguration
	}
	minimum := appAttestAuthenticatorHeaderBytes + 16 + 2 + appAttestCredentialIDBytes + 1
	if len(encoded) < minimum || len(encoded) > maxAppAttestAuthenticatorBytes {
		return parsedAppAttestAuthenticator{}, invalid("app attest authenticator size")
	}
	flags := encoded[32]
	if flags != appAttestFlagAttestedData {
		return parsedAppAttestAuthenticator{}, invalid("app attest authenticator flags")
	}
	result := parsedAppAttestAuthenticator{counter: binary.BigEndian.Uint32(encoded[33:37])}
	copy(result.rpIDHash[:], encoded[:32])
	offset := appAttestAuthenticatorHeaderBytes
	copy(result.aaguid[:], encoded[offset:offset+16])
	offset += 16
	credentialLength := int(binary.BigEndian.Uint16(encoded[offset : offset+2]))
	offset += 2
	if credentialLength != appAttestCredentialIDBytes || len(encoded)-offset < credentialLength+1 {
		return parsedAppAttestAuthenticator{}, invalid("app attest credential identifier")
	}
	copy(result.credentialID[:], encoded[offset:offset+credentialLength])
	offset += credentialLength

	var cose appAttestCOSEKeyWire
	rest, err := appAttestCBORMode.UnmarshalFirst(encoded[offset:], &cose)
	if err != nil || len(encoded[offset:])-len(rest) > maxAppAttestCOSEKeyBytes {
		return parsedAppAttestAuthenticator{}, invalid("app attest credential public key")
	}
	publicKey, err := decodeAppAttestCOSEKey(cose)
	if err != nil {
		return parsedAppAttestAuthenticator{}, err
	}
	publicKeyX963, err := publicKey.Bytes()
	if err != nil || len(publicKeyX963) != 65 || publicKeyX963[0] != 4 {
		return parsedAppAttestAuthenticator{}, invalid("app attest credential public key")
	}
	extensions, err := decodeAppAttestExtensions(rest)
	if err != nil {
		return parsedAppAttestAuthenticator{}, err
	}
	result.publicKeyX963 = publicKeyX963
	result.extensions = extensions
	return result, nil
}

func parseAppAttestAssertionObject(encoded []byte) (parsedAppAttestAssertion, error) {
	if appAttestCBORModeError != nil || appAttestCBORMode == nil {
		return parsedAppAttestAssertion{}, ErrConfiguration
	}
	if len(encoded) == 0 || len(encoded) > maxAppAttestAssertionBytes {
		return parsedAppAttestAssertion{}, invalid("app attest assertion size")
	}
	var wire appAttestAssertionWire
	if err := appAttestCBORMode.Unmarshal(encoded, &wire); err != nil {
		return parsedAppAttestAssertion{}, invalid("app attest assertion CBOR")
	}
	if len(wire.Signature) < 8 || len(wire.Signature) > maxAppAttestSignatureBytes ||
		len(wire.AuthenticatorData) < appAttestAuthenticatorHeaderBytes ||
		len(wire.AuthenticatorData) > maxAppAttestAuthenticatorBytes {
		return parsedAppAttestAssertion{}, invalid("app attest assertion shape")
	}
	flags := wire.AuthenticatorData[32]
	if flags != 0 {
		return parsedAppAttestAssertion{}, invalid("app attest assertion flags")
	}
	extensions, err := decodeAppAttestExtensions(wire.AuthenticatorData[appAttestAuthenticatorHeaderBytes:])
	if err != nil {
		return parsedAppAttestAssertion{}, err
	}
	result := parsedAppAttestAssertion{
		signature:         append([]byte(nil), wire.Signature...),
		authenticatorData: append([]byte(nil), wire.AuthenticatorData...),
		counter:           binary.BigEndian.Uint32(wire.AuthenticatorData[33:37]), extensions: extensions,
	}
	copy(result.rpIDHash[:], wire.AuthenticatorData[:32])
	return result, nil
}

func decodeAppAttestCOSEKey(wire appAttestCOSEKeyWire) (*ecdsa.PublicKey, error) {
	if wire.KeyType != 2 || wire.Algorithm != -7 || wire.Curve != 1 || len(wire.X) != 32 || len(wire.Y) != 32 {
		return nil, invalid("app attest credential public key")
	}
	encoded := make([]byte, 1+len(wire.X)+len(wire.Y))
	encoded[0] = 4
	copy(encoded[1:], wire.X)
	copy(encoded[1+len(wire.X):], wire.Y)
	publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
	if err != nil {
		return nil, invalid("app attest credential public key")
	}
	return publicKey, nil
}

func decodeAppAttestExtensions(encoded []byte) (appAttestExtensions, error) {
	if appAttestCBORModeError != nil || appAttestCBORMode == nil {
		return appAttestExtensions{}, ErrConfiguration
	}
	if len(encoded) == 0 {
		return appAttestExtensions{}, nil
	}
	if len(encoded) > maxAppAttestAuthenticatorBytes {
		return appAttestExtensions{}, invalid("app attest extensions")
	}
	var wire appAttestExtensionsWire
	if err := appAttestCBORMode.Unmarshal(encoded, &wire); err != nil || wire.ValidationCategory == nil || wire.BundleVersion == nil ||
		len(*wire.ValidationCategory) != 4 || !validAppAttestBundleVersion(*wire.BundleVersion) {
		return appAttestExtensions{}, invalid("app attest extensions")
	}
	category := binary.LittleEndian.Uint32(*wire.ValidationCategory)
	if !validAppAttestValidationCategory(category) {
		return appAttestExtensions{}, invalid("app attest extensions")
	}
	return appAttestExtensions{present: true, validationCategory: category, bundleVersion: *wire.BundleVersion}, nil
}

func verifyAppAttestCertificateChain(encoded [][]byte, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if roots == nil || now.IsZero() || len(encoded) < 2 || len(encoded) > maxAppAttestCertificates {
		return nil, invalid("app attest certificate chain")
	}
	certificates := make([]*x509.Certificate, len(encoded))
	seen := make(map[[sha256.Size]byte]struct{}, len(encoded))
	for index, der := range encoded {
		if len(der) == 0 || len(der) > maxAppAttestCertificateBytes {
			return nil, invalid("app attest certificate chain")
		}
		digest := sha256.Sum256(der)
		if _, duplicate := seen[digest]; duplicate {
			return nil, invalid("app attest certificate chain")
		}
		seen[digest] = struct{}{}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, invalid("app attest certificate chain")
		}
		certificates[index] = certificate
	}
	leaf := certificates[0]
	if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, invalid("app attest credential certificate")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil || len(chains) == 0 || len(chains[0]) != len(certificates)+1 {
		return nil, invalid("app attest certificate chain")
	}
	// Apple specifies x5c as credential leaf followed by its intermediates.
	// Requiring the selected chain to match every supplied certificate in that
	// exact order rejects unused/unrelated certificates and a client-supplied
	// root. The final certificate exists only in the server-pinned root pool.
	for index, certificate := range certificates {
		if !bytes.Equal(chains[0][index].Raw, certificate.Raw) {
			return nil, invalid("app attest certificate chain")
		}
	}
	return leaf, nil
}

func appAttestCertificateNonce(certificate *x509.Certificate) ([]byte, error) {
	if certificate == nil {
		return nil, invalid("app attest nonce extension")
	}
	var extensionValue []byte
	count := 0
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(appAttestNonceOID) {
			count++
			extensionValue = extension.Value
		}
	}
	if count != 1 || len(extensionValue) == 0 || len(extensionValue) > 128 {
		return nil, invalid("app attest nonce extension")
	}
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(extensionValue, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return nil, invalid("app attest nonce extension")
	}
	var tagged asn1.RawValue
	rest, err = asn1.Unmarshal(sequence.Bytes, &tagged)
	if err != nil || len(rest) != 0 || tagged.Class != asn1.ClassContextSpecific || tagged.Tag != 1 || !tagged.IsCompound {
		return nil, invalid("app attest nonce extension")
	}
	var nonce []byte
	rest, err = asn1.Unmarshal(tagged.Bytes, &nonce)
	if err != nil || len(rest) != 0 || len(nonce) != sha256.Size {
		return nil, invalid("app attest nonce extension")
	}
	return append([]byte(nil), nonce...), nil
}
