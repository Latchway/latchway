// Package session issues and validates short-lived, DPoP-bound client sessions.
package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/secrets"
)

const signingKeyAdvisoryLock int64 = 0x4c41544348534b59

var (
	ErrSigningKeyUnavailable = errors.New("gateway signing key is unavailable")
	ErrTokenInvalid          = errors.New("client access token is invalid")
	ErrTokenExpired          = errors.New("client access token is expired")
)

type PublicSigningJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

type JWKS struct {
	Keys []PublicSigningJWK `json:"keys"`
}

type signingKey struct {
	material *signingKeyMaterial
}

type signingKeyMaterial struct {
	kid       string
	private   *ecdsa.PrivateKey
	notBefore time.Time
	notAfter  time.Time
}

func (key signingKey) KeyID() string {
	if key.material == nil {
		return ""
	}
	return key.material.kid
}

func (key signingKey) NotBefore() time.Time {
	if key.material == nil {
		return time.Time{}
	}
	return key.material.notBefore
}

func (key signingKey) NotAfter() time.Time {
	if key.material == nil {
		return time.Time{}
	}
	return key.material.notAfter
}

func (key signingKey) privateKey() *ecdsa.PrivateKey {
	if key.material == nil {
		return nil
	}
	return key.material.private
}

// Format prevents private signing material from reaching logs through every
// fmt verb that honors Formatter. The opaque one-pointer representation also
// ensures fmt's special %p path cannot recursively expose key fields.
func (signingKey) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}

type SigningKeyManagerConfig struct {
	Pool         *pgxpool.Pool
	Envelope     secrets.Provider
	Now          func() time.Time
	Random       io.Reader
	KeyLifetime  time.Duration
	RotationLead time.Duration
}

type SigningKeyManager struct {
	pool         *pgxpool.Pool
	envelope     secrets.Provider
	now          func() time.Time
	random       io.Reader
	keyLifetime  time.Duration
	rotationLead time.Duration
}

func NewSigningKeyManager(config SigningKeyManagerConfig) (*SigningKeyManager, error) {
	if config.Pool == nil || config.Envelope == nil {
		return nil, errors.New("signing-key manager dependency is nil")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.KeyLifetime == 0 {
		config.KeyLifetime = 30 * 24 * time.Hour
	}
	if config.RotationLead == 0 {
		config.RotationLead = 24 * time.Hour
	}
	if config.KeyLifetime < 24*time.Hour || config.KeyLifetime > 366*24*time.Hour || config.RotationLead < time.Hour || config.RotationLead >= config.KeyLifetime {
		return nil, errors.New("signing-key rotation durations are invalid")
	}
	return &SigningKeyManager{
		pool: config.Pool, envelope: config.Envelope, now: config.Now, random: config.Random,
		keyLifetime: config.KeyLifetime, rotationLead: config.RotationLead,
	}, nil
}

// Active returns an active private key, rotating it under a global PostgreSQL
// advisory lock when it approaches expiry. The previous key remains public in
// retiring state until its validity window ends.
func (manager *SigningKeyManager) Active(ctx context.Context) (signingKey, error) {
	now := manager.now().UTC()
	tx, err := manager.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return signingKey{}, fmt.Errorf("begin signing-key selection: %w", err)
	}
	defer rollbackSigning(tx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", signingKeyAdvisoryLock); err != nil {
		return signingKey{}, fmt.Errorf("lock signing-key rotation: %w", err)
	}
	if err := manager.verifyMasterKeyConsistency(ctx, tx); err != nil {
		return signingKey{}, err
	}
	record, found, err := loadActiveSigningRecord(ctx, tx)
	if err != nil {
		return signingKey{}, err
	}
	if found && record.notAfter.After(now.Add(manager.rotationLead)) && !now.Before(record.notBefore) {
		if err := tx.Commit(ctx); err != nil {
			return signingKey{}, fmt.Errorf("commit signing-key selection: %w", err)
		}
		return manager.decrypt(record)
	}
	if found {
		if _, err := tx.Exec(ctx, `
			UPDATE gateway_signing_keys
			SET status = 'retiring'
			WHERE gateway_signing_key_id = $1 AND status = 'active'
		`, record.id); err != nil {
			return signingKey{}, fmt.Errorf("retire active signing key: %w", err)
		}
	}
	created, err := manager.create(ctx, tx, now)
	if err != nil {
		return signingKey{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return signingKey{}, fmt.Errorf("commit signing-key rotation: %w", err)
	}
	return created, nil
}

// verifyMasterKeyConsistency runs under the signing-key rotation advisory lock.
// Checking every historical record prevents a changed master key from being
// hidden by rotation and serializes the first marker written to a fresh
// database across concurrently starting replicas.
func (manager *SigningKeyManager) verifyMasterKeyConsistency(ctx context.Context, tx pgx.Tx) error {
	var mismatch bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM gateway_signing_keys
			WHERE master_key_identifier <> $1
		)
	`, manager.envelope.KeyID()).Scan(&mismatch); err != nil {
		return errors.New("verify gateway signing-key master-key consistency")
	}
	if mismatch {
		return ErrSigningKeyUnavailable
	}
	return nil
}

// PublicJWKS returns only currently usable public members. No encrypted or
// private material is represented in the returned type.
func (manager *SigningKeyManager) PublicJWKS(ctx context.Context) (JWKS, error) {
	now := manager.now().UTC()
	rows, err := manager.pool.Query(ctx, `
		SELECT public_jwk
		FROM gateway_signing_keys
		WHERE status IN ('active', 'retiring')
		  AND not_before <= $1
		  AND not_after > $1
		ORDER BY created_at DESC, gateway_signing_key_id DESC
	`, now)
	if err != nil {
		return JWKS{}, fmt.Errorf("read public signing keys: %w", err)
	}
	defer rows.Close()
	result := JWKS{Keys: make([]PublicSigningJWK, 0)}
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return JWKS{}, fmt.Errorf("scan public signing key: %w", err)
		}
		jwk, err := decodePublicSigningJWK(encoded)
		if err != nil {
			return JWKS{}, err
		}
		result.Keys = append(result.Keys, jwk)
	}
	if err := rows.Err(); err != nil {
		return JWKS{}, fmt.Errorf("iterate public signing keys: %w", err)
	}
	if len(result.Keys) == 0 {
		return JWKS{}, ErrSigningKeyUnavailable
	}
	return result, nil
}

func (manager *SigningKeyManager) PublicKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	if len(kid) < 8 || len(kid) > 128 || strings.ContainsAny(kid, "\r\n\x00") {
		return nil, ErrSigningKeyUnavailable
	}
	var encoded []byte
	err := manager.pool.QueryRow(ctx, `
		SELECT public_jwk
		FROM gateway_signing_keys
		WHERE key_id = $1
		  AND status IN ('active', 'retiring')
		  AND not_before <= $2
		  AND not_after > $2
	`, kid, manager.now().UTC()).Scan(&encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSigningKeyUnavailable
	}
	if err != nil {
		return nil, fmt.Errorf("read public signing key: %w", err)
	}
	jwk, err := decodePublicSigningJWK(encoded)
	if err != nil || jwk.Kid != kid {
		return nil, ErrSigningKeyUnavailable
	}
	return jwk.publicKey()
}

type signingRecord struct {
	id            string
	kid           string
	publicJWK     []byte
	formatVersion int16
	masterKeyID   string
	ciphertext    []byte
	nonce         []byte
	notBefore     time.Time
	notAfter      time.Time
}

func loadActiveSigningRecord(ctx context.Context, tx pgx.Tx) (signingRecord, bool, error) {
	var record signingRecord
	err := tx.QueryRow(ctx, `
		SELECT gateway_signing_key_id, key_id, public_jwk, encryption_format_version,
		       master_key_identifier, encrypted_private_key, nonce, not_before, not_after
		FROM gateway_signing_keys
		WHERE status = 'active'
		FOR UPDATE
	`).Scan(&record.id, &record.kid, &record.publicJWK, &record.formatVersion, &record.masterKeyID,
		&record.ciphertext, &record.nonce, &record.notBefore, &record.notAfter)
	if errors.Is(err, pgx.ErrNoRows) {
		return signingRecord{}, false, nil
	}
	if err != nil {
		return signingRecord{}, false, fmt.Errorf("read active signing key: %w", err)
	}
	return record, true, nil
}

func (manager *SigningKeyManager) create(ctx context.Context, tx pgx.Tx, now time.Time) (signingKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), manager.random)
	if err != nil {
		return signingKey{}, errors.New("generate gateway signing key")
	}
	keyID, err := id.New(id.GatewaySigningKey)
	if err != nil {
		return signingKey{}, fmt.Errorf("generate gateway signing-key ID: %w", err)
	}
	publicJWK := publicJWKFromKey(keyID, &privateKey.PublicKey)
	encodedPublic, err := json.Marshal(publicJWK)
	if err != nil {
		return signingKey{}, errors.New("encode gateway public key")
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return signingKey{}, errors.New("encode gateway private key")
	}
	envelope, err := manager.envelope.Encrypt(privateDER, signingAssociatedData(keyID))
	clear(privateDER)
	if err != nil {
		return signingKey{}, errors.New("encrypt gateway private key")
	}
	notBefore := now.Add(-time.Minute)
	notAfter := now.Add(manager.keyLifetime)
	if _, err := tx.Exec(ctx, `
		INSERT INTO gateway_signing_keys (
			gateway_signing_key_id, key_id, algorithm, public_jwk,
			encryption_format_version, master_key_identifier, encrypted_private_key, nonce,
			status, not_before, not_after, created_at
		) VALUES ($1, $1, 'ES256', $2, $3, $4, $5, $6, 'active', $7, $8, $9)
	`, keyID, encodedPublic, int16(envelope.FormatVersion), envelope.KeyID, envelope.Ciphertext, envelope.Nonce,
		notBefore, notAfter, now); err != nil {
		return signingKey{}, fmt.Errorf("store gateway signing key: %w", err)
	}
	return signingKey{material: &signingKeyMaterial{kid: keyID, private: privateKey, notBefore: notBefore, notAfter: notAfter}}, nil
}

func (manager *SigningKeyManager) decrypt(record signingRecord) (signingKey, error) {
	jwk, err := decodePublicSigningJWK(record.publicJWK)
	if err != nil || jwk.Kid != record.kid {
		return signingKey{}, ErrSigningKeyUnavailable
	}
	plaintext, err := manager.envelope.Decrypt(secrets.Envelope{
		FormatVersion: int(record.formatVersion), Algorithm: "AES-256-GCM", KeyID: record.masterKeyID,
		Nonce: record.nonce, Ciphertext: record.ciphertext,
	}, signingAssociatedData(record.id))
	if err != nil {
		return signingKey{}, ErrSigningKeyUnavailable
	}
	defer clear(plaintext)
	parsed, err := x509.ParsePKCS8PrivateKey(plaintext)
	if err != nil {
		return signingKey{}, ErrSigningKeyUnavailable
	}
	privateKey, ok := parsed.(*ecdsa.PrivateKey)
	publicKey, publicErr := jwk.publicKey()
	if !ok || publicErr != nil || privateKey.Curve == nil || privateKey.Curve.Params().Name != elliptic.P256().Params().Name || privateKey.PublicKey.X.Cmp(publicKey.X) != 0 || privateKey.PublicKey.Y.Cmp(publicKey.Y) != 0 {
		return signingKey{}, ErrSigningKeyUnavailable
	}
	return signingKey{material: &signingKeyMaterial{kid: record.kid, private: privateKey, notBefore: record.notBefore.UTC(), notAfter: record.notAfter.UTC()}}, nil
}

func signingAssociatedData(keyID string) secrets.AssociatedData {
	return secrets.AssociatedData{
		OrganizationID: "gateway", EnvironmentID: "global", SecretID: keyID,
		SecretVersion: 1, FormatVersion: 1,
	}
}

func publicJWKFromKey(kid string, key *ecdsa.PublicKey) PublicSigningJWK {
	return PublicSigningJWK{
		Kty: "EC", Crv: "P-256", X: base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
		Y: base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))), Kid: kid, Use: "sig", Alg: "ES256",
	}
}

func decodePublicSigningJWK(encoded []byte) (PublicSigningJWK, error) {
	value, err := jsonsafe.Decode(encoded)
	if err != nil {
		return PublicSigningJWK{}, ErrSigningKeyUnavailable
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != 7 {
		return PublicSigningJWK{}, ErrSigningKeyUnavailable
	}
	jwk := PublicSigningJWK{
		Kty: textMember(object, "kty"), Crv: textMember(object, "crv"), X: textMember(object, "x"),
		Y: textMember(object, "y"), Kid: textMember(object, "kid"), Use: textMember(object, "use"), Alg: textMember(object, "alg"),
	}
	if _, err := jwk.publicKey(); err != nil {
		return PublicSigningJWK{}, err
	}
	return jwk, nil
}

func (jwk PublicSigningJWK) publicKey() (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.Use != "sig" || jwk.Alg != "ES256" || len(jwk.Kid) < 8 || len(jwk.Kid) > 128 {
		return nil, ErrSigningKeyUnavailable
	}
	x, errX := base64.RawURLEncoding.Strict().DecodeString(jwk.X)
	y, errY := base64.RawURLEncoding.Strict().DecodeString(jwk.Y)
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 || base64.RawURLEncoding.EncodeToString(x) != jwk.X || base64.RawURLEncoding.EncodeToString(y) != jwk.Y {
		return nil, ErrSigningKeyUnavailable
	}
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if key.X.Sign() <= 0 || key.Y.Sign() <= 0 || !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, ErrSigningKeyUnavailable
	}
	return key, nil
}

func textMember(object map[string]any, name string) string {
	value, _ := object[name].(string)
	return value
}

func rollbackSigning(tx pgx.Tx) {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(rollbackCtx)
}
