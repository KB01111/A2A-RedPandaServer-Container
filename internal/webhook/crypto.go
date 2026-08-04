package webhook

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
)

const (
	credentialEnvelopeVersion byte = 1
	credentialHeaderBytes          = 5 // version byte plus uint32 key ID
)

// CredentialCipher encrypts webhook credentials using AES-256-GCM. Ciphertext
// includes an envelope version and key ID so keys can be rotated without
// rewriting queued deliveries.
type CredentialCipher struct {
	currentKeyID uint32
	keys         map[uint32][]byte
	random       io.Reader
}

// NewCredentialCipher constructs a versioned AES-256-GCM keyring. All key
// material must be exactly 32 bytes and is copied before being retained.
func NewCredentialCipher(currentKeyID uint32, keys map[uint32][]byte) (*CredentialCipher, error) {
	if currentKeyID == 0 {
		return nil, fmt.Errorf("credential key ID must be non-zero")
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("at least one credential key is required")
	}
	keyring := make(map[uint32][]byte, len(keys))
	for id, key := range keys {
		if id == 0 || len(key) != 32 {
			return nil, fmt.Errorf("credential key %d must contain exactly 32 bytes", id)
		}
		keyring[id] = append([]byte(nil), key...)
	}
	if _, ok := keyring[currentKeyID]; !ok {
		return nil, fmt.Errorf("current credential key %d is not in the keyring", currentKeyID)
	}
	return &CredentialCipher{currentKeyID: currentKeyID, keys: keyring, random: cryptorand.Reader}, nil
}

// Encrypt authenticates aad but does not include it in the ciphertext.
func (c *CredentialCipher) Encrypt(plaintext, aad []byte) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("credential cipher is required")
	}
	block, err := aes.NewCipher(c.keys[c.currentKeyID])
	if err != nil {
		return nil, fmt.Errorf("initialize credential cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize credential AEAD: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(c.random, nonce); err != nil {
		return nil, fmt.Errorf("generate credential nonce: %w", err)
	}
	result := make([]byte, credentialHeaderBytes, credentialHeaderBytes+len(nonce)+len(plaintext)+gcm.Overhead())
	result[0] = credentialEnvelopeVersion
	binary.BigEndian.PutUint32(result[1:], c.currentKeyID)
	result = append(result, nonce...)
	result = gcm.Seal(result, nonce, plaintext, aad)
	return result, nil
}

// Decrypt authenticates and decrypts a versioned credential envelope.
func (c *CredentialCipher) Decrypt(envelope, aad []byte) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("credential cipher is required")
	}
	if len(envelope) < credentialHeaderBytes || envelope[0] != credentialEnvelopeVersion {
		return nil, fmt.Errorf("unsupported credential envelope")
	}
	keyID := binary.BigEndian.Uint32(envelope[1:credentialHeaderBytes])
	key, ok := c.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("credential key is unavailable")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize credential cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize credential AEAD: %w", err)
	}
	encoded := envelope[credentialHeaderBytes:]
	if len(encoded) < gcm.NonceSize()+gcm.Overhead() {
		return nil, fmt.Errorf("invalid credential envelope")
	}
	nonce := encoded[:gcm.NonceSize()]
	plaintext, err := gcm.Open(nil, nonce, encoded[gcm.NonceSize():], aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt credentials: %w", err)
	}
	return plaintext, nil
}

const (
	HeaderDeliveryID        = "A2A-Delivery-ID"
	HeaderDeliveryTimestamp = "A2A-Delivery-Timestamp"
	HeaderDeliveryKeyID     = "A2A-Delivery-Key-ID"
	HeaderDeliverySignature = "A2A-Delivery-Signature"
	HeaderNotificationToken = "A2A-Notification-Token"
	signatureVersion        = "v1"
)

// Ed25519Signer signs a canonical digest of the immutable delivery ID, Unix
// timestamp, and payload. KeyID is public metadata used by receivers to select
// the verification key.
type Ed25519Signer struct {
	KeyID      string
	PrivateKey ed25519.PrivateKey
}

func (s Ed25519Signer) sign(id DeliveryID, timestamp time.Time, payload []byte) (map[string]string, error) {
	if s.KeyID == "" || len(s.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("valid Ed25519 signing key and key ID are required")
	}
	unix := strconv.FormatInt(timestamp.UTC().Unix(), 10)
	message := signatureMessage(id, unix, payload)
	signature := ed25519.Sign(s.PrivateKey, message)
	return map[string]string{
		HeaderDeliveryID:        string(id),
		HeaderDeliveryTimestamp: unix,
		HeaderDeliveryKeyID:     s.KeyID,
		HeaderDeliverySignature: signatureVersion + "=" + base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}

// VerifySignature verifies the signing headers produced by Ed25519Signer.
func VerifySignature(publicKey ed25519.PublicKey, id DeliveryID, unixTimestamp, encodedSignature string, payload []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	prefix := signatureVersion + "="
	if len(encodedSignature) <= len(prefix) || encodedSignature[:len(prefix)] != prefix {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature[len(prefix):])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, signatureMessage(id, unixTimestamp, payload), signature)
}

func signatureMessage(id DeliveryID, unixTimestamp string, payload []byte) []byte {
	digest := sha256.Sum256(payload)
	return []byte(signatureVersion + "\n" + string(id) + "\n" + unixTimestamp + "\n" + hex.EncodeToString(digest[:]))
}

func credentialAAD(delivery NewDelivery) []byte {
	result := []byte("bridge.a2a.webhook-credentials/v1")
	for _, value := range []string{string(delivery.ID), delivery.Tenant, delivery.TaskID, delivery.ConfigID} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		result = append(result, size[:]...)
		result = append(result, value...)
	}
	return result
}

func wipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// NewStableID returns a UUIDv7-formatted identifier. Its timestamp ordering is
// useful for database indexes; the random portion prevents collisions.
func NewStableID(now time.Time, random io.Reader) (string, error) {
	if random == nil {
		random = cryptorand.Reader
	}
	millis := now.UTC().UnixMilli()
	if millis < 0 || uint64(millis) > (1<<48)-1 {
		return "", fmt.Errorf("identifier timestamp is outside UUIDv7 range")
	}
	value := make([]byte, 16)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", fmt.Errorf("generate identifier randomness: %w", err)
	}
	value[0] = byte(millis >> 40)
	value[1] = byte(millis >> 32)
	value[2] = byte(millis >> 24)
	value[3] = byte(millis >> 16)
	value[4] = byte(millis >> 8)
	value[5] = byte(millis)
	value[6] = (value[6] & 0x0f) | 0x70
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

var errRedirectsDisabled = errors.New("webhook redirects are disabled")
