package webhook

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestCredentialCipherRoundTripRotationAndAuthentication(t *testing.T) {
	t.Parallel()
	key1 := bytes.Repeat([]byte{1}, 32)
	key2 := bytes.Repeat([]byte{2}, 32)
	oldCipher, err := NewCredentialCipher(1, map[uint32][]byte{1: key1})
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("delivery/tenant/task")
	plaintext := []byte(`{"token":"secret"}`)
	envelope, err := oldCipher.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(envelope, []byte("secret")) {
		t.Fatal("ciphertext contains plaintext credential")
	}
	rotated, err := NewCredentialCipher(2, map[uint32][]byte{1: key1, 2: key2})
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := rotated.Decrypt(envelope, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypt() = %q, want %q", decrypted, plaintext)
	}
	if _, err := rotated.Decrypt(envelope, []byte("another-delivery")); err == nil {
		t.Fatal("Decrypt() with different associated data succeeded")
	}
	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)-1] ^= 1
	if _, err := rotated.Decrypt(tampered, aad); err == nil {
		t.Fatal("Decrypt() of tampered envelope succeeded")
	}
}

func TestCredentialCipherRejectsInvalidKeyringsAndEnvelopes(t *testing.T) {
	t.Parallel()
	if _, err := NewCredentialCipher(1, map[uint32][]byte{1: make([]byte, 31)}); err == nil {
		t.Fatal("NewCredentialCipher() accepted a non-AES-256 key")
	}
	cipher, err := NewCredentialCipher(1, map[uint32][]byte{1: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	for _, envelope := range [][]byte{nil, {2, 0, 0, 0, 1}, {1, 0, 0, 0, 2}} {
		if _, err := cipher.Decrypt(envelope, nil); err == nil {
			t.Fatalf("Decrypt(%v) error = nil", envelope)
		}
	}
}

func TestEd25519SignatureBindsIDTimestampAndPayload(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := Ed25519Signer{KeyID: "signing-key-1", PrivateKey: privateKey}
	headers, err := signer.sign("delivery-1", time.Unix(1_700_000_000, 0), []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySignature(publicKey, "delivery-1", headers[HeaderDeliveryTimestamp], headers[HeaderDeliverySignature], []byte("payload")) {
		t.Fatal("VerifySignature() rejected a valid signature")
	}
	if VerifySignature(publicKey, "delivery-2", headers[HeaderDeliveryTimestamp], headers[HeaderDeliverySignature], []byte("payload")) {
		t.Fatal("signature did not bind the delivery ID")
	}
	if VerifySignature(publicKey, "delivery-1", headers[HeaderDeliveryTimestamp], headers[HeaderDeliverySignature], []byte("changed")) {
		t.Fatal("signature did not bind the payload")
	}
}

func TestNewStableIDIsUUIDv7AndUnique(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 123_000_000)
	first, err := NewStableID(now, strings.NewReader(strings.Repeat("a", 16)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewStableID(now, strings.NewReader(strings.Repeat("b", 16)))
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 36 || first[14] != '7' || !strings.Contains("89ab", string(first[19])) {
		t.Fatalf("NewStableID() = %q, want UUIDv7", first)
	}
	if first == second {
		t.Fatal("NewStableID() produced a collision")
	}
}
