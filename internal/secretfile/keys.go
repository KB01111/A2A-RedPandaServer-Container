package secretfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strconv"
)

type AES256Keyring struct {
	CurrentKeyID uint32
	Keys         map[uint32][]byte
}

func ReadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	value, err := ReadString(path, "webhook signing private key", 16<<10)
	if err != nil {
		return nil, err
	}
	data := []byte(value)
	defer wipe(data)
	if block, rest := pem.Decode(data); block != nil {
		if block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("webhook signing key must contain one PKCS#8 PRIVATE KEY PEM block")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse webhook signing PKCS#8 key: %w", err)
		}
		key, ok := parsed.(ed25519.PrivateKey)
		if !ok || len(key) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("webhook signing key must be Ed25519")
		}
		return append(ed25519.PrivateKey(nil), key...), nil
	}
	decoded, err := decodeBase64(value)
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("webhook signing key must be PKCS#8 PEM or base64 Ed25519 private key")
	}
	return ed25519.PrivateKey(decoded), nil
}

func ReadAES256Keyring(path string) (AES256Keyring, error) {
	value, err := ReadString(path, "webhook credential keyring", 64<<10)
	if err != nil {
		return AES256Keyring{}, err
	}
	data := []byte(value)
	defer wipe(data)
	var document struct {
		CurrentKeyID uint32            `json:"currentKeyId"`
		Keys         map[string]string `json:"keys"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return AES256Keyring{}, fmt.Errorf("decode webhook credential keyring: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return AES256Keyring{}, fmt.Errorf("decode webhook credential keyring: trailing data")
	}
	if document.CurrentKeyID == 0 || len(document.Keys) == 0 {
		return AES256Keyring{}, fmt.Errorf("webhook credential keyring requires currentKeyId and keys")
	}
	result := AES256Keyring{CurrentKeyID: document.CurrentKeyID, Keys: make(map[uint32][]byte, len(document.Keys))}
	for rawID, encoded := range document.Keys {
		id, err := strconv.ParseUint(rawID, 10, 32)
		if err != nil || id == 0 {
			return AES256Keyring{}, fmt.Errorf("webhook credential key ID %q is invalid", rawID)
		}
		key, err := decodeBase64(encoded)
		if err != nil || len(key) != 32 {
			return AES256Keyring{}, fmt.Errorf("webhook credential key %q must be base64-encoded 32 bytes", rawID)
		}
		result.Keys[uint32(id)] = key
	}
	if _, ok := result.Keys[result.CurrentKeyID]; !ok {
		return AES256Keyring{}, fmt.Errorf("current webhook credential key is absent from keys")
	}
	return result, nil
}

func decodeBase64(value string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
