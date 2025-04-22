package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// CryptKey represents a wrapped AES key with a unique ID and builtin encryption functions
type CryptKey struct {
	Key   []byte `json:"key"`    // AES key data
	Name  string `json:"name"`   // Human-readable name for the key
	KeyID string `json:"key_id"` // Unique identifier for the key
}

// NewCryptKey generates a new wrapped random AES-256 key and derives a KeyID
func NewCryptKey() (*CryptKey, error) {
	// Generate 256-bit random key
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Compute KeyID (first 16 bytes of base64-encoded SHA-256-hashed key)
	hash := sha256.Sum256(key)
	keyIDBytes := hash[:16] // Truncate to 128 bits
	keyID := base64.StdEncoding.EncodeToString(keyIDBytes)

	return &CryptKey{
		Key:   key,
		KeyID: keyID,
	}, nil
}

// EncryptData encrypts data using the Key with AES GCM.
// The output data is in the form of (IV/nonce) + (ciphertext).
func (k *CryptKey) EncryptData(data []byte) ([]byte, error) {
	encrypted, err := encryptDataWithKey(data, k.Key)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

// DecryptData decrypts data (IV and ciphertext) using the Key with AES GCM.
// The output data is the original unencrypted data.
func (k *CryptKey) DecryptData(data []byte) ([]byte, error) {
	return decryptDataWithKey(data, k.Key)
}
