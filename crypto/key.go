package crypto

import (
	"crypto/aes"
	"crypto/cipher"
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

// EncryptData encrypts plaintext using the Key with AES GCM
func (k *CryptKey) EncryptData(plaintext []byte) ([]byte, error) {
	// Create AES cipher block
	block, err := aes.NewCipher(k.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create AES GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random 12-byte IV (nonce)
	iv := make([]byte, gcm.NonceSize()) // 12 bytes for AES-GCM (by default at least)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Encrypt plaintext
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)

	return append(iv, ciphertext...), nil
}

// DecryptData decrypts data (IV and ciphertext) using the Key with AES GCM
func (k *CryptKey) DecryptData(data []byte) ([]byte, error) {
	// Create AES cipher block
	block, err := aes.NewCipher(k.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create AES GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Check if data is long enough to contain IV and ciphertext
	nonceSize := gcm.NonceSize() // 12 bytes
	if len(data) < nonceSize {
		return nil, fmt.Errorf("data too short: missing IV")
	}

	// Split IV and ciphertext
	iv := data[:nonceSize]
	ciphertext := data[nonceSize:]

	// Decrypt ciphertext
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
