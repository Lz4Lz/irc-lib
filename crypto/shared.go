package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// encryptDataWithKey encrypts given data using the given 32-byte AES key.
// It returns (12-byte IV) + (encrypted data).
func encryptDataWithKey(data, key []byte) ([]byte, error) {
	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
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
		return nil, fmt.Errorf("failed to generate IV (nonce): %w", err)
	}

	// Encrypt the data
	encrypted := gcm.Seal(nil, iv, data, nil)

	return append(iv, encrypted...), nil
}

// decryptDataWithKey decrypts given data (IV + ciphertext) using the given 32-byte AES key.
// It returns the original decrypted data.
func decryptDataWithKey(data, key []byte) ([]byte, error) {
	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create AES GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Check if data is long enough to contain IV and ciphertext
	nonceSize := gcm.NonceSize() // Standard 12 bytes
	if len(data) < nonceSize {
		return nil, fmt.Errorf("data too short: missing IV")
	}

	// Split IV and ciphertext
	iv := data[:nonceSize]
	encrypted := data[nonceSize:]

	// Decrypt ciphertext
	decrypted, err := gcm.Open(nil, iv, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return decrypted, nil
}
