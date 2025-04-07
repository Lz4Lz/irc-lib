package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// PasskeyEncryptString encrypts the plaintext string with the given passkey, and produces a base64-encoded encrypted output
func PasskeyEncryptString(plaintext, passkey string) (string, error) {
	data := []byte(plaintext)

	// Generate random salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	// Derive 32-byte key from passkey using PBKDF2
	key := pbkdf2.Key([]byte(passkey), salt, 4096, 32, sha256.New)

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create AES GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt string
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Combine salt, nonce, and ciphertext into one output
	result := append(salt, nonce...)
	result = append(result, ciphertext...)

	return base64.StdEncoding.EncodeToString(result), nil
}

// PasskeyDecryptString decrypts a base64-encoded ciphertext created by PasskeyEncryptString, into a raw usable string
func PasskeyDecryptString(ciphertext, passkey string) (string, error) {
	// Decode base64 input
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Extract salt, nonce, and ciphertext
	if len(data) < 28 { // Ensure components are present: 16 (salt) + 12 (nonce) minimum
		return "", fmt.Errorf("invalid ciphertext length")
	}
	salt := data[:16]
	nonce := data[16:28] // GCM standard nonce size of 12
	cipherBytes := data[28:]

	// Derive original key from passkey and salt
	key := pbkdf2.Key([]byte(passkey), salt, 4096, 32, sha256.New)

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create AES GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, cipherBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
