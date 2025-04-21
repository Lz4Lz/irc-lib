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

// PasskeyEncrypt encrypts the binary data with the given passkey, and returns the encrypted binary output data
func PasskeyEncrypt(data []byte, passkey string) ([]byte, error) {
	// Generate random salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	// Derive 32-byte key from passkey using PBKDF2
	key := pbkdf2.Key([]byte(passkey), salt, 4096, 32, sha256.New)

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create AES GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate random nonce (IV)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt string
	encrypted := gcm.Seal(nil, nonce, data, nil)

	// Combine salt, nonce, and encrypted data into one output
	result := append(salt, nonce...)
	result = append(result, encrypted...)

	return result, nil
}

// PasskeyDecrypt decrypts the encrypted binary data with the given passkey, into decrypted raw binary data
func PasskeyDecrypt(data []byte, passkey string) ([]byte, error) {
	// Extract salt, nonce, and encrypted data
	if len(data) < 28 { // Ensure components are present: 16 (salt) + 12 (nonce) minimum
		return nil, fmt.Errorf("invalid ciphertext length")
	}
	salt := data[:16]
	nonce := data[16:28] // GCM standard nonce size of 12
	encrypted := data[28:]

	// Derive original key from passkey and salt
	key := pbkdf2.Key([]byte(passkey), salt, 4096, 32, sha256.New)

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create AES GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt data
	decrypted, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

// PasskeyEncryptString encrypts the plaintext string with the given passkey, and produces a base64-encoded encrypted output
func PasskeyEncryptString(plaintext, passkey string) (string, error) {
	data := []byte(plaintext)
	result, err := PasskeyEncrypt(data, passkey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(result), nil
}

// PasskeyDecryptString decrypts a base64-encoded ciphertext created by PasskeyEncryptString, into a raw usable string
func PasskeyDecryptString(ciphertext, passkey string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	result, err := PasskeyDecrypt(data, passkey)
	if err != nil {
		return "", err
	}
	return string(result), nil
}
