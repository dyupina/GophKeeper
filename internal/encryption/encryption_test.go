package encryption

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate encryption key: %v", err)
	}

	plaintext := []byte("This is a secret message!")

	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text does not match plaintext. Expected: %s, Got: %s", plaintext, decrypted)
	}
}

func TestEncryptInvalidKey(t *testing.T) {
	invalidKey := []byte("short-key") // Key shorter than KeySize (32 bytes)
	plaintext := []byte("This is a test")

	_, err := Encrypt(plaintext, invalidKey)
	if err == nil {
		t.Errorf("Expected error for invalid key size, but got nil")
	}
}

func TestGenerateKey(t *testing.T) {
	masterKey := "my-master-key"
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("failed to generate salt: %v", err)
	}

	key := GenerateKey(masterKey, salt)

	if len(key) != KeySize {
		t.Errorf("Generated key has incorrect length. Expected: %d, Got: %d", KeySize, len(key))
	}
}

func TestGenerateMasterKey(t *testing.T) {
	masterKey, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey failed: %v", err)
	}

	decodedKey, err := base64.StdEncoding.DecodeString(masterKey)
	if err != nil {
		t.Fatalf("Failed to decode Base64 master key: %v", err)
	}

	if len(decodedKey) != KeySize {
		t.Errorf("Generated master key has incorrect length. Expected: %d, Got: %d", KeySize, len(decodedKey))
	}
}
