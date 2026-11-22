package subscription

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const identitySize = 32

// originHWID derives a different public identifier for each HTTPS origin from
// the same private installation secret.
func originHWID(path, origin string) (string, error) {
	secret, err := installationSecret(path)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(origin))
	return hex.EncodeToString(mac.Sum(nil)[:16]), nil
}

func installationSecret(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("installation identity path is required")
	}
	data, err := readIdentity(path)
	if !errors.Is(err, os.ErrNotExist) {
		return data, err
	}
	secret := make([]byte, identitySize)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := installIdentity(path, secret); err != nil {
		if errors.Is(err, os.ErrExist) {
			return readIdentity(path)
		}
		return nil, err
	}
	return secret, nil
}

func readIdentity(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() != identitySize {
		return nil, errors.New("invalid installation identity file")
	}
	secret := make([]byte, identitySize)
	_, err = io.ReadFull(file, secret)
	return secret, err
}

func installIdentity(path string, secret []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".subscription-identity-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(secret); err != nil {
		file.Close()
		return err
	}
	writeErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	// Publish the complete private file without replacing a concurrent winner.
	return os.Link(file.Name(), path)
}
