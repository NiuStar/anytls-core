package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var webPasswordMu sync.Mutex

const webSessionTTL = 8 * time.Hour
const webCookieName = "anytls_session"

func webRandom(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// This recoverable, application-only secret is not a macOS/sudo password.
// Entropy is 192 bits; storing a slow hash would prevent the requested CLI recovery.
func webReadPassword(path string) (string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return "", errors.New("WebUI password must be a regular 0600 file")
	}
	b, err := readSnapshotSource(path, 128, false)
	if err != nil {
		return "", errors.New("WebUI password cannot be read")
	}
	password := strings.TrimSuffix(string(b), "\n")
	decoded, err := base64.RawURLEncoding.DecodeString(password)
	if err != nil || len(decoded) != 24 || len(password) != 32 {
		return "", errors.New("invalid WebUI password file; use password reset")
	}
	return password, nil
}
func webPassword(path string, reset bool) (string, error) {
	webPasswordMu.Lock()
	defer webPasswordMu.Unlock()
	current, err := webReadPassword(path)
	if err == nil && !reset {
		return current, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) && !reset {
		return "", err
	}
	if reset {
		if st, e := os.Lstat(path); e == nil && !st.Mode().IsRegular() {
			return "", errors.New("WebUI password target must be regular")
		}
	}
	password, err := webRandom(24)
	if err != nil {
		return "", err
	}
	if reset {
		if err := webAtomicWrite(path, []byte(password+"\n")); err != nil {
			return "", err
		}
	} else {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, os.ErrExist) {
			return webReadPassword(path)
		}
		if err != nil {
			return "", err
		}
		_, writeErr := io.WriteString(f, password+"\n")
		syncErr := f.Sync()
		closeErr := f.Close()
		if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
			return "", err
		}
	}
	return webReadPassword(path)
}
func passwordCommand(args []string) error {
	if len(args) > 1 || (len(args) == 1 && args[0] != "reset") {
		return errors.New("usage: anytls password [reset]")
	}
	_, config, _, err := servicePaths()
	if err != nil {
		return err
	}
	password, err := webPassword(filepath.Join(filepath.Dir(config), "webui.password"), len(args) == 1)
	if err != nil {
		return err
	}
	fmt.Println("WebUI account: admin")
	fmt.Println("WebUI password: " + password)
	if len(args) == 1 {
		fmt.Println("Password rotated; existing WebUI sessions are invalid.")
	}
	return nil
}
func webAtomicWrite(path string, b []byte) error {
	if st, err := os.Lstat(path); err == nil {
		if !st.Mode().IsRegular() {
			return errors.New("target must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".anytls-web-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	n, err := f.Write(b)
	if err != nil || n != len(b) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return errors.Join(err, f.Close())
	}
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func webEqual(a, b string) bool {
	x, y := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(x[:], y[:]) == 1
}

type webSession struct {
	csrf         string
	expires      time.Time
	passwordHash [32]byte
}
