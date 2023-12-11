package domain

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strings"
)

func HashAndEncode(id []byte) string {
	hash := sha256.Sum256(id)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func FixStringEncoding(content string) string {
	content = strings.ReplaceAll(content, "+", "-")
	content = strings.ReplaceAll(content, "/", "_")
	content = strings.ReplaceAll(content, "=", "")
	return content
}

func FixEncoding(content []byte) io.Reader {
	allStr := string(content)
	return strings.NewReader(FixStringEncoding(allStr))
}
