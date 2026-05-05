package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

func main() {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	token := pg.APIKeyTokenPrefix + body
	prefix := body[:pg.APIKeyPrefixLen]
	hash, err := pg.HashArgon2id(token)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("TOKEN=%s\nPREFIX=%s\nHASH=%s\n", token, prefix, hash)
}
