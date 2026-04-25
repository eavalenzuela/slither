package pg

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/argon2"
)

// BootstrapAdmin ensures an admin user exists. Behaviour is idempotent:
//
//   - If any user with role='admin' is already present, BootstrapAdmin
//     returns ("", false, nil). The compose stack calls this on every
//     start; a no-op on re-runs is what we want.
//   - Otherwise it inserts username with a fresh argon2id hash of
//     plaintextPassword and returns (id, true, nil). When the caller
//     supplied an empty plaintextPassword, BootstrapAdmin generates a
//     random URL-safe 24-byte password and returns it via the second
//     return value's error path; see slither-db's bootstrap-admin
//     subcommand for the wrapping that prints it.
//
// The argon2id parameters follow OWASP "second recommended" defaults:
// 64 MiB memory, 3 iterations, parallelism 4, 16-byte salt, 32-byte
// hash. Phase 5 may revisit with login latency targets.
func (s *Store) BootstrapAdmin(ctx context.Context, username, plaintextPassword string) (id string, created bool, err error) {
	if username == "" {
		return "", false, errors.New("pg.BootstrapAdmin: username required")
	}
	if plaintextPassword == "" {
		return "", false, errors.New("pg.BootstrapAdmin: password required")
	}

	var existing string
	err = s.pool.QueryRow(ctx, `
		SELECT id::text FROM users WHERE role = 'admin' LIMIT 1
	`).Scan(&existing)
	switch {
	case err == nil:
		return "", false, nil
	case errors.Is(err, pgx.ErrNoRows):
		// fall through to insert
	default:
		return "", false, fmt.Errorf("pg.BootstrapAdmin: probe: %w", err)
	}

	hash, herr := HashArgon2id(plaintextPassword)
	if herr != nil {
		return "", false, fmt.Errorf("pg.BootstrapAdmin: hash: %w", herr)
	}
	id, ierr := s.InsertUser(ctx, username, hash, RoleAdmin)
	if ierr != nil {
		return "", false, fmt.Errorf("pg.BootstrapAdmin: insert: %w", ierr)
	}
	return id, true, nil
}

// HashArgon2id returns a self-describing argon2id hash of plaintext in
// the standard PHC format ($argon2id$v=19$m=...,t=...,p=...$salt$hash).
// Exposed so #41 console signup uses the same parameters as bootstrap.
func HashArgon2id(plaintext string) (string, error) {
	const (
		memoryKiB = 64 * 1024
		iters     = 3
		parallel  = 4
		saltLen   = 16
		hashLen   = 32
	)
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt: %w", err)
	}
	hash := argon2.IDKey([]byte(plaintext), salt, iters, memoryKiB, parallel, hashLen)
	enc := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKiB, iters, parallel,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))
	return enc, nil
}

// VerifyArgon2id constant-time-compares plaintext against an encoded
// argon2id hash. Returns false on any structural error so callers can
// uniformly treat invalid hashes as auth failures.
func VerifyArgon2id(encoded, plaintext string) bool {
	var version int
	var memoryKiB, iters uint32
	var parallel uint8
	var saltB64, hashB64 string
	n, err := fmt.Sscanf(encoded,
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s",
		&version, &memoryKiB, &iters, &parallel, &saltB64)
	if err != nil || n != 5 {
		return false
	}
	// The trailing $hash is left in saltB64 by Sscanf when there's no
	// whitespace separator — split manually.
	for i := 0; i < len(saltB64); i++ {
		if saltB64[i] == '$' {
			hashB64 = saltB64[i+1:]
			saltB64 = saltB64[:i]
			break
		}
	}
	if hashB64 == "" {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(hashB64)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(plaintext), salt, iters, memoryKiB, parallel, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
