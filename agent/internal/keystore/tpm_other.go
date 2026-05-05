//go:build !linux

package keystore

// tryTPM is a non-Linux stub. The TPM store is Linux-only because
// the kernel device path (/dev/tpmrm0) and the in-tree TPM 2.0
// driver are Linux-specific. On other OSes the AutoSelect chain
// skips TPM and goes straight to the keyring / file path, matching
// the broader Linux-only invariant ADR-0001 records.
func tryTPM(_ string) (Store, error) {
	return nil, errUnsupported
}
