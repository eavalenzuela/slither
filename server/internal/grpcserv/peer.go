package grpcserv

import (
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// peerTLSInfo extracts a credentials.TLSInfo from a peer.Peer. Split
// into its own file so the import of grpc/credentials is colocated with
// where it's actually used and so test files can shadow it cleanly.
func peerTLSInfo(p *peer.Peer) (credentials.TLSInfo, bool) {
	if p == nil {
		return credentials.TLSInfo{}, false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	return tlsInfo, ok
}
