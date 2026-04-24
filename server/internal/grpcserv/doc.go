// Package grpcserv hosts the gRPC listeners: an mTLS-authenticated Session
// listener for enrolled agents and a separate pre-cert Enroll listener.
//
// Phase 2 §4.1: scaffolded in #31; mTLS listener wiring lands in #33,
// Enroll RPC in #34, Session handler + ingest fan-out in #37, and
// ruleset push in #39.
package grpcserv
