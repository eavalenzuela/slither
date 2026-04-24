// Package mtls owns the slither CA: loading the CA key/cert from disk,
// issuing per-host client certs from CSRs, and building TLS configs for
// the listeners in package grpcserv.
//
// Phase 2 §4.1: scaffolded in #31; real CA load + SignCSR land in #33.
package mtls
