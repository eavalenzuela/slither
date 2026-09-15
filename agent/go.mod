module github.com/t3rmit3/slither/agent

go 1.26.0

require (
	github.com/cilium/ebpf v0.22.0
	github.com/google/go-tpm v0.9.8
	github.com/google/uuid v1.6.0
	github.com/t3rmit3/slither/pkg v0.0.0
	github.com/t3rmit3/slither/proto v0.0.0
	golang.org/x/sys v0.48.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)

replace (
	github.com/t3rmit3/slither/pkg => ../pkg
	github.com/t3rmit3/slither/proto => ../proto
)
