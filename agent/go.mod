module github.com/t3rmit3/slither/agent

go 1.25.0

require (
	github.com/cilium/ebpf v0.21.0
	github.com/google/go-tpm v0.9.8
	github.com/google/uuid v1.6.0
	github.com/t3rmit3/slither/pkg v0.0.0
	github.com/t3rmit3/slither/proto v0.0.0
	golang.org/x/sys v0.45.0
	google.golang.org/grpc v1.80.0
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
)

require (
	go.opentelemetry.io/otel/metric v1.41.0 // indirect
	go.opentelemetry.io/otel/trace v1.41.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
)

replace (
	github.com/t3rmit3/slither/pkg => ../pkg
	github.com/t3rmit3/slither/proto => ../proto
)
