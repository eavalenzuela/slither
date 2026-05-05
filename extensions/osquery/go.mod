module github.com/t3rmit3/slither/extensions/osquery

go 1.25.0

require (
	github.com/t3rmit3/slither/pkg v0.0.0
	github.com/t3rmit3/slither/proto v0.0.0
	google.golang.org/protobuf v1.36.11
)

replace (
	github.com/t3rmit3/slither/pkg => ../../pkg
	github.com/t3rmit3/slither/proto => ../../proto
)
