module github.com/t3rmit3/slither/server

go 1.24

require (
	github.com/t3rmit3/slither/pkg v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/t3rmit3/slither/pkg => ../pkg
