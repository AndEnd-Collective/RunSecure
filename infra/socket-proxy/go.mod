module github.com/AndEnd-Collective/runsecure/infra/socket-proxy

go 1.27.1

require (
	github.com/AndEnd-Collective/runsecure/infra/telemetry v0.0.0-20261122003207-606585840a0c
	github.com/stretchr/testify v1.12.1
)

require go.yaml.in/yaml/v3 v3.0.6 // indirect

replace github.com/AndEnd-Collective/runsecure/infra/telemetry => ../telemetry
