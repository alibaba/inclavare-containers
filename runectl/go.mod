module github.com/inclavare-containers/runectl

go 1.14

require (
	github.com/go-restruct/restruct v0.0.0-20191227155143-5734170a48a1
	github.com/golang/protobuf v1.4.2
	github.com/opencontainers/runc v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.6.0
	github.com/urfave/cli v1.22.4
)

replace github.com/opencontainers/runc => github.com/alibaba/inclavare-containers/rune v0.0.0-20200527123028-5b951e6d3bb0
