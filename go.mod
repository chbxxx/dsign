module github.com/bluehelix-chain/dsign

go 1.12

require (
	github.com/bluehelix-chain/ed25519 v0.0.0-20210907164056-e5e646770046
	github.com/bluehelix-chain/ed25519/edwards25519 v0.0.0-20210907164056-e5e646770046
	github.com/davecgh/go-spew v1.1.1
	github.com/golang/protobuf v1.5.0
	github.com/radicalrafi/gomorph v0.0.0-20190316104301-a9bc4d1b0ab0
	github.com/stretchr/testify v1.4.0
	google.golang.org/protobuf v1.27.1
)

replace github.com/bluehelix-chain/ed25519 => ../ed25519

replace github.com/bluehelix-chain/ed25519/edwards25519 => ../ed25519/edwards25519
