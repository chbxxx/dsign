protoc --go_out=plugins=grpc:. -I $GOPATH/src:. ectypes.proto
protoc --go_out=plugins=grpc:. -I $GOPATH/src:. edtypes.proto
