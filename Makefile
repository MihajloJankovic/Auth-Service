sudo apt install protoc
protoc -I=protos/ --go_out=protos/files --go-grpc_out=protos/files protos/app.proto