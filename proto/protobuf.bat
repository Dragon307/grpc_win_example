C:\grpc64d\protobuf\bin\protoc.exe -I . --grpc_out=. --plugin=protoc-gen-grpc=C:\grpc64d\grpc\bin\grpc_cpp_plugin.exe helloworld.proto
C:\grpc64d\protobuf\bin\protoc.exe -I . --cpp_out=. helloworld.proto
copy helloworld.grpc.pb.* greeter_client\
copy helloworld.pb.* greeter_client\
copy helloworld.grpc.pb.* greeter_server\
copy helloworld.pb.* greeter_server\

