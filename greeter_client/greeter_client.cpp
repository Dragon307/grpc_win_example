/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#define NOMINMAX
#include <windows.h>
#include <wincrypt.h>

#include <iostream>
#include <memory>
#include <string>
#include <fstream>
#include <openssl/ssl.h>
#include <openssl/engine.h>

#include <grpcpp/grpcpp.h>
#include <grpc/grpc_security.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/security/tls_credentials_options.h>

#include "../proto/helloworld.grpc.pb.h"
#include "../GrpcCommonLib/GrpcCommonLib.h"

using grpc::Channel;
using grpc::ClientAsyncResponseReader;
using grpc::ClientContext;
using grpc::Status;
using grpc::CompletionQueue;
using grpc::AuthContext;
using helloworld::HelloRequest;
using helloworld::HelloReply;
using helloworld::Greeter;

char* roots_file = nullptr;
char* root_store_name = nullptr;
char* pem_roots = nullptr;
int pem_roots_length = 0;
char* certs_file = nullptr;
char* cert_store = nullptr;
char* cert_name = nullptr;
char* pem_cert_chain = nullptr;
char* keyId = nullptr;
char* keyIdFile = nullptr;
bool userLocation = true;
char* server_address = nullptr;
char* server_name = nullptr;

HCERTSTORE hRootCertStore = NULL;
HCERTCHAINENGINE hChainEngine = NULL;

typedef class ::grpc_impl::experimental::TlsKeyMaterialsConfig TlsKeyMaterialsConfig;
typedef class ::grpc_impl::experimental::TlsCredentialReloadArg TlsCredentialReloadArg;
typedef struct ::grpc_impl::experimental::TlsCredentialReloadInterface TlsCredentialReloadInterface;
typedef struct ::grpc_impl::experimental::TlsServerAuthorizationCheckInterface TlsServerAuthorizationCheckInterface;
typedef class ::grpc_impl::experimental::TlsServerAuthorizationCheckArg TlsServerAuthorizationCheckArg;
typedef class ::grpc_impl::experimental::TlsServerAuthorizationCheckConfig TlsServerAuthorizationCheckConfig;
typedef class ::grpc_impl::experimental::TlsCredentialsOptions TlsCredentialsOptions;
typedef class TestTlsServerAuthorizationCheck TestTlsServerAuthorizationCheck;

std::shared_ptr<TestTlsServerAuthorizationCheck> server_check = nullptr;

class GreeterClient {
public:
    GreeterClient(std::shared_ptr<Channel> channel)
        : stub_(Greeter::NewStub(channel)) {}

    // Assembles the client's payload, sends it and presents the response back
    // from the server.
    std::string SayHello(const std::string& user) {
        // Data we are sending to the server.
        HelloRequest request;
        request.set_name(user);

        // Container for the data we expect from the server.
        HelloReply reply;

        // Context for the client. It could be used to convey extra information to
        // the server and/or tweak certain RPC behaviors.
        ClientContext context;

        // The actual RPC.
        Status status = stub_->SayHello(&context, request, &reply);

        // Act upon its status.
        if (status.ok()) {
            return reply.message();
        }
        else {
            std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
            return "RPC failed";
        }
    }

private:
    std::unique_ptr<Greeter::Stub> stub_;
};


bool verify_server(const char* peer_pem)
{
    int verify_result = 1;
    if (peer_pem == nullptr)
    {
        printf("No Certificates\n");
        return false;
    }

    printf("Peer Cert:\n%s\n", peer_pem);
    if (win_verify_peer_certs(hChainEngine, strlen(peer_pem), peer_pem) == 0) {
        printf("Chain is not verified\n");
        return false;
    }
    else
    {
        printf("Chain is verified\n");
        return true;
    }
}

class TestTlsServerAuthorizationCheck
    : public TlsServerAuthorizationCheckInterface {
    int Schedule(TlsServerAuthorizationCheckArg* arg) override {
        if (arg) {
            if (arg->target_name().c_str())
            {
                printf("Callback TargetName: %s\n", arg->target_name().c_str());
            }

            if (verify_server(arg->peer_cert().c_str()))
            {
                // Chain is verified
                arg->set_cb_user_data(nullptr);
                arg->set_success(1);
                arg->set_status(GRPC_STATUS_OK);
            }
            else
            {
                // Chain is not verified
                arg->set_cb_user_data(nullptr);
                arg->set_success(0);
                arg->set_status(GRPC_STATUS_UNAUTHENTICATED);
            }
        }
        return 0;
    }

    void Cancel(TlsServerAuthorizationCheckArg* arg) override {
        if (arg) {
            arg->set_success(0);
            arg->set_status(GRPC_STATUS_PERMISSION_DENIED);
        }
    }
};

std::shared_ptr<grpc::ChannelCredentials>
_grpc_get_channel_credentials(
    std::shared_ptr<TlsServerAuthorizationCheckConfig> server_check_config,
    char* rootCerts,
    char* certChain,            // Optional, set for client auth
    char* keyId)                // Optional, set for client auth
{
    grpc::string pem_root_certs;
    grpc::string pem_private_key;
    grpc::string pem_cert_chain;
    if (rootCerts) { pem_root_certs = rootCerts; }
    if (certChain) { pem_cert_chain = certChain; }
    if (keyId) { pem_private_key = keyId; }

    // Key Material
    struct TlsKeyMaterialsConfig::PemKeyCertPair pair = { pem_private_key, pem_cert_chain };
    std::shared_ptr<TlsKeyMaterialsConfig> key_materials_config(new TlsKeyMaterialsConfig());
    key_materials_config->set_pem_root_certs(pem_root_certs);
    key_materials_config->add_pem_key_cert_pair(pair);

    // Credential Options
    TlsCredentialsOptions credential_options = TlsCredentialsOptions(
        GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE,
        GRPC_SSL_SKIP_SERVER_CERTIFICATE_VERIFICATION,
        key_materials_config,
        nullptr,
        server_check_config);

    std::shared_ptr<grpc_impl::ChannelCredentials> channel_credentials =
        grpc::experimental::TlsCredentials(credential_options);

    return channel_credentials;
}

void RunClient() {
    printf("Server Address: %s\n", server_address);
    printf("Server Name: %s\n", server_name);
    std::shared_ptr<TestTlsServerAuthorizationCheck>
        server_check(new TestTlsServerAuthorizationCheck());
    std::shared_ptr<TlsServerAuthorizationCheckConfig>
        server_check_config(new TlsServerAuthorizationCheckConfig(server_check));
    std::shared_ptr<grpc::ChannelCredentials> clientChannelCredentials =
        _grpc_get_channel_credentials(
            server_check_config,
            pem_roots,
            pem_cert_chain,
            keyId);
    grpc::ChannelArguments args;
    args.SetSslTargetNameOverride(server_name);
    std::cout << "Creating Custom Channel" << std::endl;
    GreeterClient greeter(grpc::CreateCustomChannel(
        server_address, clientChannelCredentials, args));
    std::string user("world");
    std::string reply = greeter.SayHello(user);
    std::cout << "Greeter received: " << reply << std::endl;
}

void Usage(void)
{
    printf("Usage: greeter_client [options]\n");
    printf("Options are:\n");
    printf("  -?                        - This message\n");
    printf("  -v                        - Verbose\n");
    printf("  -address <string>         - Server address Example: 0.0.0.0:50051 \n");
    printf("  -name <string>            - Server name: 0.0.0.0:50051 \n");
    printf("  -roots <filename>         - Roots certs in PEM format\n");
    printf("  -rootStore <store name>   - Root store Name Example: ROOT, My\n");
    printf("  -cert <filename>          - Server cert chain PEM file\n");
    printf("  -certName  <string>       - Server cert name to look for.\n");
    printf("  -certStore <store name>   - Server cert store name. \n");
    printf("  -key <key>                - engine:<engine_name>:<KeyId>\n");
    printf("  -keyFile <filename>       - File containing engine key id string\n");
    printf("\n");
}

int main(int argc, char** argv) {

    int ReturnStatus = 0;

    while (--argc > 0)
    {
        if (**++argv == '-')
        {
            if (_stricmp(argv[0] + 1, "address") == 0)
            {
                if (argc < 2 || argv[1][0] == '-') {
                    printf("Option (-%s) : missing argument\n", argv[0] + 1);
                    goto BadUsage;
                }
                server_address = argv[1];
                argc -= 1;
                argv += 1;
            }
            if (_stricmp(argv[0] + 1, "name") == 0)
            {
                if (argc < 2 || argv[1][0] == '-') {
                    printf("Option (-%s) : missing argument\n", argv[0] + 1);
                    goto BadUsage;
                }
                server_name = argv[1];
                argc -= 1;
                argv += 1;
            }
            else if (_stricmp(argv[0] + 1, "roots") == 0)
            {
                if (argc < 2 || argv[1][0] == '-') {
                    printf("Option (-%s) : missing argument\n", argv[0] + 1);
                    goto BadUsage;
                }
                roots_file = argv[1];
                argc -= 1;
                argv += 1;
            }
            else if (_stricmp(argv[0] + 1, "rootStore") == 0)
            {
                if (argc < 2 || argv[1][0] == '-') {
                    printf("Option (-%s) : missing argument\n", argv[0] + 1);
                    goto BadUsage;
                }
                root_store_name = argv[1];
                argc -= 1;
                argv += 1;
            }
            else if (_stricmp(argv[0] + 1, "cert") == 0)
            {
                if (argc < 2 || argv[1][0] == '-') {
                    printf("Option (-%s) : missing argument\n", argv[0] + 1);
                    goto BadUsage;
                }
                certs_file = argv[1];
                argc -= 1;
                argv += 1;
            }
            else if (_stricmp(argv[0] + 1, "certName") == 0)
            {
                if (argc < 2 || argv[1][0] == '-') {
                    printf("Option (-%s) : missing argument\n", argv[0] + 1);
                    goto BadUsage;
                }
                cert_name = argv[1];
                argc -= 1;
                argv += 1;
            }
            else if (_stricmp(argv[0] + 1, "certStore") == 0)
            {
                if (argc < 2 || argv[1][0] == '-') {
                    printf("Option (-%s) : missing argument\n", argv[0] + 1);
                    goto BadUsage;
                }
                cert_store = argv[1];
                argc -= 1;
                argv += 1;
            }
            else if (strcmp(argv[0] + 1, "key") == 0)
            {
                if (argc < 2 || argv[1][0] == '-') {
                    printf("Option (-%s) : missing argument\n", argv[0] + 1);
                    goto BadUsage;
                }
                keyId = (char*)LocalAlloc(LPTR, strlen(argv[1]) + 1);
                if (keyId == nullptr)
                {
                    printf("Can't allocate \n");
                    ReturnStatus = -1;
                    goto CommonReturn;
                }
                memcpy(keyId, argv[1], strlen(argv[1]));
                argc -= 1;
                argv += 1;
            }
            else if (strcmp(argv[0] + 1, "keyFile") == 0)
            {
                if (argc < 2 || argv[1][0] == '-') {
                    printf("Option (-%s) : missing argument\n", argv[0] + 1);
                    goto BadUsage;
                }
                keyIdFile = argv[1];
                argc -= 1;
                argv += 1;
            }
            else if (strcmp(argv[0] + 1, "?") == 0)
            {
                goto BadUsage;
            }
        }
    }

    if (roots_file && root_store_name)
    {
        printf("Specify either roots file or root store\n");
        goto BadUsage;
    }

    if (certs_file && cert_name)
    {
        printf("Specify either clientCertsChain or clientCertName \n");
        goto BadUsage;
    }

    if (roots_file)
    {
        std::ifstream fileStream(roots_file);
        std::string fileContents((std::istreambuf_iterator<char>(fileStream)), std::istreambuf_iterator<char>());

        // Open HCERTSTORE from PEM encoded roots
        if (win_open_memory_cert_store(
                fileContents.length(),
                fileContents.c_str(),
                &hRootCertStore))
        {
            // Create an global engine
            if (!win_create_engine_with_exclusive_root_store(hRootCertStore, &hChainEngine))
            {
                printf("Can't create engine \n");
                ReturnStatus = -1;
                goto CommonReturn;
            }
        }
        else
        {
            printf("Can't open mem store from Roots file\n");
            ReturnStatus = -1;
            goto CommonReturn;
        }

        pem_roots = (char*)LocalAlloc(LPTR, fileContents.length() + 1);
        if (pem_roots == nullptr) {
            printf("Can't allocate \n");
            ReturnStatus = -1;
            goto CommonReturn;
        }
        memcpy(pem_roots, fileContents.c_str(), fileContents.length());
    }
    else if (root_store_name)
    {
        printf("Opening Store: %s\n", root_store_name);
        hRootCertStore = CertOpenSystemStoreA(NULL, root_store_name);
        if (hRootCertStore == nullptr)
        {
            printf("Can't open the store\n");
            ReturnStatus = -1;
            goto CommonReturn;
        }

        if (!win_get_trusted_roots(hRootCertStore, &pem_roots_length, &pem_roots))
        {
            printf("Couldn't get the trusted roots from Store\n");
            ReturnStatus = -1;
            goto CommonReturn;
        }

        // Create an global engine
        if (!win_create_engine_with_exclusive_root_store(hRootCertStore, &hChainEngine))
        {
            printf("Can't create engine \n");
            ReturnStatus = -1;
            goto CommonReturn;
        }
    }

    if (certs_file)
    {
        std::ifstream fileStream(certs_file);
        std::string fileContents((std::istreambuf_iterator<char>(fileStream)), std::istreambuf_iterator<char>());
        pem_cert_chain = (char*)LocalAlloc(LPTR, fileContents.length() + 1);
        if (pem_cert_chain == NULL) {
            printf("Can't allocate \n");
            ReturnStatus = -1;
            goto CommonReturn;
        }
        memcpy(pem_cert_chain, fileContents.c_str(), fileContents.length());
    }
    else if(cert_store && cert_name)
    {
        int pem_chain_length = 0;
        int key_id_length = 0;
        PCCERT_CONTEXT pCertContext = win_get_cert_context(cert_store, cert_name);
        if (pCertContext != nullptr) {
            if (!win_get_cert_chain(pCertContext, &pem_chain_length, &pem_cert_chain))
            {
                printf("Can't get the certificate chain\n");
                ReturnStatus = -1;
                goto CommonReturn;
            }

            if (!win_get_engine_key_id(pCertContext, cert_store, &key_id_length, &keyId))
            {
                printf("Can't get the engine id\n");
                ReturnStatus = -1;
                goto CommonReturn;
            }
        }
        else
        {
            printf("Couldn't find the certificate for %s\n", cert_name);
            ReturnStatus = -1;
            goto CommonReturn;
        }
    }

    if (keyIdFile)
    {
        std::ifstream fileStream(keyIdFile);
        std::string fileContents((std::istreambuf_iterator<char>(fileStream)), std::istreambuf_iterator<char>());
        keyId = (char*)LocalAlloc(LPTR, fileContents.length() + 1);
        if (keyId == nullptr)
        {
            printf("Can't allocate \n");
            ReturnStatus = -1;
            goto CommonReturn;
        }
        memcpy(keyId, fileContents.c_str(), fileContents.length());
    }

    if (!pem_roots)
    {
        printf("Missing Root Information\n");
        goto BadUsage;
    }
    else
    {
        printf("Root Certs:\n%s\n\n", pem_roots);
    }

    if (pem_cert_chain)
    {
        printf("Cert Chain:\n%s\n\n", pem_cert_chain);
    }

    if (keyId)
    {
        printf("KeyId:\n%s\n\n", keyId);
    }

    RunClient();

    ReturnStatus = 0;
CommonReturn:
    LocalFree(pem_roots);
    LocalFree(keyId);
    LocalFree(pem_cert_chain);

    if (hChainEngine) {
        CertFreeCertificateChainEngine(hChainEngine);
    }

    if (hRootCertStore)
    {
        CertCloseStore(hRootCertStore, 0);
    }

    return ReturnStatus;

BadUsage:
    Usage();
    ReturnStatus = -1;
    goto CommonReturn;
}
