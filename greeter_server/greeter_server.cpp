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
#include <grpcpp/security/server_credentials.h>

#include "../proto/helloworld.grpc.pb.h"
#include "../GrpcCommonLib/GrpcCommonLib.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::AuthContext;
using helloworld::HelloRequest;
using helloworld::HelloReply;
using helloworld::Greeter;

bool verify_client = false;
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

HCERTSTORE hRootCertStore = NULL;
HCERTCHAINENGINE hChainEngine = NULL;

typedef class ::grpc_impl::experimental::TlsKeyMaterialsConfig TlsKeyMaterialsConfig;
typedef class ::grpc_impl::experimental::TlsCredentialReloadArg TlsCredentialReloadArg;
typedef struct ::grpc_impl::experimental::TlsCredentialReloadInterface TlsCredentialReloadInterface;
typedef struct ::grpc_impl::experimental::TlsServerAuthorizationCheckInterface TlsServerAuthorizationCheckInterface;
typedef class ::grpc_impl::experimental::TlsServerAuthorizationCheckArg TlsServerAuthorizationCheckArg;
typedef class ::grpc_impl::experimental::TlsServerAuthorizationCheckConfig TlsServerAuthorizationCheckConfig;
typedef class ::grpc_impl::experimental::TlsCredentialsOptions TlsCredentialsOptions;

// Logic and data behind the server's behavior.
class GreeterServiceImpl final : public Greeter::Service {
    Status SayHello(ServerContext* context, const HelloRequest* request,
        HelloReply* reply) override {

        std::shared_ptr<const AuthContext> auth_ctx = context->auth_context();

        if (auth_ctx)
        {
            printf("\nGot Auth Context\n");
            grpc::string_ref endCert;
            grpc::string_ref certChain;

            std::vector<grpc::string_ref> ClientCertProperty =
                auth_ctx->FindPropertyValues(GRPC_X509_PEM_CERT_PROPERTY_NAME);
            for (grpc::string_ref cert : ClientCertProperty) {
                printf("\nClientCert:\n%s\n\n", cert.data());
                endCert = cert;
            }

            std::vector<grpc::string_ref> ClientCertChainProperty =
                auth_ctx->FindPropertyValues(GRPC_X509_PEM_CERT_CHAIN_PROPERTY_NAME);

            for (grpc::string_ref certChainString : ClientCertChainProperty) {
                printf("\nClientCertChain:\n%s\n\n", certChainString.data());
                certChain = certChainString;
            }

            if (win_verify_peer_certs(
                    hChainEngine,
                    certChain.length(),
                    certChain.data(),
                    endCert.length(),
                    endCert.data()))
            {
                printf("Chain is verified\n");
                std::string prefix("Hello ");
                reply->set_message(prefix + request->name());
                return Status::OK;
            }
            else
            {
                printf("Chain is not verified\n");
                return Status::CANCELLED;
            }
        }
        else
        {
            std::string prefix("Hello ");
            reply->set_message(prefix + request->name());
            return Status::OK;
        }
    }
};

std::shared_ptr<grpc::ServerCredentials>
_grpc_get_server_credentials(
    char* rootCerts,
    char* certChain,
    char* keyId,
    bool requestClientCert)
{
    std::shared_ptr<grpc::ServerCredentials> server_credentials = nullptr;
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

    if (requestClientCert)
    {
        TlsCredentialsOptions credential_options = TlsCredentialsOptions(
            GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_BUT_DONT_VERIFY,
            GRPC_SSL_SKIP_ALL_SERVER_VERIFICATION,
            key_materials_config,
            nullptr,
            nullptr);
        server_credentials = TlsServerCredentials(credential_options);
    }
    else
    {
        TlsCredentialsOptions credential_options = TlsCredentialsOptions(
            GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE,
            GRPC_SSL_SKIP_ALL_SERVER_VERIFICATION,
            key_materials_config,
            nullptr,
            nullptr);
        server_credentials = TlsServerCredentials(credential_options);
    }
    return server_credentials;
}


void RunServer() {
    printf("Server Address: %s\n", server_address);
    std::string serverAddress(server_address);
    GreeterServiceImpl service;
    std::shared_ptr<grpc::ServerCredentials> serverChannelCredentials =
        _grpc_get_server_credentials(
            pem_roots,
            pem_cert_chain,
            keyId,
            verify_client);
    ServerBuilder builder;
    builder.AddListeningPort(serverAddress, serverChannelCredentials);
    builder.RegisterService(&service);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    if (server) {
        printf("Server listening on %s\n", server_address);
        server->Wait();
    }
    else {
        printf("Server Builder Failed\n");
    }

}

void Usage(void)
{
    printf("Usage: greeter_server [options]\n");
    printf("Options are:\n");
    printf("  -?                            - This message\n");
    printf("  -v                            - Verbose\n");
    printf("  -address <string>             - Server address Example: 0.0.0.0:50051 \n");
    printf("  -roots <filename>             - Roots certs in PEM format\n");
    printf("  -rootStore <store name>       - Root store Name Example: ROOT, My\n");
    printf("  -cert <filename>              - Server cert chain PEM file\n");
    printf("  -certName  <string>           - Server cert name to look for.\n");
    printf("  -certStore <store name>       - Server cert store name. \n");
    printf("  -key <key>                    - engine:<engine_name>:<KeyId>\n");
    printf("  -keyFile <filename>           - File containing engine key id string\n");
    printf("  -verifyClient                 - Verify client cert \n");
    printf("\n");
}

int main(int argc, char** argv)
{
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
            else if (_stricmp(argv[0] + 1, "verifyClient") == 0)
            {
                verify_client = true;
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
        printf("Specify either serverCertsChain or serverCertName \n");
        goto BadUsage;
    }

    if (roots_file)
    {
        std::ifstream fileStream(roots_file);
        std::string fileContents((std::istreambuf_iterator<char>(fileStream)),std::istreambuf_iterator<char>());

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
        std::ifstream serverCertFile(certs_file);
        std::string fileContents((std::istreambuf_iterator<char>(serverCertFile)), std::istreambuf_iterator<char>());
        pem_cert_chain = (char*)LocalAlloc(LPTR, fileContents.length() + 1);
        if (pem_cert_chain == nullptr) {
            printf("Can't allocate \n");
            ReturnStatus = -1;
            goto CommonReturn;
        }
        memcpy(pem_cert_chain, fileContents.c_str(), fileContents.length());
    }
    else if (cert_name && cert_store)
    {
        int pem_chain_length = 0;
        int key_id_length = 0;
        PCCERT_CONTEXT pCertContext = win_get_cert_context(cert_store, cert_name);
        if (pCertContext != nullptr)
        {
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

    if (!pem_cert_chain)
    {
        printf("Missing server chain information\n");
        goto BadUsage;
    }
    else
    {
        printf("Cert Chain:\n%s\n\n", pem_cert_chain);
    }

    if (!keyId)
    {
        printf("Missing key Id\n");
        goto BadUsage;
    }
    else
    {
        printf("KeyId:\n%s\n\n", keyId);
    }

    RunServer();

    ReturnStatus = 0;
CommonReturn:
    LocalFree(pem_roots);
    LocalFree(pem_cert_chain);
    LocalFree(keyId);

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
