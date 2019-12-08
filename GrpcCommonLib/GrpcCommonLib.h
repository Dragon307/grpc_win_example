#pragma once


void win_get_trusted_roots(
    HCERTSTORE  hCertStore,
    int* pem_roots_Length,          // Excludes NULL terminator
    char** pem_roots);               // LocalFree()


void win_get_engine_key_id(
    PCCERT_CONTEXT pCertContext,
    char* store_name,
    int* key_id_Length,
    char** key_id);

void win_get_cert_chain(
    PCCERT_CONTEXT pCertContext,
    int* pem_chain_length,
    char** pem_chain);

PCCERT_CONTEXT win_get_cert_context(
    char* store_name,
    char* subject_name);

int win_verify_peer_certs(
    HCERTCHAINENGINE hChainEngine,
    int certLength,
    const char* certBytes);

int win_open_mem_store(
    int certLength,
    const char* certBytes,
    HCERTSTORE* hCertStore);
