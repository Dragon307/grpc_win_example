#pragma once

// Open PEM encoded certs as a HCERTSTORE
bool
win_open_memory_cert_store(
    size_t certLength,
    const char* certBytes,
    HCERTSTORE* hCertStore);

// Create HCERTCHAINENGINE with exclusive HCERTSTORE
bool
win_create_engine_with_exclusive_root_store(
    HCERTSTORE hRootCertStore,
    HCERTCHAINENGINE* hChainEngine);

// Return all the trusted certificates from a HCERTSTORE in PEM encoded format
bool
win_get_trusted_roots(
    HCERTSTORE  hCertStore,
    int* pem_roots_Length,  // Excludes NULL terminator
    char** pem_roots);      // LocalFree()

// Search the store and get Certificate Context from 
PCCERT_CONTEXT
win_get_cert_context(
    char* store_name,
    char* subject_name);

// Get certificate chain in PEM encoded format from PCCERT_CONTEXT
bool
win_get_cert_chain(
    PCCERT_CONTEXT pCertContext,
    int* pem_chain_length,
    char** pem_chain);      // LocalFree()

// Get engine key id from PCCERT_CONTEXT
bool
win_get_engine_key_id(
    PCCERT_CONTEXT pCertContext,
    char* store_name,
    int* key_id_Length,
    char** key_id);         // LocalFree()

// Verify the certs
bool
win_verify_peer_certs(
    HCERTCHAINENGINE hChainEngine,
    size_t certLength,
    const char* certBytes);


