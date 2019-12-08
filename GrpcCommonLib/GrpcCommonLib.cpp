// GrpcWinCommon.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "framework.h"
#define NOMINMAX
#include <windows.h>
#include <wincrypt.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>

__inline
DWORD
_GetNonzeroLastError()
{
    DWORD dwError = GetLastError();

    if (dwError == 0)
    {
        dwError = (DWORD)E_UNEXPECTED;
    }

    return dwError;
}

void
_DumpHex(
    const char* prefixString,
    BYTE* pbBinary,
    DWORD cbBinary)
{
    CHAR* szString = NULL;
    DWORD dwStringSize = 0;

    if (CryptBinaryToStringA(pbBinary, cbBinary, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, NULL, &dwStringSize))
    {
        szString = (CHAR*)LocalAlloc(LPTR, dwStringSize * sizeof(CHAR));
        if (szString)
        {
            if (CryptBinaryToStringA(pbBinary, cbBinary, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, szString, &dwStringSize))
            {
                printf("%s: %s\n", prefixString, szString);
            }
            LocalFree(szString);
        }
    }
}

static
bool ConvertAnsiToUnicode(
    LPCSTR pszAnsi,
    LPWSTR *ppwszUnicode)
{
    bool   fResult = false;
    LPWSTR pwszUnicode = NULL;
    DWORD  dwWideSize = 0;
    DWORD  dwSizeToAlloc = 0;
    *ppwszUnicode = NULL;

    if (!(dwWideSize = MultiByteToWideChar(CP_UTF8, 0, pszAnsi, strlen(pszAnsi), NULL, 0)))
    {
        goto ErrorReturn;
    }

    if (!(pwszUnicode = (WCHAR*)LocalAlloc(LPTR, (dwWideSize + 1) * sizeof(WCHAR))))
    {
        goto ErrorReturn;
    }

    if (!MultiByteToWideChar(CP_UTF8, 0, pszAnsi, strlen(pszAnsi), pwszUnicode, dwWideSize))
    {
        LocalFree(pwszUnicode);
        goto ErrorReturn;
    }
    *ppwszUnicode = pwszUnicode;
    fResult = true;
CommonReturn:
    return fResult;
ErrorReturn:
    fResult = false;
    goto CommonReturn;
}

HRESULT
_CertNameToStr(
    DWORD dwCertEncodingType,
    CERT_NAME_BLOB const* pName,
    DWORD dwStrType,
    PWSTR* ppwszName)
{
    HRESULT hr;
    DWORD cwc = 0;
    WCHAR* pwszName = NULL;

    for (;;)
    {
        cwc = CertNameToStr(
            dwCertEncodingType,
            const_cast<CERT_NAME_BLOB*>(pName),
            dwStrType,
            pwszName,
            cwc);
        if (1 > cwc)
        {
            hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
            goto error;
        }
        if (NULL != pwszName)
        {
            break;
        }
        pwszName = (WCHAR*)LocalAlloc(
            LPTR,
            (cwc + 1) * sizeof(WCHAR));
        if (NULL == pwszName)
        {
            hr = E_OUTOFMEMORY;
            goto error;
        }
    }
    *ppwszName = pwszName;
    pwszName = NULL;
    hr = S_OK;

error:
    if (NULL != pwszName)
    {
        LocalFree(pwszName);
    }
    return(hr);
}

HRESULT
DisplayCertInfo(
    PCCERT_CONTEXT pCertContext)
{
    HRESULT hr = S_OK;
    DWORD Flags = CERT_X500_NAME_STR |
        CERT_NAME_STR_REVERSE_FLAG |
        CERT_NAME_STR_NO_QUOTING_FLAG |
        CERT_NAME_STR_ENABLE_PUNYCODE_FLAG;
    PWSTR pwszSubject = NULL;
    PWSTR pwszIssuer = NULL;

    if (SUCCEEDED(_CertNameToStr(
        X509_ASN_ENCODING,
        &pCertContext->pCertInfo->Subject,
        Flags,
        &pwszSubject)))
    {
        printf("Subject: %S\n", pwszSubject);
    }

    if (SUCCEEDED(_CertNameToStr(
        X509_ASN_ENCODING,
        &pCertContext->pCertInfo->Issuer,
        Flags,
        &pwszIssuer)))
    {
        printf("Issuer:  %S\n", pwszIssuer);
    }
    printf("--------------------------------------------------------------------\n");
CommonReturn:
    return hr;
}

void win_get_trusted_roots(
    HCERTSTORE  hCertStore,
    int* pem_roots_Length,          // Excludes NULL terminator
    char** pem_roots)               // LocalFree()
{
    X509* cert = NULL;
    BIO* mem = NULL;
    int memLen = 0;
    const unsigned char* memBytes = NULL;   // Don't free
    *pem_roots_Length = 0;
    PCCERT_CONTEXT pCertContext = NULL;
    int certCount = 0;

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL) {
        goto end;
    }

    while ((pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) != 0)
    {
        cert = NULL;
        BIO* certBio = NULL;

        DisplayCertInfo(pCertContext);

        certCount++;
        certBio = BIO_new(BIO_s_mem());
        if (certBio == NULL) {
            continue;
        }

        BIO_write(certBio, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);

        cert = d2i_X509_bio(certBio, NULL);
        if (cert == NULL) {
            printf("\n d2i failed. ");
            BIO_printf(certBio, "unable to load certificate\n");
            ERR_print_errors(certBio);
            continue;
        }
        if (!PEM_write_bio_X509(mem, cert)) {
            printf("\n PEM_write_bio_X509 failed. ");
            BIO_printf(certBio, "unable to write PEM file\n");
            ERR_print_errors(certBio);
            continue;
        }

        X509_free(cert);
        cert = NULL;
    }

    memLen = (int)BIO_get_mem_data(mem, (char**)&memBytes);
    if (memLen > 0) {
        *pem_roots = (char*)LocalAlloc(LPTR, memLen + sizeof(char));
        if (*pem_roots == NULL) {
            goto end;
        }
        memcpy(*pem_roots, memBytes, memLen);
        *pem_roots_Length = memLen;
        //printf("\n Roots: \n%s\n", *pem_roots);
    }
    //printf("Found %d roots\n", certCount);

end:
    if (mem) {
        BIO_flush(mem);
        BIO_free(mem);
    }

    return;
}

PCCERT_CONTEXT win_get_cert_context(
    char* store_name,
    char* subject_name
    )
{
    PCCERT_CONTEXT pCertContext = NULL;
    HCERTSTORE  hCertStore = NULL;
    LPWSTR pwszSubjectName = nullptr;

    hCertStore = CertOpenSystemStoreA(NULL, store_name);

    if (hCertStore != NULL)
    {
        //printf("Opened Store: %s\n", store_name);
        if (!ConvertAnsiToUnicode(subject_name, &pwszSubjectName))
        {
            goto CommonReturn;
        }

        pCertContext = CertFindCertificateInStore(
            hCertStore,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_STR,
            pwszSubjectName,
            NULL);
        if (pCertContext == nullptr) {
            printf("Couldn't find the cert for : %S\n", pwszSubjectName);
        }
        CertCloseStore(hCertStore, 0);
    }

CommonReturn:
    return pCertContext;
}

void win_get_cert_chain(
    PCCERT_CONTEXT pCertContext,
    int* pem_chain_length,
    char** pem_chain)               // LocalFree()
{
    HRESULT hr = S_OK;
    DWORD dwError = ERROR_SUCCESS;
    X509* cert = NULL;
    BIO* mem = NULL;
    BUF_MEM* bptr = NULL;
    int memLen = 0;
    const unsigned char* memBytes = NULL;   // Don't free
    int certCount = 0;
    DWORD dwFlags = 0;
    PCERT_SIMPLE_CHAIN pChain = NULL;
    PCCERT_CHAIN_CONTEXT pChainContext = NULL;
    CERT_CHAIN_PARA ChainPara = { 0 };
    ChainPara.cbSize = sizeof(ChainPara);
    CERT_CHAIN_POLICY_PARA PolicyPara = { 0 };
    CERT_CHAIN_POLICY_STATUS PolicyStatus = { 0 };
    *pem_chain_length = 0;

    if (!CertGetCertificateChain(
        NULL,                  // use the default chain engine
        pCertContext,          // pointer to the end certificate
        NULL,                  // use the default time
        NULL,                  // search no additional stores
        &ChainPara,            // use AND logic and enhanced key usage 
        dwFlags,
        NULL,                  // currently reserved
        &pChainContext))       // return a pointer to the chain created
    {
        dwError = _GetNonzeroLastError();
        printf("CertGetCertificateChain Failed: %d \n",dwError);
        goto CommonReturn;
    }

    //printf("The size of the chain context is %d. \n", pChainContext->cbSize);
    //printf("%d simple chains found.\n", pChainContext->cChain);
    //printf("Error status for the chain: %d\n", pChainContext->TrustStatus.dwErrorStatus);
    //printf("Info status for the chain: %d\n", pChainContext->TrustStatus.dwInfoStatus);

    PolicyPara.cbSize = sizeof(PolicyPara);
    PolicyStatus.cbSize = sizeof(PolicyStatus);

    if (!CertVerifyCertificateChainPolicy(
        CERT_CHAIN_POLICY_BASE,
        pChainContext,
        &PolicyPara,
        &PolicyStatus))
    {
        dwError = _GetNonzeroLastError();
        printf("CertVerifyCertificateChainPolicy failed: %d\n", dwError);
        goto CommonReturn;
    }

    dwError = PolicyStatus.dwError;

    if (dwError != ERROR_SUCCESS) {
        printf("CertVerifyCertificateChainPolicy with CERT_CHAIN_POLICY_BASE failed: %d\n", dwError);
        goto CommonReturn;
    }

    if (pChainContext->cChain == 0) {
        printf("No Chain Found\n");
        dwError = ERROR_NOT_FOUND;
        goto CommonReturn;
    }

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL) {
        dwError = ERROR_INTERNAL_ERROR;
        goto CommonReturn;
    }

    // Get certs from first simple chain
    pChain = pChainContext->rgpChain[0];
    //printf("Number of Chain elements: %d\n", pChain->cElement);
    for (DWORD i = 0; i < pChain->cElement; i++) {
        PCCERT_CONTEXT pCert = pChain->rgpElement[i]->pCertContext;
        cert = NULL;
        BIO* certBio = NULL;

        certCount++;
        certBio = BIO_new(BIO_s_mem());
        if (certBio == NULL) {
            dwError = ERROR_INTERNAL_ERROR;
            continue;
        }

        BIO_write(certBio, pCert->pbCertEncoded, pCert->cbCertEncoded);

        cert = d2i_X509_bio(certBio, NULL);
        if (cert == NULL) {
            printf("\n d2i failed. ");
            BIO_printf(certBio, "unable to load certificate\n");
            ERR_print_errors(certBio);
            dwError = ERROR_INTERNAL_ERROR;
            continue;
        }
        if (!PEM_write_bio_X509(mem, cert)) {
            printf("\n PEM_write_bio_X509 failed. ");
            BIO_printf(certBio, "unable to write PEM file\n");
            ERR_print_errors(certBio);
            dwError = ERROR_INTERNAL_ERROR;
            continue;
        }

        X509_free(cert);
        cert = NULL;
    }

    memLen = (int)BIO_get_mem_data(mem, (char**)&memBytes);
    if (memLen > 0) {
        *pem_chain = (char*)LocalAlloc(LPTR, memLen + sizeof(char));
        if (*pem_chain == NULL) {
            dwError = ERROR_INTERNAL_ERROR;
            goto CommonReturn;
        }
        memcpy(*pem_chain, memBytes, memLen);
        *pem_chain_length = memLen;
    }

CommonReturn:
    if (pChainContext != NULL)
    {
        CertFreeCertificateChain(pChainContext);
    }

    if (mem) {
        BIO_flush(mem);
        BIO_free(mem);
    }

    hr = HRESULT_FROM_WIN32(dwError);
    return;
}

void win_get_engine_key_id(
    PCCERT_CONTEXT pCertContext,
    char* store_name,
    int* key_id_Length,
    char** key_id)
{
    BYTE hash[20];
    DWORD cbHash = sizeof(hash);
    CHAR hexHash[20 * 2 + 1] = { 0 };
    DWORD cbCount = sizeof(hexHash);
    char* engine_key_id = nullptr;
    char engine_prefix[] = "engine:e_ncrypt:user:";
    char keySeperator[] = ":";
    char* keyIdTemp = nullptr;
    char* copyPtr = nullptr;

    if (CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, hash, &cbHash))
    {
        _DumpHex("CERT_HASH_PROP_ID", hash, cbHash);
        if (!CryptBinaryToStringA(
                hash,
                cbHash,
                CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF,
                hexHash,
                &cbCount))
        {
            printf("CryptBinaryToStringA Failed");
            goto CommonReturn;
        }

        keyIdTemp = (char*)LocalAlloc(LPTR, strlen(engine_prefix) + strlen(store_name) + strlen(keySeperator) +  cbCount + 1);
        if (keyIdTemp == NULL) {
            goto CommonReturn;
        }

        copyPtr = keyIdTemp;
        memcpy(copyPtr, engine_prefix, strlen(engine_prefix));
        copyPtr += strlen(engine_prefix);

        memcpy(copyPtr, store_name, strlen(store_name));
        copyPtr += strlen(store_name);

        memcpy(copyPtr, keySeperator, strlen(keySeperator));
        copyPtr += strlen(keySeperator);

        memcpy(copyPtr, hexHash, cbCount);
        copyPtr += cbCount;
    }

    *key_id = keyIdTemp;
    keyIdTemp = nullptr;
CommonReturn:
    if (keyIdTemp) {
        LocalFree(keyIdTemp);
    }

    return;
}

int _load_pem_certs(
    int certLength,
    const char* certBytes,
    X509** cert,
    STACK_OF(X509)** ca)
{
    int ret = 0;
    BIO* in = NULL;
    STACK_OF(X509_INFO)* certInfos = NULL;

    *cert = NULL;
    *ca = sk_X509_new_null();
    if (*ca == NULL) {
        goto openSslErr;
    }

    in = BIO_new_mem_buf(certBytes, certLength);
    if (in == NULL) {
        goto openSslErr;
    }

    certInfos = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
    if (certInfos == NULL) {
        goto openSslErr;
    }

    for (int i = 0; i < sk_X509_INFO_num(certInfos); i++) {
        X509_INFO* certInfo = sk_X509_INFO_value(certInfos, i);
        if (certInfo->x509 != NULL) {
            if (*cert == NULL) {
                *cert = certInfo->x509;
            }
            else {
                if (!sk_X509_push(*ca, certInfo->x509)) {
                    goto openSslErr;
                }
            }

            X509_up_ref(certInfo->x509);
        }
    }

    if (!*cert) {
        goto end;
    }

    ret = 1;

end:
    sk_X509_INFO_pop_free(certInfos, X509_INFO_free);
    BIO_free(in);

    if (!ret) {
        X509_free(*cert);
        *cert = NULL;
        sk_X509_pop_free(*ca, X509_free);
        *ca = NULL;
    }

    return ret;

openSslErr:
    goto end;
}


int win_verify_peer_certs(
    HCERTCHAINENGINE hChainEngine,
    int certLength,
    const char* certBytes)
{
    DWORD dwError = ERROR_SUCCESS;
    int mscryptFlags = 0;
    int ret = 0;
    int verifyChainError = 0;
    int newCertLength = 0;
    unsigned char* newCertBytes = NULL;
    X509* end = NULL;
    STACK_OF(X509)* rest = NULL;
    int chainDepth = 0;
    HCERTSTORE hCertStore = NULL;
    int len = 0;
    unsigned char* buf = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    CERT_CHAIN_PARA ChainPara = { 0 };
    ChainPara.cbSize = sizeof(ChainPara);
    DWORD dwChainFlags = 0;
    PCCERT_CHAIN_CONTEXT pChainContext = NULL;

    if (!_load_pem_certs(
        certLength,
        certBytes,
        &end,
        &rest)) {
        printf("_load_pem_certs FAILED\n");
        ret = 0;
        goto CommonReturn;
    }

    len = i2d_X509(end, &buf);
    if (len < 0)
    {
        ret = 0;
        goto CommonReturn;
    }

    hCertStore = CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        NULL,                       // hCryptProv
        CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG | CERT_STORE_SHARE_CONTEXT_FLAG,
        NULL);                      // pvPara
    if (NULL == hCertStore)
    {
        ret = 0;
        goto CommonReturn;
    }

    if (!CertAddEncodedCertificateToStore(
        hCertStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        buf,
        len,
        CERT_STORE_ADD_USE_EXISTING,
        &pCertContext))
    {
        ret = 0;
        goto CommonReturn;
    }

    OPENSSL_free(buf);
    buf = nullptr;

    printf("End certificate:\n");
    X509_NAME_print_ex_fp(
        stdout,
        X509_get_subject_name(end),
        0,                      // indent
        XN_FLAG_ONELINE | XN_FLAG_DN_REV);
    printf("\n");

    printf("CA certificates:\n");
    chainDepth = sk_X509_num(rest);
    for (int i = 0; i < chainDepth; i++)
    {
        PCCERT_CONTEXT pCertRest = NULL;
        X509* cert = sk_X509_value(rest, i);
        printf("  [%d]: ", i);
        X509_NAME_print_ex_fp(
            stdout,
            X509_get_subject_name(cert),
            0,                      // indent
            XN_FLAG_ONELINE | XN_FLAG_DN_REV);
        printf("\n");

        len = i2d_X509(cert, &buf);
        if (len < 0)
        {
            ret = 0;
            goto CommonReturn;
        }

        if (!CertAddEncodedCertificateToStore(
            hCertStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            buf,
            len,
            CERT_STORE_ADD_USE_EXISTING,
            &pCertRest))
        {
            ret = 0;
            goto CommonReturn;
        }

        OPENSSL_free(buf);
        buf = nullptr;
        CertFreeCertificateContext(pCertRest);
    }

    if (!CertGetCertificateChain(
        hChainEngine,
        pCertContext,
        NULL,                   // pTime
        hCertStore,
        &ChainPara,
        dwChainFlags,
        NULL,                   // pvReserved
        &pChainContext))
    {
        dwError = _GetNonzeroLastError();
        printf("CertGetCertificateChain Failed: %d\n", dwError);
        ret = 0;
        goto CommonReturn;
    }

    {
        CERT_CHAIN_POLICY_PARA PolicyPara = { 0 };
        CERT_CHAIN_POLICY_STATUS PolicyStatus = { 0 };

        PolicyPara.cbSize = sizeof(PolicyPara);
        PolicyStatus.cbSize = sizeof(PolicyStatus);

        if (!CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_BASE,
            pChainContext,
            &PolicyPara,
            &PolicyStatus))
        {
            dwError = _GetNonzeroLastError();
            printf("CertGetCertificateChain Failed: %d\n", dwError);
            ret = 0;
            goto CommonReturn;
        }

        dwError = PolicyStatus.dwError;
        printf("Certificate chain status: %d (0x%x)\n", PolicyStatus.dwError, PolicyStatus.dwError);

        if (dwError == ERROR_SUCCESS)
        {
            ret = 1;
        }
    }

CommonReturn:
    if (end)
    {
        X509_free(end);
    }

    if (rest)
    {
        sk_X509_pop_free(rest, X509_free);
    }

    if (hCertStore != NULL)
    {
        CertCloseStore(hCertStore, 0);
    }

    if (pChainContext != NULL)
    {
        CertFreeCertificateChain(pChainContext);
    }

    if (pCertContext != NULL)
    {
        CertFreeCertificateContext(pCertContext);
    }

    return ret;
}

int win_open_mem_store(
    int certLength,
    const char* certBytes,
    HCERTSTORE* hCertStore)
{
    DWORD dwError = ERROR_SUCCESS;
    int mscryptFlags = 0;
    int ret = 0;
    int verifyChainError = 0;
    int newCertLength = 0;
    unsigned char* newCertBytes = NULL;
    STACK_OF(X509)* roots = NULL;
    int chainDepth = 0;
    int len = 0;
    unsigned char* buf = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    CERT_CHAIN_PARA ChainPara = { 0 };
    ChainPara.cbSize = sizeof(ChainPara);
    DWORD dwChainFlags = 0;
    PCCERT_CHAIN_CONTEXT pChainContext = NULL;
    BIO* in = NULL;
    STACK_OF(X509_INFO)* certInfos = NULL;

    roots = sk_X509_new_null();
    if (roots == NULL) {
        goto openSslErr;
    }

    in = BIO_new_mem_buf(certBytes, certLength);
    if (in == NULL) {
        goto openSslErr;
    }

    certInfos = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
    if (certInfos == NULL) {
        goto openSslErr;
    }

    *hCertStore = CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        NULL,                       // hCryptProv
        CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG | CERT_STORE_SHARE_CONTEXT_FLAG,
        NULL);                      // pvPara
    if (NULL == *hCertStore)
    {
        ret = 0;
        goto CommonReturn;
    }

    for (int i = 0; i < sk_X509_INFO_num(certInfos); i++) {
        X509_INFO* certInfo = sk_X509_INFO_value(certInfos, i);
        if (certInfo->x509 != NULL) {
            if (!sk_X509_push(roots, certInfo->x509)) {
                goto openSslErr;
            }
            X509_up_ref(certInfo->x509);
        }
    }

    printf("Root Certificates:\n");
    chainDepth = sk_X509_num(roots);
    for (int i = 0; i < chainDepth; i++)
    {
        PCCERT_CONTEXT pCertRest = NULL;
        X509* cert = sk_X509_value(roots, i);
        printf("  [%d]: ", i);
        X509_NAME_print_ex_fp(
            stdout,
            X509_get_subject_name(cert),
            0,                      // indent
            XN_FLAG_ONELINE | XN_FLAG_DN_REV);
        printf("\n");

        if (!CertAddEncodedCertificateToStore(
            *hCertStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            buf,
            len,
            CERT_STORE_ADD_USE_EXISTING,
            &pCertRest))
        {
            ret = 0;
            goto CommonReturn;
        }

        CertFreeCertificateContext(pCertRest);
    }

    ret = 1;

CommonReturn:
    if (roots)
    {
        sk_X509_pop_free(roots, X509_free);
    }

    sk_X509_INFO_pop_free(certInfos, X509_INFO_free);
    BIO_free(in);

    return ret;

openSslErr:
    goto CommonReturn;
}
