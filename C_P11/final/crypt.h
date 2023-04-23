#ifndef _CRYPT_H_
#define _CRYPT_H_

#include <cryptoki.h>

//#define FALSE 0
//#define TRUE 1

#define SK_SIZE 128     // 128 bits (for AES)
#define SK_BYTE_SIZE 16     // 16 byte (for AES)
#define RSA_MOD_SIZE 2048    // RSA key size

#define NUM(a) (sizeof(a) / sizeof((a)[0]))

typedef unsigned char uchar;
typedef unsigned int uint;

extern CK_FUNCTION_LIST *gFunctionList;

void SAFE_FREE(void* ptr);

int nCipher_check_key_exists(CK_SESSION_HANDLE hSession, char* keyName);
int nCipher_SEC_rsa_key_gen(CK_SESSION_HANDLE hSession, char* label, CK_OBJECT_HANDLE *hPuK, CK_OBJECT_HANDLE *hPrK);
int nCipher_SEC_rsa_key_import(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE *hPuK, CK_OBJECT_HANDLE *hPrK);
int nCipher_SEC_rsa_sign(CK_SESSION_HANDLE hSession, uchar *msg, CK_ULONG msg_len, CK_OBJECT_HANDLE hPrK, uchar **sig, CK_ULONG *sig_len);
int nCipher_SEC_rsa_verify(CK_SESSION_HANDLE hSession, uchar *msg, CK_ULONG msg_len, uchar *sig, CK_ULONG sig_len,  CK_OBJECT_HANDLE hPuK);
int nCipher_SEC_exportRSAPubKeyVal(CK_SESSION_HANDLE hSession, CK_BYTE** eVal, CK_ULONG_PTR eValLen, CK_BYTE** nVal, CK_ULONG_PTR nValLen, CK_OBJECT_HANDLE hPuK);
int nCipher_SEC_raw_rsa_sign(CK_SESSION_HANDLE hSession, uchar *hashVal, CK_ULONG hash_len, CK_OBJECT_HANDLE hPrK, uchar **sig, CK_ULONG *sig_len);
int nCipher_SEC_raw_rsa_verify(CK_SESSION_HANDLE hSession, uchar *hashVal, CK_ULONG hash_len, uchar *sig, CK_ULONG sig_len, CK_OBJECT_HANDLE hPuK);
int nCipher_SEC_raw_rsa_encrypt(CK_SESSION_HANDLE hSession, uchar *hashVal, CK_ULONG hash_len, CK_OBJECT_HANDLE hPrK, uchar **sig, CK_ULONG *sig_len);
int nCipher_SEC_raw_rsa_decrypt(CK_SESSION_HANDLE hSession, uchar *hashVal, CK_ULONG hash_len, uchar **sig, CK_ULONG *sig_len, CK_OBJECT_HANDLE hPuK);

#endif

