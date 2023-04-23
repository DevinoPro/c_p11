
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "crypt.h"
#include "keyTemplate.h"

void SAFE_FREE(void* ptr)
{
	if(ptr != NULL)
		free(ptr);
	else
		fprintf(stderr, "[-] free is failed : mem indicates null pointer.!\n");
}

int nCipher_check_key_exists(CK_SESSION_HANDLE hSession, char* keyName) {
  
  if (!keyName)
    return 0;

  CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE template[] = {
      { CKA_CLASS, &keyClass, sizeof(keyClass) },
      { CKA_LABEL, keyName, strlen(keyName)} 
  };
  CK_ULONG objectCount;
  CK_OBJECT_HANDLE object;

  gFunctionList->C_FindObjectsInit(hSession, template, NUM(template));
  gFunctionList->C_FindObjects(hSession, &object, 1, &objectCount);
  gFunctionList->C_FindObjectsFinal(hSession);

  if (objectCount > 0) {
    fprintf(stderr, "[-] %s key already exists\n", keyName); 
    return 1;
  }

  return 0;
}

int nCipher_SEC_rsa_key_gen(CK_SESSION_HANDLE hSession, char *label, CK_OBJECT_HANDLE *hPuK, CK_OBJECT_HANDLE *hPrK)
{
	CK_ULONG rv;
	CK_MECHANISM rsa_key_gen_mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};

  if (!label)
    return 0;

	//Set attribute value for RSA
	token = true;
	private = false;
	modifiable = false;
	sensitive = true;
	ncrypt = false;
	sign = true;
	verify = true;
	extractable = false;

	//Label Setting
	char *rsaPuKLabel = label;//"nCipher Exercise RSA2048 Public Key";
	if(rsaPublicKeyTemplate[4].type == CKA_LABEL){
		rsaPublicKeyTemplate[4].ulValueLen = (CK_ULONG)strlen(rsaPuKLabel);
		rsaPublicKeyTemplate[4].pValue = (void*)rsaPuKLabel;
	}else
		fprintf(stderr, "[-] ]RSA PuK Label Setting Err\n");

	char *rsaPrKLabel = label; //"nCipher Exercise RSA2048 Private Key";
	if(rsaPrivateKeyTemplate[4].type == CKA_LABEL){
		rsaPrivateKeyTemplate[4].ulValueLen = (CK_ULONG)strlen(rsaPrKLabel);
		rsaPrivateKeyTemplate[4].pValue = (void*)rsaPrKLabel;
	}else
		fprintf(stderr, "[-] RSA PrK Label Setting Err\n");

	rv = gFunctionList->C_GenerateKeyPair(hSession, &rsa_key_gen_mech, rsaPublicKeyTemplate, NUM(rsaPublicKeyTemplate),
			rsaPrivateKeyTemplate, NUM(rsaPrivateKeyTemplate), hPuK, hPrK);

	if(rv == CKR_OK)
		return 1;
	else
		return 0;
}

int nCipher_SEC_rsa_sign(CK_SESSION_HANDLE hSession, uchar *msg, CK_ULONG msg_len, CK_OBJECT_HANDLE hPrK, uchar **sig, CK_ULONG *sig_len)
{
	CK_ULONG rv;
	CK_MECHANISM rsa_sign_mech = {CKM_SHA1_RSA_PKCS, NULL_PTR, 0};

	rv = gFunctionList->C_SignInit(hSession, &rsa_sign_mech, hPrK);
	if(rv == CKR_OK){
		rv = gFunctionList->C_Sign(hSession, msg, msg_len, NULL_PTR, sig_len);
		if(rv == CKR_OK)
		{
			*sig = (CK_BYTE*)malloc(sizeof(uchar)*(*sig_len));
			rv = gFunctionList->C_Sign(hSession, msg, msg_len, *sig, sig_len);
		}
	}

	if(rv == CKR_OK)
		return 1;
	else
		return 0;
}

int nCipher_SEC_rsa_verify(CK_SESSION_HANDLE hSession, uchar *msg, CK_ULONG msg_len, uchar *sig, CK_ULONG sig_len,  CK_OBJECT_HANDLE hPuK)
{
	CK_ULONG rv;
	CK_MECHANISM rsa_verify_mech = {CKM_SHA1_RSA_PKCS, NULL_PTR, 0};

	rv = gFunctionList->C_VerifyInit(hSession, &rsa_verify_mech, hPuK);
	if(rv == CKR_OK)
		rv = gFunctionList->C_Verify(hSession, msg, msg_len, sig, sig_len);

	if(rv == CKR_OK)
		return 1;
	else
		return 0;
}

int nCipher_SEC_exportRSAPubKeyVal(CK_SESSION_HANDLE hSession, CK_BYTE** eVal, CK_ULONG_PTR eValLen, CK_BYTE** nVal, CK_ULONG_PTR nValLen, CK_OBJECT_HANDLE hPuK)
{
	CK_RV rv;

	*eVal=NULL_PTR;
	*nVal=NULL_PTR;
	CK_ATTRIBUTE exportValTemplate[] = {
			{CKA_PUBLIC_EXPONENT, NULL_PTR, 0}, // e
			{CKA_MODULUS, NULL_PTR, 0}, // n
	};

	rv = gFunctionList->C_GetAttributeValue(hSession, hPuK, exportValTemplate, NUM(exportValTemplate));
	if(rv != CKR_OK)
	{
		fprintf(stderr, "Failed to C_GetAttributeValue phase 1!\n");
		return 0;
	}

	exportValTemplate[0].pValue = (void*) malloc(exportValTemplate[0].ulValueLen);
	exportValTemplate[1].pValue = (void*) malloc(exportValTemplate[1].ulValueLen);

	rv = gFunctionList->C_GetAttributeValue(hSession, hPuK, exportValTemplate, NUM(exportValTemplate));
	if(rv != CKR_OK)
	{
		fprintf(stderr, "Failed to C_GetAttributeValue phase 2!\n");
		return 0;
	}
  else {
  	*eValLen = exportValTemplate[0].ulValueLen;
	  *nValLen = exportValTemplate[1].ulValueLen;
  	*eVal = exportValTemplate[0].pValue;
	  *nVal = exportValTemplate[1].pValue;

	  return 1;
  }
}

int nCipher_SEC_raw_rsa_sign(CK_SESSION_HANDLE hSession, uchar *hashVal, CK_ULONG hash_len, CK_OBJECT_HANDLE hPrK, uchar **sig, CK_ULONG *sig_len) {

  CK_ULONG rv;
  CK_MECHANISM rsa_sign_mech = {CKM_RSA_X_509, NULL_PTR, 0};

  rv = gFunctionList->C_SignInit(hSession, &rsa_sign_mech, hPrK);
  if (rv == CKR_OK) {
    rv = gFunctionList->C_Sign(hSession, hashVal, hash_len, NULL_PTR, sig_len);
    if (rv == CKR_OK) {

      *sig = (CK_BYTE*) malloc(sizeof(uchar)*(*sig_len));
      rv = gFunctionList->C_Sign(hSession, hashVal, hash_len, *sig, sig_len);
    }
  }

  if (rv == CKR_OK)
    return 1;

  return 0;
}


int nCipher_SEC_raw_rsa_verify(CK_SESSION_HANDLE hSession, uchar *hashVal, CK_ULONG hash_len, uchar *sig, CK_ULONG sig_len, CK_OBJECT_HANDLE hPuK) {

  CK_ULONG rv;
  CK_MECHANISM rsa_sign_mech = {CKM_RSA_X_509, NULL_PTR, 0};
  //CK_MECHANISM rsa_sign_mech = {CKM_RSA_PKCS, NULL_PTR, 0};

  rv = gFunctionList->C_VerifyInit(hSession, &rsa_sign_mech, hPuK);
  if (rv == CKR_OK) 
    rv = gFunctionList->C_Verify(hSession, hashVal, hash_len, sig, sig_len);

  if (rv == CKR_OK)
    return 1;

  return 0;
}

int nCipher_SEC_raw_rsa_encrypt(CK_SESSION_HANDLE hSession, uchar *hashVal, CK_ULONG hash_len, CK_OBJECT_HANDLE hPrK, uchar **sig, CK_ULONG *sig_len) {

  CK_ULONG rv;
  CK_MECHANISM rsa_sign_mech = {CKM_RSA_X_509, NULL_PTR, 0};

  rv = gFunctionList->C_EncryptInit(hSession, &rsa_sign_mech, hPrK);
  if (rv == CKR_OK) {
    rv = gFunctionList->C_Encrypt(hSession, hashVal, hash_len, NULL_PTR, sig_len);
    if (rv == CKR_OK) {

      *sig = (CK_BYTE*) malloc(sizeof(uchar)*(*sig_len));
      rv = gFunctionList->C_Sign(hSession, hashVal, hash_len, *sig, sig_len);
    }
  }

  if (rv == CKR_OK)
    return 1;

  return 0;
}


int nCipher_SEC_raw_rsa_decrypt(CK_SESSION_HANDLE hSession, uchar *hashVal, CK_ULONG hash_len, uchar **sig, CK_ULONG *sig_len, CK_OBJECT_HANDLE hPuK) {

  CK_ULONG rv;
  CK_MECHANISM rsa_sign_mech = {CKM_RSA_PKCS, NULL_PTR, 0};

  rv = gFunctionList->C_EncryptInit(hSession, &rsa_sign_mech, hPuK);
  if (rv == CKR_OK) {
    rv = gFunctionList->C_Encrypt(hSession, hashVal, hash_len, NULL_PTR, sig_len);
    if (rv == CKR_OK) {

      *sig = (CK_BYTE*) malloc(sizeof(uchar)*(*sig_len));
      rv = gFunctionList->C_Sign(hSession, hashVal, hash_len, *sig, sig_len);
    }
  }

  if (rv == CKR_OK)
    return 1;

  return 0;
}
