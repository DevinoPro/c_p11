
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "crypt.h"
#include "ssl.h"


#define ROOT_KEY_NAME      "testkey2"
#define IMEI_KEY_NAME      "testkey2"
#define SW_CARD_LABEL      "TESTSWCARD" 
#define SW_CARD_PROTECTION "TESTSWCARD" //password

#define SECURE_IMEI_ROOT_KEY        "secure_imei_root_key"
#define SECURE_IMEI_SIGNER_KEY      "secure_imei_signer_key"
#define SECURE_MSL_ROOT_KEY         "secure_msl_root_key"
#define SECURE_MSL_SIGNER_KEY       "secure_msl_signer_key"


CK_RV get_slot(int private_objects, int print_used, CK_SLOT_ID *hSlot);
CK_RV ocs_login(CK_SESSION_HANDLE hSession);
void binToHex(unsigned char* src, unsigned int	srcsz, char** dst);


const u8 ppadding[RSANUMBYTES - SHA_DIGEST_SIZE] = { 0x00, 0x01,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0x00, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
                               0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
                             };


CK_FUNCTION_LIST *gFunctionList;

//unsigned char data[SHA_DIGEST_SIZE] = {0xBD, 0xF5, 0xF2, 0x0F, 0x61, 0x77, 0x15, 0x04, 0x47, 0x00, 
//                                       0x0B, 0xC3, 0x5A, 0x21, 0xD1, 0x1E, 0x5C, 0x2C, 0x55, 0x80};

//unsigned char data[SHA_DIGEST_SIZE] = {0x19, 0x29, 0xa9, 0xb4, 0x59, 0x7d, 0xd7, 0xf3, 0x28, 0x7c, 
//                                       0xa7, 0x62, 0xdb, 0x12, 0x2b, 0xcf, 0xe8, 0x53, 0x7f, 0xc8};

unsigned char data[SHA_DIGEST_SIZE] = {0xb1, 0xcc, 0x31, 0x1c, 0x38, 0xd2, 0x5d, 0x7c, 0xd3, 0x86, 
                                       0x7a, 0x3b, 0x83, 0x5d, 0xe4, 0x09, 0x07, 0x52, 0x17, 0x0b};

unsigned char signKeyId[SIGN_KEY_ID_SIZE] = "0506"; //{0x11, 0x22, 0x33, 0x44};

void check_return_value(CK_RV rv, const char *msg) {

	if (rv != CKR_OK) {
		fprintf(stderr, "Error at %s: %u\n", msg, (unsigned int) rv);
		exit(EXIT_FAILURE);
	}
}

CK_SESSION_HANDLE start_session() {

  CK_SLOT_ID hSlot = 0;
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

  C_GetFunctionList(&gFunctionList);

  rv = gFunctionList->C_Initialize(NULL_PTR);
  check_return_value(rv, "initialize");

  int private_objects = 1;
  int print_used = 1;
  rv = get_slot(private_objects, print_used, &hSlot);
  check_return_value(rv, "get_slot");

  rv = gFunctionList->C_OpenSession(hSlot,
                                    CKF_RW_SESSION | CKF_SERIAL_SESSION,
                                    NULL, NULL,
                                    &hSession);
  
	check_return_value(rv, "open session");
	
    //login
    rv = ocs_login(hSession);
    if (rv != CKR_OK){
        fprintf(stderr, "Failed to login\n");
        return NULL_PTR ;
    }
	
	
	return hSession;
}

void key_generate(CK_SESSION_HANDLE hSession) {

  char *root_key_label = ROOT_KEY_NAME; //
  char *imei_key_label = IMEI_KEY_NAME; //

  if (nCipher_check_key_exists(hSession, root_key_label) == 0) {

    fprintf(stdout, "create %s key\n", root_key_label);
    CK_OBJECT_HANDLE hPrK, hPuK;
    nCipher_SEC_rsa_key_gen(hSession, root_key_label, &hPuK, &hPrK);
  }

  if (nCipher_check_key_exists(hSession,  imei_key_label) == 0) {

    fprintf(stdout, "create %s key\n", imei_key_label);
    CK_OBJECT_HANDLE hPrK, hPuK;
    nCipher_SEC_rsa_key_gen(hSession, imei_key_label, &hPuK, &hPrK);
  }
}

CK_OBJECT_HANDLE get_private_key_by_label(CK_SESSION_HANDLE hSession, char *sigKeyName){

  if (!sigKeyName)
    return NULL_PTR;

  CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
  CK_ULONG sigKeyLen = strlen(sigKeyName);
  CK_ATTRIBUTE sigKeyTemplate[] = {
      {CKA_CLASS, &keyClass, sizeof(keyClass)},
      {CKA_LABEL, sigKeyName, sigKeyLen}
  };

  CK_ULONG cnt = 0;
  CK_OBJECT_HANDLE pGetHandles[2];
  gFunctionList->C_FindObjectsInit(hSession, sigKeyTemplate, NUM(sigKeyTemplate));
  gFunctionList->C_FindObjects(hSession, pGetHandles, 2, &cnt);
  gFunctionList->C_FindObjectsFinal(hSession);

  if (cnt == 0) {
    fprintf(stderr, "cannot find the %s key object!\n", sigKeyName);
    return NULL_PTR;
  }
  else if (cnt > 1) {
    fprintf(stderr, "%s Label collision detected\n", sigKeyName);
    return NULL_PTR;
  }

  return pGetHandles[0];
}

CK_OBJECT_HANDLE get_public_key_by_label(CK_SESSION_HANDLE hSession, char *sigKeyName){

  if (!sigKeyName)
    return NULL_PTR;

  CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
  CK_ULONG sigKeyLen = strlen(sigKeyName);
  CK_ATTRIBUTE sigKeyTemplate[] = {
      {CKA_CLASS, &keyClass, sizeof(keyClass)},
      {CKA_LABEL, sigKeyName, sigKeyLen}
  };

  CK_ULONG cnt = 0;
  CK_OBJECT_HANDLE pGetHandles[2];
  gFunctionList->C_FindObjectsInit(hSession, sigKeyTemplate, NUM(sigKeyTemplate));
  gFunctionList->C_FindObjects(hSession, pGetHandles, 2, &cnt);
  gFunctionList->C_FindObjectsFinal(hSession);

  if (cnt == 0) {
    fprintf(stderr, "cannot find the %s key object!\n", sigKeyName);
    return NULL_PTR;
  }
  else if (cnt > 1) {
    fprintf(stderr, "%s Label collision detected\n", sigKeyName);
    return NULL_PTR;
  }

  return pGetHandles[0];
}

void sign_and_verify(CK_SESSION_HANDLE hSession, uchar* keyName, uchar *msg, CK_ULONG msg_len, uchar** sig, CK_ULONG* sig_len) {

  int ret;
  if (!keyName || !msg) {
    fprintf(stderr, "keyname or msg has null");
    return;
  }

  CK_OBJECT_HANDLE imei_priv_key = get_private_key_by_label(hSession, keyName);
  if (imei_priv_key) {
  
    ret = nCipher_SEC_raw_rsa_sign(hSession, msg, msg_len, imei_priv_key, sig, sig_len);
    if (ret != 1) { 
      fprintf(stderr, "Failed to Signing with key %s\n", keyName);
      return;
    }
  }

  CK_OBJECT_HANDLE imei_pub_key = get_public_key_by_label(hSession, keyName);
  if (imei_pub_key) {
    
    ret = nCipher_SEC_raw_rsa_verify(hSession, msg, msg_len, *sig, *sig_len, imei_pub_key);

    if (ret == 1) {
   
      fprintf(stdout, "[+] Verify Success with key %s\n\n", keyName);
    }
    else {
      fprintf(stderr, "[-] Failed to Signing with key %s\n\n", keyName);
    }
  }
}

MC_RSAPublicKey get_public_value_from_key(CK_SESSION_HANDLE hSession, uchar* keyName) {

  MC_RSAPublicKey pubkey;
  CK_OBJECT_HANDLE imei_pub_key = get_public_key_by_label(hSession, keyName);

  if (imei_pub_key) {
  
    CK_BYTE_PTR eVal, nVal;
    CK_ULONG eValLen, nValLen;
    nCipher_SEC_exportRSAPubKeyVal(hSession, &eVal, &eValLen, &nVal, &nValLen, imei_pub_key);

    n_to_MC_RSAPublicKey(nVal, nValLen, &pubkey);

    uchar *hex_rsa_public;
    printf("[+] rsa public ::\n");
    binToHex((uchar*) &pubkey, sizeof(MC_RSAPublicKey), (char **)&hex_rsa_public);
    printf("%s\n\n", hex_rsa_public);

    printf("[+] len = %d\n", pubkey.len);
    printf("[+] n0inv = %08x\n", pubkey.n0inv);
    printf("[+] n[RSANUMWORDS] = {");
    for (int i=0; i<RSANUMWORDS; i++){

      printf("%u, ", pubkey.n[i]);
    }
    printf("}\n");
    
    printf("[+] n[RSANUMWORDS] = {");
    for (int i=0; i<RSANUMWORDS; i++){

      printf("%u, ", pubkey.rr[i]);
    }
    printf("}\n");
  }
  return pubkey;
}

void signing_test(CK_SESSION_HANDLE hSession) {
 
  uchar ddata[RSANUMBYTES];
  memcpy(ddata, ppadding, RSANUMBYTES - SHA_DIGEST_SIZE);
  memcpy(ddata + RSANUMBYTES - SHA_DIGEST_SIZE, data, SHA_DIGEST_SIZE);

  // sign hashed IMEI data with IMEI_KEY
  uchar* data_sig;
  CK_ULONG data_sig_len;
  sign_and_verify(hSession, IMEI_KEY_NAME, ddata, RSANUMBYTES, &data_sig, &data_sig_len);

  uchar *hex_data_sig;
  printf("[+] data sig ::\n");
  binToHex(data_sig, data_sig_len, (char **)&hex_data_sig);
  printf("%s\n\n", hex_data_sig);

  MC_RSAPublicKey pubkey = get_public_value_from_key(hSession, IMEI_KEY_NAME);
  if (MC_RSA_verify(&pubkey, data_sig, RSANUMBYTES, data) == 0) {
    
    fprintf(stderr, "[-] Verify failed with MC_RSA_verify method\n\n");
  }
  else {
    fprintf(stdout, "[+] Verify success with MC_RSA_verify method\n\n");
  }

  printf("[+] public base64 ::\n");
  printf("%s\n\n", __base64_encode((unsigned char*) &pubkey, sizeof(MC_RSAPublicKey)));

  uchar buf[sizeof(MC_RSAPublicKey) + SIGN_KEY_ID_SIZE] = {0, };
  uchar public_digest[SHA_DIGEST_SIZE] = {0, };

  memcpy(buf, &pubkey, sizeof(MC_RSAPublicKey));
  memcpy(buf + sizeof(MC_RSAPublicKey), signKeyId, SIGN_KEY_ID_SIZE);

  SHA_CTX sha_ctx;
  SHA1_Init(&sha_ctx);
  SHA1_Update(&sha_ctx, buf, sizeof(MC_RSAPublicKey) + SIGN_KEY_ID_SIZE);
  SHA1_Final(public_digest, &sha_ctx);

  fprintf(stdout, "[+] public digest value ::\n""");
  for (int i=0; i<SHA_DIGEST_SIZE; i++) {
    printf("%02X", public_digest[i]);
  }
  printf("\n\n");

  uchar ppublic[RSANUMBYTES];
  memcpy(ppublic, ppadding, RSANUMBYTES - SHA_DIGEST_SIZE);
  memcpy(ppublic + RSANUMBYTES - SHA_DIGEST_SIZE, public_digest, SHA_DIGEST_SIZE);
  fprintf(stdout, "[+] ppublic value ::\n""");
  for (int i=0; i<RSANUMBYTES; i++) {
    printf("%02X", ppublic[i]);
  }
  printf("\n\n");
  
  uchar* public_sig;
  CK_ULONG public_sig_len;
  sign_and_verify(hSession, ROOT_KEY_NAME, ppublic, RSANUMBYTES, &public_sig, &public_sig_len);
  //sign_and_verify(hSession, ROOT_KEY_NAME, buf, sizeof(MC_RSAPublicKey) + SIGN_KEY_ID_SIZE, &public_sig, &public_sig_len);
  
  uchar *hex_public_sig;
  printf("[+] public sig ::\n");
  binToHex(public_sig, public_sig_len, (char **)&hex_public_sig);
  printf("%s\n\n", hex_public_sig);
  
  printf("[+] public sig base64 ::\n");
  printf("%s\n\n", __base64_encode(public_sig, public_sig_len));

  MC_RSAPublicKey rootpubkey = get_public_value_from_key(hSession, ROOT_KEY_NAME);
  if (MC_RSA_verify(&rootpubkey, public_sig, RSANUMBYTES, public_digest) == 0) {
    
    fprintf(stderr, "[-] Verify failed with MC_RSA_verify method\n\n");
  }
  else {
    fprintf(stdout, "[+] Verify success with MC_RSA_verify method\n\n");
  }
}

int main(int argc, char** argv) {

  CK_SESSION_HANDLE hSession;
  hSession = start_session();

  key_generate(hSession);

  signing_test(hSession);

  return 0;
}

CK_RV get_slot(int private_objects, int print_used, CK_SLOT_ID *hSlot) {
	CK_ULONG i, islot, nslots = 0;
	CK_SLOT_ID_PTR pslots = NULL;
	CK_RV rv;
	CK_TOKEN_INFO tinfo;
	char label_padded[32]; /* same size as tinfo.label */

	// Get OCS Name
    char *label = strdup(SW_CARD_LABEL);
	// char *label = (char*)calloc(sizeof(tinfo.label), sizeof(char));
	// if (private_objects) {
		// printf("Input OCS NAME: ");
		// if(fgets(label, sizeof(tinfo.label), stdin) == NULL_PTR)
			// return CK_FALSE;
		// fputc('\n', stdin);
		// short lasti = strlen(label);
		// label[lasti-1] = '\0';
	// }

	assert(sizeof(tinfo.label) == sizeof(label_padded));
	if (label) {
		if (strlen(label) > sizeof(tinfo.label)) {
			fprintf(stderr, "Label can only be %ld chars long",
					(long)sizeof(label_padded));
			return CKR_ARGUMENTS_BAD;
		}
		memset(label_padded, ' ', sizeof(label_padded));
		memcpy(label_padded, label, strlen(label));
	}

	rv = gFunctionList->C_GetSlotList(0, NULL_PTR, &nslots);
	if (rv != CKR_OK) goto err;
	if (nslots == 0) {
		rv = CKR_TOKEN_NOT_PRESENT;
		goto err;
	}

	pslots = malloc(sizeof(CK_SLOT_ID) * nslots);
	if (!pslots) {
		fprintf(stderr, "failed to malloc %ld slotIDs", nslots);
		rv = CKR_HOST_MEMORY; goto err;
	}
	rv = gFunctionList->C_GetSlotList(1, pslots, &nslots);
	if (rv != CKR_OK) goto err;

	if(private_objects == 0){
		*hSlot = pslots[0];
		goto err;
	}


	for (islot = 0; islot < nslots; islot++) {
		rv = gFunctionList->C_GetTokenInfo(pslots[islot], &tinfo);

		if (rv == CKR_TOKEN_NOT_PRESENT) {
			/* Could have been removed since the C_GetSlotList call. */
			continue;
		}

		if (rv != CKR_OK) goto err;

		if (private_objects &&
				!(tinfo.flags & CKF_USER_PIN_INITIALIZED))
			continue;

		if (label &&
				strncmp(label_padded,
						(char *)tinfo.label,
						sizeof(tinfo.label)))
			continue;

		if (print_used) {
			/* islot not very meaningful with tokenPresent used */
			printf("Using token with label \"");
			for (i = 0; i < sizeof(tinfo.label); i++)
				printf("%c", tinfo.label[i]);
			printf("\"\n");
		}

		break;
	}
	if (islot < nslots) {
		rv = CKR_OK;
		*hSlot = pslots[islot];
	} else
		rv = CKR_TOKEN_NOT_PRESENT;

err:
	SAFE_FREE(label);
	SAFE_FREE(pslots);
	return rv;
}

CK_RV ocs_login(CK_SESSION_HANDLE hSession) {
	CK_RV rv = CK_TRUE;
    char *passphrase = strdup(SW_CARD_PROTECTION);//(char*)calloc(20, sizeof(char));

    
	// char *passphrase = (char*)calloc(20, sizeof(char));

	// printf("Input Password: ");
	// if(fgets(passphrase, 20, stdin) == NULL_PTR)
		// return CK_FALSE;

	// fputc('\n', stdin);

	// short lasti = strlen(passphrase);
	// passphrase[lasti-1] = '\0';

	if (passphrase != NULL_PTR)
		rv = C_Login(hSession, CKU_USER,
				(CK_UTF8CHAR*)passphrase, (CK_ULONG)strlen((char *)passphrase));

	SAFE_FREE(passphrase);

	return rv;
}

void binToHex(unsigned char* src, unsigned int	srcsz, char** dst) {
	char          hex_str[]= "0123456789ABCDEF";
	unsigned int	i;

	*dst = (char *)malloc(srcsz * 2);
	(*dst)[srcsz * 2] = 0;

	if (!srcsz)
		return;

	for (i = 0; i < srcsz; i++)	{
		(*dst)[i * 2] = hex_str[src[i] >> 4  ];
		(*dst)[i * 2 + 1] = hex_str[src[i] & 0x0F];
	}
	(*dst)[(srcsz-1) * 2 + 2] = '\0';
}

