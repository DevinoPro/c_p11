/*
 * keyTemplate.h
 *
 *  Created on: June 10, 2019
 *      Author: Gunil
 */

#ifndef KEYTEMPLATE_H_
#define KEYTEMPLATE_H_

#include <cryptoki.h>

static CK_BBOOL true = CK_TRUE;
static CK_BBOOL false = CK_FALSE;

static CK_BBOOL token;
static CK_BBOOL private;
static CK_BBOOL modifiable;
static CK_BBOOL sensitive;
static CK_BBOOL ncrypt;
static CK_BBOOL sign;
static CK_BBOOL verify;
static CK_BBOOL wrap;
static CK_BBOOL extractable;

static CK_OBJECT_CLASS class_secret = CKO_SECRET_KEY;
static CK_OBJECT_CLASS class_public = CKO_PUBLIC_KEY;
static CK_OBJECT_CLASS class_private = CKO_PRIVATE_KEY;


static CK_KEY_TYPE key_type_aes = CKK_AES;
static CK_KEY_TYPE key_type_rsa = CKK_RSA;

static CK_ULONG aes_key_size = 16; //byte size

static CK_ULONG modulusbits = 2048;
static CK_BYTE publicexponent[] = { 0, 0, 0, 0x3 }; // 3 == 2^1 + 1 /* 65537 == 2^16 + 1 */

static CK_ATTRIBUTE aesKeyTemplate[] = {
		{CKA_CLASS, &class_secret, sizeof(class_secret)},
		{CKA_PRIVATE, &private, sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE, &modifiable, sizeof(CK_BBOOL)},
		{CKA_TOKEN, &token, sizeof(CK_BBOOL)},
		{CKA_LABEL, NULL_PTR, 0},
		{CKA_KEY_TYPE, &key_type_aes, sizeof(key_type_aes)},
		{CKA_ID, NULL_PTR, 0},
		{CKA_SENSITIVE, &sensitive, sizeof(CK_BBOOL)},
		{CKA_ENCRYPT, &ncrypt, sizeof(CK_BBOOL)},
		{CKA_DECRYPT, &ncrypt, sizeof(CK_BBOOL)},
		{CKA_WRAP, &wrap, sizeof(CK_BBOOL)},
		{CKA_UNWRAP, &wrap, sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE, &extractable, sizeof(CK_BBOOL)},
		{CKA_VALUE_LEN, &aes_key_size, sizeof(aes_key_size)}
};

static CK_ATTRIBUTE rsaPublicKeyTemplate[] = {
		{CKA_CLASS, &class_public, sizeof(class_public)},
		{CKA_PRIVATE, &false, sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE, &modifiable, sizeof(CK_BBOOL)},
		{CKA_TOKEN, &token, sizeof(CK_BBOOL)},
		{CKA_LABEL, NULL_PTR, 0},
		{CKA_KEY_TYPE, &key_type_rsa, sizeof(key_type_rsa)},
		{CKA_ID, NULL_PTR, 0},
		{CKA_SUBJECT, NULL_PTR, 0},
		{CKA_ENCRYPT, &ncrypt, sizeof(CK_BBOOL)},
		{CKA_VERIFY, &verify, sizeof(CK_BBOOL)},
		{CKA_MODULUS_BITS, &modulusbits, sizeof(modulusbits)},
		{CKA_PUBLIC_EXPONENT, publicexponent, sizeof(publicexponent)}
};

static CK_ATTRIBUTE rsaPrivateKeyTemplate[] = {
		{CKA_CLASS, &class_private, sizeof(class_private)},
		{CKA_PRIVATE, &private, sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE, &modifiable, sizeof(CK_BBOOL)},
		{CKA_TOKEN, &token, sizeof(CK_BBOOL)},
		{CKA_LABEL, NULL_PTR, 0},
		{CKA_KEY_TYPE, &key_type_rsa, sizeof(key_type_rsa)},
		{CKA_ID, NULL_PTR, 0},
		{CKA_SUBJECT, NULL_PTR, 0},
		{CKA_SENSITIVE, &sensitive, sizeof(CK_BBOOL)},
		{CKA_DECRYPT, &ncrypt, sizeof(CK_BBOOL)},
		{CKA_SIGN, &sign, sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE, &extractable, sizeof(extractable)}
};

#endif /* KEYTEMPLATE_H_ */
