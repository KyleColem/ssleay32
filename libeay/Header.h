#pragma once
#include <windows.h>
bool loadFunc();
typedef struct rsa_st RSA;

typedef int (*dPEM_read_bio_RSAPrivateKey)(int bp, void** x1, int cb, void* u);
typedef int(*dEVP_PKEY_assign)(int, int, int);
typedef int(*dEVP_SignFinal)(DWORD*, int, DWORD*, DWORD*);
typedef int(*dEVP_DigestUpdate)(int);
typedef int(*dEVP_DigestInit)(int*, DWORD*);
typedef int(*dEVP_PKEY_size)(int*);
typedef void(*dEVP_PKEY_free)(void*);
typedef DWORD* (*dEVP_PKEY_new)(void);
typedef void* (*dEVP_sha1)();
typedef void* (*dBIO_s_file)();
typedef int(*dBIO_ctrl)(DWORD*, int, int, int);
typedef void* (*dBIO_new)(int);
typedef int(*dERR_load_crypto_strings)();
typedef char* (*dERR_error_string)(int, char*);
typedef int(*dERR_get_error)();
typedef int(*dEVP_cleanup)();
typedef int(*dOpenSSL_add_all_digests)();
typedef int(*dOpenSSL_add_all_ciphers)();
typedef int(*dEVP_MD_CTX_cleanup)(int a1);
typedef int(*dEVP_MD_CTX_init)(DWORD* a1);

dPEM_read_bio_RSAPrivateKey func1;
dEVP_PKEY_assign func2;
dEVP_SignFinal func3;
dEVP_DigestUpdate func4;
dEVP_DigestInit func5;
dEVP_PKEY_size func6;
dEVP_PKEY_free func7;
dEVP_PKEY_new func8;
dEVP_sha1 func9;
dBIO_s_file func10;
dBIO_ctrl func11;
dBIO_new func12;
dERR_load_crypto_strings func13;
dERR_error_string func14;
dERR_get_error func15;
dEVP_cleanup func16;
dOpenSSL_add_all_digests func17;
dOpenSSL_add_all_ciphers func18;
dEVP_MD_CTX_cleanup func19;
dEVP_MD_CTX_init func20;
