#pragma once
//#define _DEBUGT
/* Standard initialisation options */
# define OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS 0x00000001L
# define OPENSSL_INIT_LOAD_CRYPTO_STRINGS    0x00000002L
# define OPENSSL_INIT_ADD_ALL_CIPHERS        0x00000004L
# define OPENSSL_INIT_ADD_ALL_DIGESTS        0x00000008L
# define OPENSSL_INIT_NO_ADD_ALL_CIPHERS     0x00000010L
# define OPENSSL_INIT_NO_ADD_ALL_DIGESTS     0x00000020L
# define OPENSSL_INIT_LOAD_CONFIG            0x00000040L
# define OPENSSL_INIT_NO_LOAD_CONFIG         0x00000080L
# define OPENSSL_INIT_ASYNC                  0x00000100L
# define OPENSSL_INIT_ENGINE_RDRAND          0x00000200L
# define OPENSSL_INIT_ENGINE_DYNAMIC         0x00000400L
# define OPENSSL_INIT_ENGINE_OPENSSL         0x00000800L
# define OPENSSL_INIT_ENGINE_CRYPTODEV       0x00001000L
# define OPENSSL_INIT_ENGINE_CAPI            0x00002000L
# define OPENSSL_INIT_ENGINE_PADLOCK         0x00004000L
# define OPENSSL_INIT_ENGINE_AFALG           0x00008000L
/* OPENSSL_INIT_ZLIB                         0x00010000L */
# define OPENSSL_INIT_ATFORK                 0x00020000L
/* OPENSSL_INIT_BASE_ONLY                    0x00040000L */
# define OPENSSL_INIT_NO_ATEXIT              0x00080000L
/* OPENSSL_INIT flag range 0xfff00000 reserved for OPENSSL_init_ssl() */
/* Max OPENSSL_INIT flag value is 0x80000000 */

/* openssl and dasync not counted as builtin */
# define OPENSSL_INIT_ENGINE_ALL_BUILTIN \
    (OPENSSL_INIT_ENGINE_RDRAND | OPENSSL_INIT_ENGINE_DYNAMIC \
    | OPENSSL_INIT_ENGINE_CRYPTODEV | OPENSSL_INIT_ENGINE_CAPI | \
    OPENSSL_INIT_ENGINE_PADLOCK)


/* OPENSSL_INIT flag 0x010000 reserved for internal use */
# define OPENSSL_INIT_NO_LOAD_SSL_STRINGS    0x00100000L
# define OPENSSL_INIT_LOAD_SSL_STRINGS       0x00200000L

# define OPENSSL_INIT_SSL_DEFAULT \
        (OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;
typedef int pem_password_cb(char* buf, int size, int rwflag, void* userdata);
typedef struct ssl_cipher_st SSL_CIPHER;

struct ssl_cipher_st {
    uint32_t valid;
    const char* name;           /* text name */
    const char* stdname;        /* RFC name */
    uint32_t id;                /* id, 4 bytes, first is version */
    /*
     * changed in 1.0.0: these four used to be portions of a single value
     * 'algorithms'
     */
    uint32_t algorithm_mkey;    /* key exchange algorithm */
    uint32_t algorithm_auth;    /* server authentication */
    uint32_t algorithm_enc;     /* symmetric encryption */
    uint32_t algorithm_mac;     /* symmetric authentication */
    int min_tls;                /* minimum SSL/TLS protocol version */
    int max_tls;                /* maximum SSL/TLS protocol version */
    int min_dtls;               /* minimum DTLS protocol version */
    int max_dtls;               /* maximum DTLS protocol version */
    uint32_t algo_strength;     /* strength and export flags */
    uint32_t algorithm2;        /* Extra flags */
    int32_t strength_bits;      /* Number of bits really used */
    uint32_t alg_bits;          /* Number of bits for algorithm */
};


typedef int(*pOPENSSL_init_ssl)(unsigned long long a1, int a2);
typedef SSL_METHOD* (*pTLSv1_client_method)();
typedef void* (*pSSL_CTX_new)(const SSL_METHOD* method);
typedef long (*pSSL_CTX_ctrl)(void* ctx, int cmd, long larg, void* parg);
typedef void (*pSSL_CTX_set_default_passwd_cb)(void* ctx, pem_password_cb* cb);
typedef void (*pSSL_CTX_set_default_passwd_cb_userdata)(void* ctx, void* u);
typedef int (*pSSL_CTX_set_default_verify_paths)(void* ctx);
typedef int (*pSSL_CTX_set_cipher_list)(void* ctx, const char* str);
typedef void (*pSSL_CTX_free)(void* ctx);
typedef void(*pSSL_set_accept_state)(void* pointer);

typedef int(*pSSL_set_ex_data)(void* s, int idx, void* arg);
typedef int (*pSSL_set_fd)(void* ssl, int fd);
typedef void* (*pSSL_get_current_cipher)(void* ssl);
typedef char* (*pSSL_CIPHER_get_name)(void* cipher);
typedef int (*pSSL_shutdown)(void* ssl);
typedef void* (*pSSL_new)(void* ctx);
typedef int(*pSSL_connect)(void* ssl);
typedef char* (*pSSL_CIPHER_description)(void* cipher, char* buf, int size);
typedef void (*pSSL_free)(void* ssl);
typedef int(*pSSL_CIPHER_get_bits)(void* cipher, int* alg_bits);
typedef char* (*pSSL_CIPHER_get_version)(void* cipher);
typedef int (*pSSL_read)(void* ssl, void* buf, int num);
typedef int (*pSSL_write)(void* ssl, void* buf, int num);
typedef int(*pSSL_get_error)(void* ssl, int ret);