#include <iostream>
#include <fstream>
extern std::ofstream logFile;
#define NEWFILE

int  OpenSSL_add_all_algorithms() {
	/*проверить! запускается через getModuleHandle*/
	return 1;
}


#ifdef NEWFILE
int  ASN1_INTEGER_get() {
	logFile << 7<< std::endl; return 1;
}

int  ASN1_INTEGER_set() {
	logFile << 8<< std::endl; return 1;
}

int  ASN1_get_object() {
	logFile << 32<< std::endl; return 1;
}

int  ASN1_object_size() {
	logFile << 35<< std::endl; return 1;
}

int  ASN1_put_object() {
	logFile << 37
		<< std::endl; return 1;
}

int  BIO_ctrl() {
	logFile << 52
		<< std::endl; return 1;
}

int  BIO_int_ctrl() {
	logFile << 53
		<< std::endl; return 1;
}

int  BIO_f_buffer() {
	logFile << 58
		<< std::endl; return 1;
}

int  BIO_find_type() {
	logFile << 65
		<< std::endl; return 1;
}

int  BIO_free() {
	logFile << 66
		<< std::endl; return 1;
}

int  BIO_free_all() {
	logFile << 67
		<< std::endl; return 1;
}

int  BIO_get_retry_reason() {
	logFile << 74
		<< std::endl; return 1;
}

int  BIO_new() {
	logFile << 78
		<< std::endl; return 1;
}

int  BIO_pop() {
	logFile << 85
		<< std::endl; return 1;
}

int  BIO_printf() {
	logFile << 86
		<< std::endl; return 1;
}

int  BIO_push() {
	logFile << 87
		<< std::endl; return 1;
}

int  BIO_puts() {
	logFile << 88
		<< std::endl; return 1;
}

int  BIO_read() {
	logFile << 89
		<< std::endl; return 1;
}

int  BIO_s_connect() {
	logFile << 91
		<< std::endl; return 1;
}

int  BIO_s_file() {
	logFile << 93
		<< std::endl; return 1;
}

int  BIO_s_mem() {
	logFile << 95
		<< std::endl; return 1;
}

int  BIO_s_socket() {
	logFile << 98
		<< std::endl; return 1;
}

int  BIO_write() {
	logFile << 109
		<< std::endl; return 1;
}

int  BN_CTX_free() {
	logFile << 110
		<< std::endl; return 1;
}

int  BN_CTX_new() {
	logFile << 111
		<< std::endl; return 1;
}

int  BN_bin2bn() {
	logFile << 118
		<< std::endl; return 1;
}

int  BN_bn2bin() {
	logFile << 120
		<< std::endl; return 1;
}

int  BN_clear_free() {
	logFile << 123
		<< std::endl; return 1;
}

int  BN_copy() {
	logFile << 125
		<< std::endl; return 1;
}

int  BN_dup() {
	logFile << 128
		<< std::endl; return 1;
}

int  BN_free() {
	logFile << 129
		<< std::endl; return 1;
}

int  BN_num_bits() {
	logFile << 151
		<< std::endl; return 1;
}

int  BN_ucmp() {
	logFile << 165
		<< std::endl; return 1;
}

int  BUF_MEM_free() {
	logFile << 167
		<< std::endl; return 1;
}

int  BUF_MEM_grow() {
	logFile << 168
		<< std::endl; return 1;
}

int  BUF_MEM_new() {
	logFile << 169
		<< std::endl; return 1;
}

int  BUF_strdup() {
	logFile << 170
		<< std::endl; return 1;
}

int  CRYPTO_add_lock() {
	logFile << 176
		<< std::endl; return 1;
}

int  CRYPTO_free() {
	logFile << 181
		<< std::endl; return 1;
}

int  CRYPTO_lock() {
	logFile << 187
		<< std::endl; return 1;
}

int  CRYPTO_malloc() {
	logFile << 188
		<< std::endl; return 1;
}

int  CRYPTO_mem_ctrl() {
	logFile << 189
		<< std::endl; return 1;
}

int  CRYPTO_realloc() {
	logFile << 193
		<< std::endl; return 1;
}

int  DH_compute_key() {
	logFile << 201
		<< std::endl; return 1;
}

int  DH_free() {
	logFile << 202
		<< std::endl; return 1;
}

int  DH_generate_key() {
	logFile << 203
		<< std::endl; return 1;
}

int  DH_new() {
	logFile << 205
		<< std::endl; return 1;
}

int  DH_size() {
	logFile << 206
		<< std::endl; return 1;
}

int  DSA_sign() {
	logFile << 216
		<< std::endl; return 1;
}

int  DSA_verify() {
	logFile << 219
		<< std::endl; return 1;
}

int  ERR_clear_error() {
	logFile << 222
		<< std::endl; return 1;
}

int  ERR_func_error_string() {
	logFile << 225
		<< std::endl; return 1;
}

void  ERR_load_crypto_strings() {
	logFile << 246
		<< std::endl; return;
}

int  ERR_load_strings() {
	logFile << 247
		<< std::endl; return 1;
}

int  ERR_peek_error() {
	logFile << 248
		<< std::endl; return 1;
}

int  ERR_put_error() {
	logFile << 252
		<< std::endl; return 1;
}

int  EVP_CIPHER_CTX_cleanup() {
	logFile << 256
		<< std::endl; return 1;
}

int  EVP_DecryptFinal() {
	logFile << 264
		<< std::endl; return 1;
}

int  EVP_DecryptUpdate() {
	logFile << 266
		<< std::endl; return 1;
}

int  EVP_DigestFinal() {
	logFile << 267
		<< std::endl; return 1;
}

int  EVP_DigestInit() {
	logFile << 268
		<< std::endl; return 1;
}

int  EVP_DigestUpdate() {
	logFile << 269
		<< std::endl; return 1;
}

int  EVP_EncryptFinal() {
	logFile << 274
		<< std::endl; return 1;
}

int  EVP_EncryptUpdate() {
	logFile << 276
		<< std::endl; return 1;
}

int  EVP_PKEY_assign() {
	logFile << 279
		<< std::endl; return 1;
}

int  EVP_PKEY_copy_parameters() {
	logFile << 280
		<< std::endl; return 1;
}

int  EVP_PKEY_free() {
	logFile << 281
		<< std::endl; return 1;
}

int  EVP_PKEY_missing_parameters() {
	logFile << 282
		<< std::endl; return 1;
}

int  EVP_PKEY_new() {
	logFile << 283
		<< std::endl; return 1;
}

int  EVP_PKEY_size() {
	logFile << 285
		<< std::endl; return 1;
}

int  EVP_SignFinal() {
	logFile << 289
		<< std::endl; return 1;
}

int  EVP_VerifyFinal() {
	logFile << 290
		<< std::endl; return 1;
}

int  EVP_add_cipher() {
	logFile << 292
		<< std::endl; return 1;
}

int  EVP_add_digest() {
	logFile << 293
		<< std::endl; return 1;
}

int  EVP_des_cbc() {
	logFile << 299
		<< std::endl; return 1;
}

int  EVP_des_ede3_cbc() {
	logFile << 304
		<< std::endl; return 1;
}

int  EVP_dss1() {
	logFile << 313
		<< std::endl; return 1;
}

int  EVP_enc_null() {
	logFile << 314
		<< std::endl; return 1;
}

int  EVP_get_cipherbyname() {
	logFile << 315
		<< std::endl; return 1;
}

int  EVP_get_digestbyname() {
	logFile << 316
		<< std::endl; return 1;
}

int  EVP_idea_cbc() {
	logFile << 318
		<< std::endl; return 1;
}

int  EVP_md5() {
	logFile << 323
		<< std::endl; return 1;
}

int  EVP_rc2_cbc() {
	logFile << 325
		<< std::endl; return 1;
}

int  EVP_rc4() {
	logFile << 329
		<< std::endl; return 1;
}

int  EVP_sha1() {
	logFile << 333
		<< std::endl; return 1;
}

int  MD5_Init() {
	logFile << 341
		<< std::endl; return 1;
}

int  OBJ_ln2nid() {
	logFile << 359
		<< std::endl; return 1;
}

int  OBJ_nid2sn() {
	logFile << 363
		<< std::endl; return 1;
}

int  OBJ_obj2nid() {
	logFile << 364
		<< std::endl; return 1;
}

int  OBJ_sn2nid() {
	logFile << 365
		<< std::endl; return 1;
}

int  PEM_ASN1_read() {
	logFile << 367
		<< std::endl; return 1;
}

int  PEM_ASN1_read_bio() {
	logFile << 368
		<< std::endl; return 1;
}

int  PEM_ASN1_write() {
	logFile << 369
		<< std::endl; return 1;
}

int  PEM_ASN1_write_bio() {
	logFile << 370
		<< std::endl; return 1;
}

int  PEM_read_bio() {
	logFile << 394
		<< std::endl; return 1;
}

int  PEM_read_bio_DHparams() {
	logFile << 395
		<< std::endl; return 1;
}

int  PEM_read_bio_PrivateKey() {
	logFile << 399
		<< std::endl; return 1;
}

int  PEM_read_bio_RSAPrivateKey() {
	logFile << 400
		<< std::endl; return 1;
}

int  PEM_read_bio_X509() {
	logFile << 401
		<< std::endl; return 1;
}

int  RAND_bytes() {
	logFile << 464
		<< std::endl; return 1;
}

int  RSAPrivateKey_dup() {
	logFile << 481
		<< std::endl; return 1;
}

int  RSA_free() {
	logFile << 484
		<< std::endl; return 1;
}

int  RSA_new() {
	logFile << 486
		<< std::endl; return 1;
}

int  RSA_private_decrypt() {
	logFile << 490
		<< std::endl; return 1;
}

int  RSA_public_encrypt() {
	logFile << 493
		<< std::endl; return 1;
}

int  RSA_sign() {
	logFile << 495
		<< std::endl; return 1;
}

int  RSA_size() {
	logFile << 497
		<< std::endl; return 1;
}

int  RSA_verify() {
	logFile << 498
		<< std::endl; return 1;
}

int  SHA1_Init() {
	logFile << 503
		<< std::endl; return 1;
}

int  X509_EXTENSION_free() {
	logFile << 541
		<< std::endl; return 1;
}

int  X509_NAME_cmp() {
	logFile << 572
		<< std::endl; return 1;
}

int  X509_NAME_dup() {
	logFile << 575
		<< std::endl; return 1;
}

int  X509_NAME_free() {
	logFile << 577
		<< std::endl; return 1;
}

int  X509_STORE_CTX_cleanup() {
	logFile << 622
		<< std::endl; return 1;
}

int  X509_STORE_CTX_init() {
	logFile << 623
		<< std::endl; return 1;
}

int  X509_STORE_add_cert() {
	logFile << 624
		<< std::endl; return 1;
}

int  X509_STORE_free() {
	logFile << 626
		<< std::endl; return 1;
}

int  X509_STORE_load_locations() {
	logFile << 628
		<< std::endl; return 1;
}

int  X509_STORE_new() {
	logFile << 629
		<< std::endl; return 1;
}

int  X509_STORE_set_default_paths() {
	logFile << 630
		<< std::endl; return 1;
}

int  X509_certificate_type() {
	logFile << 635
		<< std::endl; return 1;
}

int  X509_check_private_key() {
	logFile << 636
		<< std::endl; return 1;
}

int  X509_free() {
	logFile << 641
		<< std::endl; return 1;
}

int  X509_get_issuer_name() {
	logFile << 653
		<< std::endl; return 1;
}

int  X509_get_pubkey() {
	logFile << 654
		<< std::endl; return 1;
}

int  X509_get_subject_name() {
	logFile << 657
		<< std::endl; return 1;
}

int  X509_verify_cert() {
	logFile << 679
		<< std::endl; return 1;
}

int  X509_verify_cert_error_string() {
	logFile << 680
		<< std::endl; return 1;
}

int  asn1_GetSequence() {
	logFile << 703
		<< std::endl; return 1;
}

int  d2i_ASN1_INTEGER() {
	logFile << 716
		<< std::endl; return 1;
}

int  d2i_ASN1_OCTET_STRING() {
	logFile << 718
		<< std::endl; return 1;
}

int  d2i_PrivateKey() {
	logFile << 748
		<< std::endl; return 1;
}

int  d2i_RSAPrivateKey() {
	logFile << 750
		<< std::endl; return 1;
}

int  d2i_RSAPrivateKey_bio() {
	logFile << 751
		<< std::endl; return 1;
}

int  d2i_X509() {
	logFile << 754
		<< std::endl; return 1;
}

int  d2i_X509_NAME() {
	logFile << 763
		<< std::endl; return 1;
}

int  d2i_X509_bio() {
	logFile << 774
		<< std::endl; return 1;
}

int  i2d_ASN1_INTEGER() {
	logFile << 822
		<< std::endl; return 1;
}

int  i2d_ASN1_OCTET_STRING() {
	logFile << 824
		<< std::endl; return 1;
}

int  i2d_X509() {
	logFile << 857
		<< std::endl; return 1;
}

int  i2d_X509_NAME() {
	logFile << 866
		<< std::endl; return 1;
}

int  lh_delete() {
	logFile << 887
		<< std::endl; return 1;
}

int  lh_doall_arg() {
	logFile << 889
		<< std::endl; return 1;
}

int  lh_free() {
	logFile << 890
		<< std::endl; return 1;
}

int  lh_insert() {
	logFile << 891
		<< std::endl; return 1;
}

int  lh_new() {
	logFile << 892
		<< std::endl; return 1;
}

int  lh_retrieve() {
	logFile << 897
		<< std::endl; return 1;
}

int  sk_delete() {
	logFile << 901
		<< std::endl; return 1;
}

int  sk_dup() {
	logFile << 903
		<< std::endl; return 1;
}

int  sk_find() {
	logFile << 904
		<< std::endl; return 1;
}

int  sk_free() {
	logFile << 905
		<< std::endl; return 1;
}

int  sk_new() {
	logFile << 907
		<< std::endl; return 1;
}

int  sk_pop() {
	logFile << 908
		<< std::endl; return 1;
}

int  sk_pop_free() {
	logFile << 909
		<< std::endl; return 1;
}

int  sk_push() {
	logFile << 910
		<< std::endl; return 1;
}

int  sk_set_cmp_func() {
	logFile << 911
		<< std::endl; return 1;
}

int  sk_shift() {
	logFile << 912
		<< std::endl; return 1;
}

int  sk_zero() {
	logFile << 914
		<< std::endl; return 1;
}

int  BIO_copy_next_retry() {
	logFile << 955
		<< std::endl; return 1;
}

int  RSA_flags() {
	logFile << 956
		<< std::endl; return 1;
}

int  EVP_rc2_40_cbc() {
	logFile << 959
		<< std::endl; return 1;
}

int  EVP_CIPHER_CTX_init() {
	logFile << 961
		<< std::endl; return 1;
}

int  HMAC_Update() {
	logFile << 964
		<< std::endl; return 1;
}

int  HMAC_Final() {
	logFile << 965
		<< std::endl; return 1;
}

int  EVP_PKEY_cmp_parameters() {
	logFile << 967
		<< std::endl; return 1;
}

int  CRYPTO_free_ex_data() {
	logFile << 1004
		<< std::endl; return 1;
}

int  CRYPTO_get_ex_data() {
	logFile << 1005
		<< std::endl; return 1;
}

int  CRYPTO_set_ex_data() {
	logFile << 1007
		<< std::endl; return 1;
}

int  EVP_PKEY_bits() {
	logFile << 1010
		<< std::endl; return 1;
}

int  MD5_Transform() {
	logFile << 1011
		<< std::endl; return 1;
}

int  SHA1_Transform() {
	logFile << 1012
		<< std::endl; return 1;
}

int  X509_STORE_CTX_get_error() {
	logFile << 1016
		<< std::endl; return 1;
}

int  X509_STORE_CTX_set_ex_data() {
	logFile << 1023
		<< std::endl; return 1;
}

int  CRYPTO_dup_ex_data() {
	logFile << 1025
		<< std::endl; return 1;
}

int  CRYPTO_new_ex_data() {
	logFile << 1027
		<< std::endl; return 1;
}

int  CRYPTO_get_ex_new_index() {
	logFile << 1041
		<< std::endl; return 1;
}

int  EVP_PKEY_decrypt() {
	logFile << 1070
		<< std::endl; return 1;
}

int  EVP_PKEY_encrypt() {
	logFile << 1071
		<< std::endl; return 1;
}

int  ERR_add_error_data() {
	logFile << 1081
		<< std::endl; return 1;
}

int  asn1_add_error() {
	logFile << 1091
		<< std::endl; return 1;
}

int  COMP_CTX_new() {
	logFile << 1096
		<< std::endl; return 1;
}

int  COMP_CTX_free() {
	logFile << 1097
		<< std::endl; return 1;
}

int  X509_STORE_CTX_get_ex_new_index() {
	logFile << 1100
		<< std::endl; return 1;
}

int  OBJ_NAME_add() {
	logFile << 1101
		<< std::endl; return 1;
}

int  COMP_compress_block() {
	logFile << 1144
		<< std::endl; return 1;
}

int  COMP_expand_block() {
	logFile << 1145
		<< std::endl; return 1;
}

int  COMP_zlib() {
	logFile << 1147
		<< std::endl; return 1;
}

int  EVP_MD_CTX_copy() {
	logFile << 1202
		<< std::endl; return 1;
}

int  sk_value() {
	logFile << 1653
		<< std::endl; return 1;
}

int  sk_num() {
	logFile << 1654
		<< std::endl; return 1;
}

int  sk_set() {
	logFile << 1655
		<< std::endl; return 1;
}

int  sk_sort() {
	logFile << 1671
		<< std::endl; return 1;
}

int  PEM_read_bio_X509_AUX() {
	logFile << 1959
		<< std::endl; return 1;
}

int  X509_check_purpose() {
	logFile << 2051
		<< std::endl; return 1;
}

int  EVP_PKEY_set1_RSA() {
	logFile << 2063
		<< std::endl; return 1;
}

int  EVP_PKEY_set1_DH() {
	logFile << 2107
		<< std::endl; return 1;
}

int  EVP_PKEY_get1_DH() {
	logFile << 2128
		<< std::endl; return 1;
}

int  X509_cmp() {
	logFile << 2135
		<< std::endl; return 1;
}

int  d2i_PrivateKey_bio() {
	logFile << 2181
		<< std::endl; return 1;
}

int  RAND_add() {
	logFile << 2201
		<< std::endl; return 1;
}

int  X509_STORE_CTX_get1_chain() {
	logFile << 2204
		<< std::endl; return 1;
}

int  RAND_pseudo_bytes() {
	logFile << 2206
		<< std::endl; return 1;
}

int  BIO_callback_ctrl() {
	logFile << 2252
		<< std::endl; return 1;
}

int  lh_num_items() {
	logFile << 2257
		<< std::endl; return 1;
}

int  BIO_snprintf() {
	logFile << 2292
		<< std::endl; return 1;
}

int  EVP_CIPHER_CTX_ctrl() {
	logFile << 2400
		<< std::endl; return 1;
}

int  sk_new_null() {
	logFile << 2411
		<< std::endl; return 1;
}

int  BIO_dump_indent() {
	logFile << 2426
		<< std::endl; return 1;
}

int  X509_STORE_CTX_set_flags() {
	logFile << 2451
		<< std::endl; return 1;
}

int  ENGINE_init() {
	logFile << 2475
		<< std::endl; return 1;
}

int  ENGINE_finish() {
	logFile << 2478
		<< std::endl; return 1;
}

int  X509_STORE_CTX_set_verify_cb() {
	logFile << 2524
		<< std::endl; return 1;
}

int  EC_GROUP_method_of() {
	logFile << 2568
		<< std::endl; return 1;
}

int  HMAC_Init_ex() {
	logFile << 2572
		<< std::endl; return 1;
}

int  EC_POINT_oct2point() {
	logFile << 2578
		<< std::endl; return 1;
}

int  EVP_MD_CTX_copy_ex() {
	logFile << 2589
		<< std::endl; return 1;
}

int  EVP_MD_CTX_init() {
	logFile << 2630
		<< std::endl; return 1;
}

int  d2i_OCSP_RESPID() {
	logFile << 2702
		<< std::endl; return 1;
}

int  EVP_MD_CTX_create() {
	logFile << 2712
		<< std::endl; return 1;
}

int  HMAC_CTX_init() {
	logFile << 2747
		<< std::endl; return 1;
}

int  RSA_up_ref() {
	logFile << 2760
		<< std::endl; return 1;
}

int  HMAC_CTX_cleanup() {
	logFile << 2784
		<< std::endl; return 1;
}

int  EVP_MD_CTX_cleanup() {
	logFile << 2821
		<< std::endl; return 1;
}

int  EC_GROUP_free() {
	logFile << 2877
		<< std::endl; return 1;
}

int  EVP_EncryptInit_ex() {
	logFile << 2894
		<< std::endl; return 1;
}

int  i2d_OCSP_RESPID() {
	logFile << 2898
		<< std::endl; return 1;
}

int  EVP_CipherInit_ex() {
	logFile << 2915
		<< std::endl; return 1;
}

int  EC_POINT_new() {
	logFile << 2924
		<< std::endl; return 1;
}

int  EVP_MD_CTX_destroy() {
	logFile << 2925
		<< std::endl; return 1;
}

int  EVP_aes_128_cbc() {
	logFile << 2927
		<< std::endl; return 1;
}

int  EC_POINT_free() {
	logFile << 2929
		<< std::endl; return 1;
}

int  EVP_DigestFinal_ex() {
	logFile << 2936
		<< std::endl; return 1;
}

int  EVP_aes_256_cbc() {
	logFile << 2996
		<< std::endl; return 1;
}

int  EC_POINT_copy() {
	logFile << 3010
		<< std::endl; return 1;
}

int  EVP_DecryptInit_ex() {
	logFile << 3067
		<< std::endl; return 1;
}

int  EVP_DigestInit_ex() {
	logFile << 3109
		<< std::endl; return 1;
}

int  OCSP_RESPID_free() {
	logFile << 3124
		<< std::endl; return 1;
}

int  EVP_aes_192_cbc() {
	logFile << 3155
		<< std::endl; return 1;
}

int  EVP_Digest() {
	logFile << 3165
		<< std::endl; return 1;
}

int  EC_POINT_point2oct() {
	logFile << 3178
		<< std::endl; return 1;
}

int  CONF_parse_list() {
	logFile << 3192
		<< std::endl; return 1;
}

int  ERR_peek_last_error() {
	logFile << 3205
		<< std::endl; return 1;
}

int  BUF_MEM_grow_clean() {
	logFile << 3239
		<< std::endl; return 1;
}

int  OpenSSLDie() {
	logFile << 3244
		<< std::endl; return 1;
}

int  OPENSSL_cleanse() {
	logFile << 3245
		<< std::endl; return 1;
}

int  EVP_sha384() {
	logFile << 3312
		<< std::endl; return 1;
}

int  EVP_sha512() {
	logFile << 3313
		<< std::endl; return 1;
}

int  EVP_sha224() {
	logFile << 3314
		<< std::endl; return 1;
}

int  EVP_sha256() {
	logFile << 3315
		<< std::endl; return 1;
}

int  EC_KEY_new_by_curve_name() {
	logFile << 3353
		<< std::endl; return 1;
}

int  pitem_new() {
	logFile << 3365
		<< std::endl; return 1;
}

int  X509_VERIFY_PARAM_inherit() {
	logFile << 3378
		<< std::endl; return 1;
}

int  EC_KEY_get_conv_form() {
	logFile << 3388
		<< std::endl; return 1;
}

int  pqueue_iterator() {
	logFile << 3394
		<< std::endl; return 1;
}

int  OPENSSL_DIR_end() {
	logFile << 3396
		<< std::endl; return 1;
}

int  X509_VERIFY_PARAM_set_depth() {
	logFile << 3399
		<< std::endl; return 1;
}

int  X509_VERIFY_PARAM_set_purpose() {
	logFile << 3414
		<< std::endl; return 1;
}

int  EC_KEY_up_ref() {
	logFile << 3418
		<< std::endl; return 1;
}

int  EC_KEY_free() {
	logFile << 3422
		<< std::endl; return 1;
}

int  X509_VERIFY_PARAM_new() {
	logFile << 3437
		<< std::endl; return 1;
}

int  EVP_PKEY_set1_EC_KEY() {
	logFile << 3450
		<< std::endl; return 1;
}

int  pqueue_find() {
	logFile << 3454
		<< std::endl; return 1;
}

int  EC_KEY_set_private_key() {
	logFile << 3459
		<< std::endl; return 1;
}

int  pqueue_peek() {
	logFile << 3460
		<< std::endl; return 1;
}

int  SHA256_Init() {
	logFile << 3479
		<< std::endl; return 1;
}

int  EC_KEY_get0_public_key() {
	logFile << 3480
		<< std::endl; return 1;
}

int  BUF_memdup() {
	logFile << 3489
		<< std::endl; return 1;
}

int  X509_VERIFY_PARAM_set_trust() {
	logFile << 3495
		<< std::endl; return 1;
}

int  X509_STORE_CTX_get0_param() {
	logFile << 3505
		<< std::endl; return 1;
}

int  EC_KEY_set_group() {
	logFile << 3512
		<< std::endl; return 1;
}

int  BUF_strndup() {
	logFile << 3513
		<< std::endl; return 1;
}

int  X509_VERIFY_PARAM_free() {
	logFile << 3527
		<< std::endl; return 1;
}

int  EC_METHOD_get_field_type() {
	logFile << 3528
		<< std::endl; return 1;
}

int  EC_KEY_generate_key() {
	logFile << 3550
		<< std::endl; return 1;
}

int  X509_VERIFY_PARAM_get_depth() {
	logFile << 3559
		<< std::endl; return 1;
}

int  EC_GROUP_get_degree() {
	logFile << 3570
		<< std::endl; return 1;
}

int  EC_KEY_get0_group() {
	logFile << 3575
		<< std::endl; return 1;
}

int  X509_STORE_CTX_set_default() {
	logFile << 3595
		<< std::endl; return 1;
}

int  EC_KEY_get0_private_key() {
	logFile << 3608
		<< std::endl; return 1;
}

int  X509_VERIFY_PARAM_set1() {
	logFile << 3610
		<< std::endl; return 1;
}

int  ASN1_const_check_infinite_end() {
	logFile << 3623
		<< std::endl; return 1;
}

int  SHA224_Init() {
	logFile << 3631
		<< std::endl; return 1;
}

int  SHA512_Init() {
	logFile << 3633
		<< std::endl; return 1;
}

int  ECDH_compute_key() {
	logFile << 3644
		<< std::endl; return 1;
}

int  pqueue_pop() {
	logFile << 3647
		<< std::endl; return 1;
}

int  OPENSSL_DIR_read() {
	logFile << 3657
		<< std::endl; return 1;
}

int  EC_KEY_new() {
	logFile << 3663
		<< std::endl; return 1;
}

int  SHA256_Transform() {
	logFile << 3664
		<< std::endl; return 1;
}

int  ECDSA_verify() {
	logFile << 3666
		<< std::endl; return 1;
}

int  SHA512_Transform() {
	logFile << 3675
		<< std::endl; return 1;
}

int  EC_KEY_set_public_key() {
	logFile << 3682
		<< std::endl; return 1;
}

int  EC_GROUP_get_curve_name() {
	logFile << 3695
		<< std::endl; return 1;
}

int  asn1_const_Finish() {
	logFile << 3700
		<< std::endl; return 1;
}

int  pqueue_free() {
	logFile << 3704
		<< std::endl; return 1;
}

int  EC_GROUP_new_by_curve_name() {
	logFile << 3711
		<< std::endl; return 1;
}

int  ECDSA_sign() {
	logFile << 3719
		<< std::endl; return 1;
}

int  EVP_ecdsa() {
	logFile << 3724
		<< std::endl; return 1;
}

int  EC_KEY_dup() {
	logFile << 3729
		<< std::endl; return 1;
}

int  SHA384_Init() {
	logFile << 3737
		<< std::endl; return 1;
}

int  pqueue_next() {
	logFile << 3754
		<< std::endl; return 1;
}

int  pqueue_new() {
	logFile << 3758
		<< std::endl; return 1;
}

int  pqueue_insert() {
	logFile << 3766
		<< std::endl; return 1;
}

int  pitem_free() {
	logFile << 3767
		<< std::endl; return 1;
}

int  EVP_CIPHER_CTX_new() {
	logFile << 3782
		<< std::endl; return 1;
}

int  EVP_CIPHER_CTX_free() {
	logFile << 3783
		<< std::endl; return 1;
}

int  EVP_camellia_128_cbc() {
	logFile << 3795
		<< std::endl; return 1;
}

int  EVP_camellia_256_cbc() {
	logFile << 3807
		<< std::endl; return 1;
}

int  EVP_CIPHER_block_size() {
	logFile << 3816
		<< std::endl; return 1;
}

int  BIO_set_flags() {
	logFile << 3823
		<< std::endl; return 1;
}

int  BIO_method_type() {
	logFile << 3826
		<< std::endl; return 1;
}

int  EVP_CIPHER_iv_length() {
	logFile << 3836
		<< std::endl; return 1;
}

int  EVP_MD_type() {
	logFile << 3837
		<< std::endl; return 1;
}

int  EVP_CIPHER_CTX_key_length() {
	logFile << 3841
		<< std::endl; return 1;
}

int  EVP_MD_size() {
	logFile << 3844
		<< std::endl; return 1;
}

int  BIO_clear_flags() {
	logFile << 3846
		<< std::endl; return 1;
}

int  EVP_CIPHER_flags() {
	logFile << 3857
		<< std::endl; return 1;
}

int  BIO_test_flags() {
	logFile << 3866
		<< std::endl; return 1;
}

int  EVP_CIPHER_key_length() {
	logFile << 3873
		<< std::endl; return 1;
}

int  EVP_Cipher() {
	logFile << 3874
		<< std::endl; return 1;
}

int  EVP_CIPHER_CTX_block_size() {
	logFile << 3879
		<< std::endl; return 1;
}

int  EVP_MD_CTX_set_flags() {
	logFile << 3883
		<< std::endl; return 1;
}

int  EVP_CIPHER_CTX_cipher() {
	logFile << 3888
		<< std::endl; return 1;
}

int  EVP_CIPHER_CTX_flags() {
	logFile << 3891
		<< std::endl; return 1;
}

int  EVP_MD_CTX_md() {
	logFile << 3896
		<< std::endl; return 1;
}

int  EVP_CIPHER_CTX_iv_length() {
	logFile << 3899
		<< std::endl; return 1;
}

int  CRYPTO_memcmp() {
	logFile << 3906
		<< std::endl; return 1;
}

int  EVP_seed_cbc() {
	logFile << 3914
		<< std::endl; return 1;
}

int  i2d_X509_EXTENSIONS() {
	logFile << 3922
		<< std::endl; return 1;
}

int  d2i_X509_EXTENSIONS() {
	logFile << 3925
		<< std::endl; return 1;
}

int  ENGINE_get_ssl_client_cert_function() {
	logFile << 4045
		<< std::endl; return 1;
}

int  ENGINE_load_ssl_client_cert() {
	logFile << 4046
		<< std::endl; return 1;
}

int  pqueue_size() {
	logFile << 4114
		<< std::endl; return 1;
}

int  EVP_PKEY_CTX_new() {
	logFile << 4119
		<< std::endl; return 1;
}

int  EVP_PKEY_sign_init() {
	logFile << 4125
		<< std::endl; return 1;
}

int  EVP_DigestSignInit() {
	logFile << 4144
		<< std::endl; return 1;
}

int  EVP_PKEY_encrypt_init() {
	logFile << 4164
		<< std::endl; return 1;
}

int  EVP_PKEY_new_mac_key() {
	logFile << 4174
		<< std::endl; return 1;
}

int  OBJ_find_sigid_by_algs() {
	logFile << 4210
		<< std::endl; return 1;
}

int  EVP_PKEY_CTX_ctrl() {
	logFile << 4233
		<< std::endl; return 1;
}

int  EVP_PKEY_decrypt_init() {
	logFile << 4245
		<< std::endl; return 1;
}

int  EVP_PKEY_sign() {
	logFile << 4262
		<< std::endl; return 1;
}

int  EVP_PKEY_asn1_get0_info() {
	logFile << 4320
		<< std::endl; return 1;
}

int  OBJ_bsearch_() {
	logFile << 4331
		<< std::endl; return 1;
}

int  EVP_PKEY_verify() {
	logFile << 4369
		<< std::endl; return 1;
}

int  EVP_DigestSignFinal() {
	logFile << 4372
		<< std::endl; return 1;
}

int  EVP_PKEY_asn1_find_str() {
	logFile << 4383
		<< std::endl; return 1;
}

int  EVP_PKEY_CTX_free() {
	logFile << 4430
		<< std::endl; return 1;
}

int  EVP_PKEY_id() {
	logFile << 4470
		<< std::endl; return 1;
}

int  EVP_PKEY_verify_init() {
	logFile << 4474
		<< std::endl; return 1;
}

int  EVP_PKEY_derive_set_peer() {
	logFile << 4488
		<< std::endl; return 1;
}

int  OBJ_find_sigid_algs() {
	logFile << 4513
		<< std::endl; return 1;
}

int  DHparams_dup() {
	logFile << 4540
		<< std::endl; return 1;
}

int  SRP_Calc_server_key() {
	logFile << 4570
		<< std::endl; return 1;
}

int  SRP_create_verifier_BN() {
	logFile << 4572
		<< std::endl; return 1;
}

int  SRP_Calc_u() {
	logFile << 4573
		<< std::endl; return 1;
}

int  SRP_Calc_client_key() {
	logFile << 4575
		<< std::endl; return 1;
}

int  SRP_get_default_gN() {
	logFile << 4576
		<< std::endl; return 1;
}

int  SRP_Calc_x() {
	logFile << 4577
		<< std::endl; return 1;
}

int  SRP_Calc_B() {
	logFile << 4578
		<< std::endl; return 1;
}

int  SRP_check_known_gN_param() {
	logFile << 4580
		<< std::endl; return 1;
}

int  SRP_Calc_A() {
	logFile << 4581
		<< std::endl; return 1;
}

int  SRP_Verify_A_mod_N() {
	logFile << 4582
		<< std::endl; return 1;
}

int  SRP_Verify_B_mod_N() {
	logFile << 4584
		<< std::endl; return 1;
}

int  EVP_aes_128_gcm() {
	logFile << 4601
		<< std::endl; return 1;
}

int  EVP_aes_256_gcm() {
	logFile << 4615
		<< std::endl; return 1;
}

int  EVP_aes_128_cbc_hmac_sha1() {
	logFile << 4637
		<< std::endl; return 1;
}

int  EVP_aes_256_cbc_hmac_sha1() {
	logFile << 4656
		<< std::endl; return 1;
}

int  EC_curve_nist2nid() {
	logFile << 4684
		<< std::endl; return 1;
}

int  X509_chain_check_suiteb() {
	logFile << 4692
		<< std::endl; return 1;
}

int  X509_chain_up_ref() {
	logFile << 4693
		<< std::endl; return 1;
}

int  X509_get_signature_nid() {
	logFile << 4701
		<< std::endl; return 1;
}

int  EVP_aes_128_cbc_hmac_sha256() {
	logFile << 4731
		<< std::endl; return 1;
}

int  EVP_aes_256_cbc_hmac_sha256() {
	logFile << 4740
		<< std::endl; return 1;
}

int ERR_error_string() {
	logFile << 223
		<< std::endl; return 1;
}

int ERR_get_error() {
	logFile << 227
		<< std::endl; return 1;
}

int EVP_cleanup() {
	logFile << 298
		<< std::endl; return 1;
}	

int OpenSSL_add_all_digests() {
	logFile << 510
		<< std::endl; return 1;
}
int OpenSSL_add_all_ciphers() {
	logFile << 509
		<< std::endl; return 1;
}
#endif