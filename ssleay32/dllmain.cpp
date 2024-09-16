#include <windows.h>
#include <iostream>
#include <fstream>
#include "Header.h"
static std::ofstream procLog, threadLog;
HMODULE hLink_ssleay32, hLink_libcypto;


pOPENSSL_init_ssl pOPENSSL_init_ssl_u;
pTLSv1_client_method pTLSv1_client_method_u;
pSSL_CTX_new pSSL_CTX_new_u;
pSSL_CTX_ctrl pSSL_CTX_ctrl_u;
pSSL_CTX_set_default_passwd_cb pSSL_CTX_set_default_passwd_cb_u;
pSSL_CTX_set_default_passwd_cb_userdata pSSL_CTX_set_default_passwd_cb_userdata_u;
pSSL_CTX_set_default_verify_paths pSSL_CTX_set_default_verify_paths_u;
pSSL_CTX_set_cipher_list pSSL_CTX_set_cipher_list_u;
pSSL_CTX_free pSSL_CTX_free_u;
pSSL_set_accept_state pSSL_set_accept_state_u;
pSSL_set_ex_data pSSL_set_ex_data_u;
pSSL_set_fd pSSL_set_fd_u;
pSSL_get_current_cipher pSSL_get_current_cipher_u;
pSSL_CIPHER_get_name pSSL_CIPHER_get_name_u;
pSSL_shutdown pSSL_shutdown_u;
pSSL_new pSSL_new_u;
pSSL_connect pSSL_connect_u;
pSSL_CIPHER_description pSSL_CIPHER_description_u;
pSSL_free pSSL_free_u;
pSSL_CIPHER_get_bits pSSL_CIPHER_get_bits_u;
pSSL_CIPHER_get_version pSSL_CIPHER_get_version_u;
pSSL_read pSSL_read_u;
pSSL_write pSSL_write_u;
pSSL_get_error pSSL_get_error_u;

bool loadFunc() {
	pOPENSSL_init_ssl_u = (pOPENSSL_init_ssl)GetProcAddress(hLink_ssleay32, "OPENSSL_init_ssl");
	pTLSv1_client_method_u = (pTLSv1_client_method)GetProcAddress(hLink_ssleay32, "TLS_client_method");
	pSSL_CTX_new_u = (pSSL_CTX_new)GetProcAddress(hLink_ssleay32, "SSL_CTX_new");
	pSSL_CTX_ctrl_u = (pSSL_CTX_ctrl)GetProcAddress(hLink_ssleay32, "SSL_CTX_ctrl");
	pSSL_CTX_set_default_passwd_cb_u = (pSSL_CTX_set_default_passwd_cb)GetProcAddress(hLink_ssleay32, "SSL_CTX_set_default_passwd_cb");
	pSSL_CTX_set_default_passwd_cb_userdata_u = (pSSL_CTX_set_default_passwd_cb_userdata)GetProcAddress(hLink_ssleay32, "SSL_CTX_set_default_passwd_cb_userdata");
	pSSL_CTX_set_default_verify_paths_u = (pSSL_CTX_set_default_verify_paths)GetProcAddress(hLink_ssleay32, "SSL_CTX_set_default_verify_paths");
	pSSL_CTX_set_cipher_list_u = (pSSL_CTX_set_cipher_list)GetProcAddress(hLink_ssleay32, "SSL_CTX_set_cipher_list");
	pSSL_CTX_free_u = (pSSL_CTX_free)GetProcAddress(hLink_ssleay32, "SSL_CTX_free");
	pSSL_set_accept_state_u = (pSSL_set_accept_state)GetProcAddress(hLink_ssleay32, "SSL_set_accept_state");

	pSSL_set_ex_data_u = (pSSL_set_ex_data)GetProcAddress(hLink_ssleay32, "SSL_set_ex_data");
	pSSL_set_fd_u = (pSSL_set_fd)GetProcAddress(hLink_ssleay32, "SSL_set_fd");
	pSSL_get_current_cipher_u = (pSSL_get_current_cipher)GetProcAddress(hLink_ssleay32, "SSL_get_current_cipher");
	pSSL_CIPHER_get_name_u = (pSSL_CIPHER_get_name)GetProcAddress(hLink_ssleay32, "SSL_CIPHER_get_name");
	pSSL_shutdown_u = (pSSL_shutdown)GetProcAddress(hLink_ssleay32, "SSL_shutdown");
	pSSL_new_u = (pSSL_new)GetProcAddress(hLink_ssleay32, "SSL_new");
	pSSL_connect_u = (pSSL_connect)GetProcAddress(hLink_ssleay32, "SSL_connect");
	pSSL_CIPHER_description_u = (pSSL_CIPHER_description)GetProcAddress(hLink_ssleay32, "SSL_CIPHER_description");
	pSSL_free_u = (pSSL_free)GetProcAddress(hLink_ssleay32, "SSL_free");
	pSSL_CIPHER_get_bits_u = (pSSL_CIPHER_get_bits)GetProcAddress(hLink_ssleay32, "SSL_CIPHER_get_bits");
	pSSL_CIPHER_get_version_u = (pSSL_CIPHER_get_version)GetProcAddress(hLink_ssleay32, "SSL_CIPHER_get_version");
	pSSL_read_u = (pSSL_read)GetProcAddress(hLink_ssleay32, "SSL_read");
	pSSL_write_u = (pSSL_write)GetProcAddress(hLink_ssleay32, "SSL_write");
	pSSL_get_error_u = (pSSL_get_error)GetProcAddress(hLink_ssleay32, "SSL_get_error");
#ifdef ssldebug
	procLog << pOPENSSL_init_ssl_u << '\t' << pTLSv1_client_method_u << '\t' << pSSL_CTX_new_u << '\t' << pSSL_CTX_ctrl_u << '\t' << pSSL_CTX_set_default_passwd_cb_u << '\t' << pSSL_CTX_set_default_passwd_cb_userdata_u
		<< '\t' << pSSL_CTX_set_default_verify_paths_u << '\t' << pSSL_CTX_set_cipher_list_u << '\t' << pSSL_CTX_free_u << '\t' << pSSL_set_accept_state_u <<
		'\t' << pSSL_set_ex_data_u << '\t' << pSSL_set_fd_u << '\t' << pSSL_get_current_cipher_u << '\t' << pSSL_CIPHER_get_name_u << '\t' << pSSL_shutdown_u << std::endl << std::endl;
#endif
	return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
#ifdef _DEBUGT
		procLog.open("layer_ssleay32.log", std::ios::app);
#endif
		hLink_ssleay32 = LoadLibraryW(L"libssl-1_1.dll");
		hLink_libcypto = LoadLibraryW(L"libcrypto-1_1.dll");
#ifdef _DEBUGT
		if (hLink_ssleay32 == 0) return -1;
		procLog << "load libssl-1_1.dll complete\n";
		if (hLink_libcypto == 0) return -1;
		procLog << "load libcrypto-1_1.dll complete\n";
#endif
		bool res = loadFunc();


		break;
	}
	case DLL_THREAD_ATTACH: {
#ifdef _DEBUGT
		threadLog.open("thread_ssleay32.log", std::ios::app);
#endif
		break;
	}
	case DLL_THREAD_DETACH: {
		//
		break;
	}
	case DLL_PROCESS_DETACH:
	{
		if (threadLog.is_open()) { threadLog.close(); }
		if (hLink_ssleay32) {
			FreeLibrary(hLink_ssleay32);
#ifdef _DEBUGT
			procLog << "Unload libssl-1_1.dll complete\n";
#endif
		}
		if (hLink_libcypto) {
			FreeLibrary(hLink_libcypto);
#ifdef _DEBUGT
			procLog << "Unload libcrypto-1_1.dll complete\n";
#endif
		}

		if (procLog.is_open()) procLog.close();
		break;
	}

	}
	return TRUE;
}




long SSL_CTX_ctrl(void* ctx, int cmd, long larg, void* parg) {
#ifdef _DEBUGT
	procLog << "SSL_CTX_ctrl" << '\t' << ctx << '\t' << cmd << '\t' << larg << '\t' << parg << '\t\t';
#endif
	long tmp = pSSL_CTX_ctrl_u(ctx, cmd, larg, parg);
#ifdef _DEBUGT
	procLog << tmp << std::endl;
#endif
	return tmp;
}

void SSL_CTX_free(void* ctx) {
#ifdef _DEBUGT
	procLog << "SSL_CTX_free" << '\t' << ctx << std::endl;
#endif
	pSSL_CTX_free_u(ctx);
	//return 3;
}

void* SSL_CTX_new(const SSL_METHOD* method) {
#ifdef _DEBUGT
	procLog << "SSL_CTX_new" << '\t' << method << '\t';
#endif
	void* tmp = pSSL_CTX_new_u(method);
#ifdef _DEBUGT
	procLog << tmp << std::endl;
#endif
	return tmp;
}

int SSL_CTX_set_cipher_list(void* ctx, const char* str) {
#ifdef _DEBUGT
	procLog << "SSL_CTX_set_cipher_list" << '\t' << ctx << '\t' << str << '\t';
#endif
	int tmp = pSSL_CTX_set_cipher_list_u(ctx, str);
#ifdef _DEBUGT
	procLog << tmp << std::endl;
#endif
	return tmp;
}

void SSL_CTX_set_default_passwd_cb(void* ctx, pem_password_cb* cb) {
#ifdef _DEBUGT
	procLog << "SSL_CTX_set_default_passwd_cb" << '\t' << ctx << '\t' << cb << std::endl;
#endif
	pSSL_CTX_set_default_passwd_cb_u(ctx, cb);
	//return 3;
}

int SSL_load_error_strings() {
#ifdef _DEBUGT
	procLog << "SSL_load_error_strings" << '\t';
#endif
	//int result = pOPENSSL_init_ssl_u(OPENSSL_INIT_LOAD_SSL_STRINGS, 0);
	//procLog << result << std::endl;
	return 1;
}

int SSL_CTX_set_default_verify_paths(void* ctx) {
#ifdef _DEBUGT
	procLog << "SSL_CTX_set_default_verify_paths" << '\t' << ctx << '\t';
#endif
	int tmp = pSSL_CTX_set_default_verify_paths_u(ctx);
#ifdef _DEBUGT
	procLog << tmp << std::endl;
#endif
	return tmp;
}

SSL_METHOD* TLSv1_client_method() {
	/*The SSL_CTX object uses method as connection method. The methods exist in a generic type
	(for client and server use), a server only type, and a client only type. method can be of the following types:
	TLS_method(), TLS_server_method(), TLS_client_method()  These are the general-purpose version-flexible
	SSL/TLS methods. The actual protocol version used will be negotiated to the highest version mutually
	supported by the client and the server. The supported protocols are SSLv3, TLSv1, TLSv1.1, TLSv1.2 and TLSv1.3.
	Applications should use these methods, and avoid the version-specific methods described below, which are deprecated.
*/
#ifdef _DEBUGT
	procLog << "TLSv1_client_method" << '\t';
#endif
	SSL_METHOD* tmp = pTLSv1_client_method_u();
#ifdef _DEBUGT
	procLog << tmp << std::endl;
#endif
	return tmp;
}

int SSL_library_init() {
#ifdef _DEBUGT
	procLog << "SSL_library_init"
		<< std::endl; 
#endif
	return 1;
}

void SSL_CTX_set_default_passwd_cb_userdata(void* ctx, void* u) {
#ifdef _DEBUGT
	procLog << "SSL_CTX_set_default_passwd_cb_userdata" << '\t' << ctx << '\t' << u << std::endl;
#endif
	pSSL_CTX_set_default_passwd_cb_userdata_u(ctx, u);
	//return 3;
}



void ERR_load_SSL_strings() {
#ifdef _DEBUGT
	procLog << 1
		<< std::endl;
#endif
}

char* SSL_CIPHER_description(void* cipher, char* buf, int size) {

	char* tmp = pSSL_CIPHER_description_u(cipher, buf, size);
#ifdef _DEBUGT
	procLog << "pSSL_CIPHER_description_u\t" << cipher << '\t' << buf << '\t' << size << std::endl;
#endif
	return tmp;
}

int SSL_CTX_add_client_CA() {
#ifdef _DEBUGT
	procLog << 3
		<< std::endl; 
#endif
	return 4
		;
}

int SSL_CTX_add_session() {
#ifdef _DEBUGT
	procLog << 4
		<< std::endl;
#endif
	return 5
		;
}

int SSL_CTX_check_private_key() {
#ifdef _DEBUGT
	procLog << 5
		<< std::endl;
#endif
		return 6
		;

}


int SSL_CTX_flush_sessions() {
#ifdef _DEBUGT
	procLog << 7
		<< std::endl; 
#endif
		return 8
		;
}


int SSL_CTX_get_client_CA_list() {
#ifdef _DEBUGT
	procLog << 9
		<< std::endl; 
#endif
		return 10
		;
}

int SSL_CTX_get_verify_callback() {
#ifdef _DEBUGT
	procLog << 10
		<< std::endl; 
	#endif
	return 11
		;
}

int SSL_CTX_get_verify_mode() {
#ifdef _DEBUGT
	procLog << 11
		<< std::endl;
	#endif
	return 12
		;
}


int SSL_CTX_remove_session() {
#ifdef _DEBUGT
	procLog << 13
		<< std::endl; 
	#endif
	return 14
		;
}

int ssl2_ciphers() {
#ifdef _DEBUGT
	procLog << 14
		<< std::endl; 
	#endif
	return 15
		;
}


int SSL_CTX_set_client_CA_list() {
#ifdef _DEBUGT
	procLog << 16
		<< std::endl; 
	#endif
	return 16
		;
}


int ssl3_ciphers() {
#ifdef _DEBUGT
	procLog << 18
		<< std::endl;
	#endif
	return 19
		;
}

int SSL_CTX_set_ssl_version() {
#ifdef _DEBUGT
	procLog << 19
		<< std::endl; 
	#endif
	return 20
		;
}

int SSL_CTX_set_verify() {
#ifdef _DEBUGT
	procLog << 21
		<< std::endl;
	#endif
	return 22
		;
}

int SSL_CTX_use_PrivateKey() {
#ifdef _DEBUGT
	procLog << 22
		<< std::endl; 
	#endif
	return 23
		;
}

int SSL_CTX_use_PrivateKey_ASN1() {
#ifdef _DEBUGT
	procLog << 23
		<< std::endl;
	#endif
	return 24
		;
}

int SSL_CTX_use_PrivateKey_file() {
#ifdef _DEBUGT
	procLog << 24
		<< std::endl;
	#endif
	return 25
		;
}

int SSL_CTX_use_RSAPrivateKey() {
#ifdef _DEBUGT
	procLog << 25
		<< std::endl;
	#endif
	return 26
		;
}

int SSL_CTX_use_RSAPrivateKey_ASN1() {
#ifdef _DEBUGT
	procLog << 26
		<< std::endl;
	#endif
	return 27
		;
}

int SSL_CTX_use_RSAPrivateKey_file() {
#ifdef _DEBUGT
	procLog << 27
		<< std::endl;
	#endif
	return 28
		;
}

int SSL_CTX_use_certificate() {
#ifdef _DEBUGT
	procLog << 28
		<< std::endl;
	#endif
	return 29
		;
}

int SSL_CTX_use_certificate_ASN1() {
#ifdef _DEBUGT
	procLog << 29
		<< std::endl;
	#endif
	return 30
		;
}

int SSL_CTX_use_certificate_file() {
#ifdef _DEBUGT
	procLog << 30
		<< std::endl; 
	#endif
	return 31
		;
}

int SSL_SESSION_free() {
#ifdef _DEBUGT
	procLog << 31
		<< std::endl;
	#endif
	return 32
		;
}

int SSL_SESSION_new() {
#ifdef _DEBUGT
	procLog << 32
		<< std::endl;
	#endif
	return 33
		;
}

int SSL_SESSION_print() {
#ifdef _DEBUGT
	procLog << 33
		<< std::endl;
	#endif
	return 34
		;
}

int SSL_SESSION_print_fp() {
#ifdef _DEBUGT
	procLog << 34
		<< std::endl;
	#endif
	return 35
		;
}

int SSL_accept() {
#ifdef _DEBUGT
	procLog << 35
		<< std::endl;
	#endif
	return 36
		;
}

int SSL_add_client_CA() {
#ifdef _DEBUGT
	procLog << 36
		<< std::endl;
	#endif
	return 37
		;
}

int SSL_alert_desc_string() {
#ifdef _DEBUGT
	procLog << 37
		<< std::endl;
	#endif
	return 38
		;
}

int SSL_alert_desc_string_long() {
#ifdef _DEBUGT
	procLog << 38
		<< std::endl; 
	#endif
	return 39
		;
}

int SSL_alert_type_string() {
#ifdef _DEBUGT
	procLog << 39
		<< std::endl;
	#endif
	return 40
		;
}

int SSL_alert_type_string_long() {
#ifdef _DEBUGT
	procLog << 40
		<< std::endl;
	#endif
	return 41
		;
}

int SSL_check_private_key() {
#ifdef _DEBUGT
	procLog << 41
		<< std::endl; 
	#endif
	return 42
		;
}

int SSL_clear() {
#ifdef _DEBUGT
	procLog << 42
		<< std::endl;
	#endif
	return 43
		;
}

int SSL_connect(void* ctx) {

	int tmp = pSSL_connect_u(ctx);
#ifdef _DEBUGT
	procLog << "SSL_connect\t" << tmp << std::endl;
#endif
	return tmp;
}

int SSL_copy_session_id() {
#ifdef _DEBUGT

		procLog << 44
		<< std::endl;
		#endif
		return 45
		;
}

int SSL_ctrl() {
#ifdef _DEBUGT

	procLog << 45
		<< std::endl; 
	#endif
	return 46
		;
}

int SSL_dup() {
#ifdef _DEBUGT
	procLog << 46
		<< std::endl;
	#endif
	return 47
		;
}

int SSL_dup_CA_list() {
#ifdef _DEBUGT
	procLog << 47
		<< std::endl;
	#endif
	return 48
		;
}

void SSL_free(void* ssl) {
#ifdef _DEBUGT
	procLog << "SSL_free" << std::endl;
#endif
	pSSL_free_u(ssl);
}

int SSL_get_certificate() {
#ifdef _DEBUGT
	procLog << 49
		<< std::endl;
	#endif
	return 50
		;
}

int SSL_get_cipher_list() {
#ifdef _DEBUGT
	procLog << 52
		<< std::endl;
	#endif
	return 53
		;
}

int SSL_get_ciphers() {
#ifdef _DEBUGT
	procLog << 55
		<< std::endl;
	#endif
	return 56
		;
}

int SSL_get_client_CA_list() {
#ifdef _DEBUGT
	procLog << 56
		<< std::endl;
	#endif
	return 57
		;
}

int SSL_get_default_timeout() {
#ifdef _DEBUGT
	procLog << 57
		<< std::endl;
	#endif
	return 58
		;
}

int SSL_get_error(void* ssl, int ret) {

	int tmp = pSSL_get_error_u(ssl, ret);
#ifdef _DEBUGT
	procLog << "SSL_get_error\t" << ssl << '\t' << ret << '\t' << tmp << std::endl;
#endif
	return 59;
}

int SSL_get_fd() {
#ifdef _DEBUGT
	procLog << 59
		<< std::endl;
	#endif
	return 60
		;
}

int SSL_get_peer_cert_chain() {
#ifdef _DEBUGT
	procLog << 60
		<< std::endl;
	#endif
	return 61
		;
}

int SSL_get_peer_certificate() {
#ifdef _DEBUGT
	procLog << 61
		<< std::endl;
	#endif
	return 62
		;
}

int SSL_get_rbio() {
#ifdef _DEBUGT
	procLog << 63
		<< std::endl;
	#endif
	return 64
		;
}

int SSL_get_read_ahead() {
#ifdef _DEBUGT
	procLog << 64
		<< std::endl;
	#endif
	return 65
		;
}

int SSL_get_shared_ciphers() {
#ifdef _DEBUGT
	procLog << 65
		<< std::endl; 
	#endif
	return 66
		;
}

int SSL_get_ssl_method() {
#ifdef _DEBUGT
	procLog << 66
		<< std::endl;
	#endif
	return 67
		;
}

int SSL_get_verify_callback() {
#ifdef _DEBUGT
	procLog << 69
		<< std::endl;
	#endif
	return 70
		;
}

int SSL_get_verify_mode() {
#ifdef _DEBUGT
	procLog << 70
		<< std::endl;
	#endif
	return 71
		;
}

int SSL_get_version() {
#ifdef _DEBUGT
	procLog << 71
		<< std::endl;
	#endif
	return 72
		;
}

int SSL_get_wbio() {
#ifdef _DEBUGT
	procLog << 72
		<< std::endl;
	#endif
	return 73
		;
}

int SSL_load_client_CA_file() {
#ifdef _DEBUGT
	procLog << 73
		<< std::endl;
	#endif
	return 74
		;
}


void* SSL_new(void* ctx) {
#ifdef _DEBUGT
	procLog << "SSL_new\t";
#endif
	void* tmp = pSSL_new_u(ctx);
#ifdef _DEBUGT
	procLog << tmp << std::endl;
#endif
	return tmp;
}

int SSL_peek() {
#ifdef _DEBUGT
	procLog << 76
		<< std::endl;
	#endif
	return 76
		;
}

int SSL_pending() {
#ifdef _DEBUGT
	procLog << 77
		<< std::endl;
	#endif
	return 78
		;
}

int SSL_read(void* ssl, void* buf, int num) {
	int tmp = pSSL_read_u(ssl, buf, num);
#ifdef _DEBUGT
	procLog << "SSL_read\t" << ssl << '\t' << buf << '\t' << num << '\t' << tmp << std::endl;
#endif
	return tmp;
}

int SSL_renegotiate() {
#ifdef _DEBUGT
	procLog << 79
		<< std::endl;
	#endif
	return 81
		;
}

int SSL_rstate_string() {
#ifdef _DEBUGT
	procLog << 80
		<< std::endl;
	#endif
	return 82
		;
}

int SSL_rstate_string_long() {
#ifdef _DEBUGT
	procLog << 81
		<< std::endl;
	#endif
	return 83
		;
}

void SSL_set_accept_state(void* pointer) {
#ifdef _DEBUGT
	procLog << 82 << '\t' << pointer << std::endl;
#endif
	pSSL_set_accept_state_u(pointer);

}

int SSL_set_bio() {
#ifdef _DEBUGT
	procLog << 83
		<< std::endl; 
	#endif
	return 83
		;
}

int SSL_set_cipher_list() {
#ifdef _DEBUGT
	procLog << 84
		<< std::endl;
	#endif
	return 84
		;
}

int SSL_set_client_CA_list() {
#ifdef _DEBUGT
	procLog << 85
		<< std::endl;
	#endif
	return 85
		;
}

int SSL_set_connect_state() {
#ifdef _DEBUGT
	procLog << 86
		<< std::endl;
#endif
		return 86
		;
}

int SSL_set_fd(void* ssl, int fd) {
#ifdef _DEBUGT
	procLog << "SSL_set_fd" << '\t';
#endif
	int tmp = pSSL_set_fd_u(ssl, fd);
#ifdef _DEBUGT
	procLog << tmp << std::endl;
#endif
	return tmp;
}

int SSL_set_read_ahead() {
#ifdef _DEBUGT
	procLog << 88
		<< std::endl;
	#endif
	return 88
		;
}

int SSL_set_rfd() {
	procLog << 89
		<< std::endl; return 89
		;
}

int SSL_set_session() {
	procLog << 90
		<< std::endl; return 90
		;
}

int SSL_set_ssl_method() {
	procLog << 91
		<< std::endl; return 91
		;
}

int SSL_set_verify() {
	procLog << 94
		<< std::endl; return 94
		;
}

int SSL_set_wfd() {
	procLog << 95
		<< std::endl; return 95
		;
}

int SSL_shutdown(void* ssl) {
#ifdef _DEBUGT
	procLog << "SSL_shutdown\t";
#endif
	int tmp = pSSL_shutdown_u(ssl);
#ifdef _DEBUGT
	procLog << tmp << std::endl;
#endif
	return tmp;
}

int SSL_state_string() {
	procLog << 97
		<< std::endl; return 97
		;
}

int SSL_state_string_long() {
	procLog << 98
		<< std::endl; return 98
		;
}

int SSL_use_PrivateKey() {
	procLog << 99
		<< std::endl; return 99
		;
}

int SSL_use_PrivateKey_ASN1() {
	procLog << 100
		<< std::endl; return 100
		;
}

int SSL_use_PrivateKey_file() {
	procLog << 101
		<< std::endl; return 101
		;
}

int SSL_use_RSAPrivateKey() {
	procLog << 102
		<< std::endl; return 102
		;
}

int SSL_use_RSAPrivateKey_ASN1() {
	procLog << 103
		<< std::endl; return 103
		;
}

int SSL_use_RSAPrivateKey_file() {
	procLog << 104
		<< std::endl; return 104
		;
}

int SSL_use_certificate() {
	procLog << 105
		<< std::endl; return 105
		;
}

int SSL_use_certificate_ASN1() {
	procLog << 106
		<< std::endl; return 106
		;
}

int SSL_use_certificate_file() {
	procLog << 107
		<< std::endl; return 107
		;
}

int SSL_write(void* ssl, void* buf, int num) {
	int tmp = pSSL_write_u(ssl, buf, num);
#ifdef _DEBUGT
	procLog << "SSL_write\t" << ssl << '\t' << buf << '\t' << num << '\t' << tmp << std::endl;
#endif
	return tmp;
}

int SSLv23_client_method() {
	procLog << 110
		<< std::endl; return 110
		;
}

int SSLv23_method() {
	procLog << 111
		<< std::endl; return 111
		;
}

int SSLv23_server_method() {
	procLog << 112
		<< std::endl; return 112
		;
}

int SSLv2_client_method() {
	procLog << 113
		<< std::endl; return 113
		;
}

int SSLv2_method() {
	procLog << 114
		<< std::endl; return 114
		;
}

int SSLv2_server_method() {
	procLog << 115
		<< std::endl; return 115
		;
}

int SSLv3_client_method() {
	procLog << 116
		<< std::endl; return 116
		;
}

int SSLv3_method() {
	procLog << 117
		<< std::endl; return 117
		;
}

int SSLv3_server_method() {
	procLog << 118
		<< std::endl; return 118
		;
}

int d2i_SSL_SESSION() {
	procLog << 119
		<< std::endl; return 119
		;
}

int i2d_SSL_SESSION() {
	procLog << 120
		<< std::endl; return 120
		;
}

int BIO_f_ssl() {
	procLog << 121
		<< std::endl; return 121
		;
}

int BIO_new_ssl() {
	procLog << 122
		<< std::endl; return 122
		;
}

int BIO_ssl_copy_session_id() {
	procLog << 124
		<< std::endl; return 124
		;
}

int SSL_do_handshake() {
	procLog << 125
		<< std::endl; return 125
		;
}

int SSL_get_privatekey() {
	procLog << 126
		<< std::endl; return 126
		;
}

void* SSL_get_current_cipher(void* ssl) {
#ifdef _DEBUGT
	procLog << "SSL_get_current_cipher\t";
#endif
	void* tmp = pSSL_get_current_cipher_u(ssl);
#ifdef _DEBUGT
	procLog << tmp << std::endl;
#endif
	return tmp;
}

int SSL_CIPHER_get_bits(void* cipher, int* alg_bits) {

	int tmp = pSSL_CIPHER_get_bits_u(cipher, alg_bits);
#ifdef _DEBUGT
	procLog << "SSL_CIPHER_get_bits\t" << cipher << '\t' << alg_bits << '\t' << tmp << std::endl;
#endif
	return tmp;
}

char* SSL_CIPHER_get_version(void* cipher) {
	char* tmp = pSSL_CIPHER_get_version_u(cipher);
#ifdef _DEBUGT
	procLog << "SSL_CIPHER_get_version\t" << cipher << '\t' << tmp << std::endl;
#endif
	return tmp;
}

char* SSL_CIPHER_get_name(void* cipher) {
#ifdef _DEBUGT
	procLog << "SSL_CIPHER_get_name\t";
#endif
	char* tmp = pSSL_CIPHER_get_name_u(cipher);
#ifdef _DEBUGT
	procLog << tmp << std::endl;
#endif
	return tmp;
}

int BIO_ssl_shutdown() {
	procLog << 131
		<< std::endl; return 131
		;
}

int SSL_SESSION_get_time() {
	procLog << 134
		<< std::endl; return 134
		;
}

int SSL_SESSION_set_time() {
	procLog << 135
		<< std::endl; return 135
		;
}

int SSL_SESSION_get_timeout() {
	procLog << 136
		<< std::endl; return 136
		;
}

int SSL_SESSION_set_timeout() {
	procLog << 137
		<< std::endl; return 137
		;
}

int SSL_CTX_get_ex_data() {
	procLog << 138
		<< std::endl; return 138
		;
}

int SSL_CTX_get_quiet_shutdown() {
	procLog << 140
		<< std::endl; return 140
		;
}

int SSL_CTX_load_verify_locations() {
	procLog << 141
		<< std::endl; return 141
		;
}


int SSL_CTX_set_ex_data() {
	procLog << 143
		<< std::endl; return 143
		;
}

int SSL_CTX_set_quiet_shutdown() {
	procLog << 145
		<< std::endl; return 145
		;
}

int SSL_SESSION_get_ex_data() {
	procLog << 146
		<< std::endl; return 146
		;
}

int SSL_SESSION_set_ex_data() {
	procLog << 148
		<< std::endl; return 148
		;
}

int SSL_get_SSL_CTX() {
	procLog << 150
		<< std::endl; return 150
		;
}

int SSL_get_ex_data() {
	procLog << 151
		<< std::endl; return 151
		;
}

int SSL_get_quiet_shutdown() {
	procLog << 153
		<< std::endl; return 153
		;
}

int SSL_get_session() {
	procLog << 154
		<< std::endl; return 154
		;
}

int SSL_get_shutdown() {
	procLog << 155
		<< std::endl; return 155
		;
}

int SSL_get_verify_result() {
	procLog << 157
		<< std::endl; return 157
		;
}

int SSL_set_ex_data(void* s, int idx, void* arg) {
#ifdef _DEBUGT
	procLog << "SSL_set_ex_data\t";
#endif
	int tmp = pSSL_set_ex_data_u(s, idx, arg);
#ifdef _DEBUGT
	procLog << tmp << std::endl;
#endif
	return tmp;
}

int SSL_set_info_callback() {
	procLog << 160
		<< std::endl; return 160
		;
}

int SSL_set_quiet_shutdown() {
	procLog << 161
		<< std::endl; return 161
		;
}

int SSL_set_shutdown() {
	procLog << 162
		<< std::endl; return 162
		;
}

int SSL_set_verify_result() {
	procLog << 163
		<< std::endl; return 163
		;
}

int SSL_version() {
	procLog << 164
		<< std::endl; return 164
		;
}

int SSL_get_info_callback() {
	procLog << 165
		<< std::endl; return 165
		;
}

int SSL_state() {
	procLog << 166
		<< std::endl; return 166
		;
}

int SSL_CTX_get_ex_new_index() {
	procLog << 167
		<< std::endl; return 167
		;
}

int SSL_SESSION_get_ex_new_index() {
	procLog << 168
		<< std::endl; return 168
		;
}

int SSL_get_ex_new_index() {
	procLog << 169
		<< std::endl; return 169
		;
}

int TLSv1_method() {
	procLog << 170
		<< std::endl; return 170
		;
}

int TLSv1_server_method() {
	procLog << 171
		<< std::endl; return 171
		;
}

int BIO_new_buffer_ssl_connect() {
	procLog << 173
		<< std::endl; return 173
		;
}

int BIO_new_ssl_connect() {
	procLog << 174
		<< std::endl; return 174
		;
}

int SSL_get_ex_data_X509_STORE_CTX_idx() {
	procLog << 175
		<< std::endl; return 175
		;
}

int SSL_CTX_set_tmp_dh_callback() {
	procLog << 176
		<< std::endl; return 176
		;
}

int SSL_CTX_set_tmp_rsa_callback() {
	procLog << 177
		<< std::endl; return 177
		;
}

int SSL_CTX_set_timeout() {
	procLog << 178
		<< std::endl; return 178
		;
}

int SSL_CTX_get_timeout() {
	procLog << 179
		<< std::endl; return 179
		;
}

int SSL_CTX_get_cert_store() {
	procLog << 180
		<< std::endl; return 180
		;
}

int SSL_CTX_set_cert_store() {
	procLog << 181
		<< std::endl; return 181
		;
}

int SSL_want() {
	procLog << 182
		<< std::endl; return 182
		;
}


int SSL_COMP_add_compression_method() {
	procLog << 184
		<< std::endl; return 184
		;
}

int SSL_add_file_cert_subjects_to_stack() {
	procLog << 185
		<< std::endl; return 185
		;
}

int SSL_set_tmp_rsa_callback() {
	procLog << 186
		<< std::endl; return 186
		;
}

int SSL_set_tmp_dh_callback() {
	procLog << 187
		<< std::endl; return 187
		;
}

int SSL_add_dir_cert_subjects_to_stack() {
	procLog << 188
		<< std::endl; return 188
		;
}

int SSL_set_session_id_context() {
	procLog << 189
		<< std::endl; return 189
		;
}

int SSL_CTX_use_certificate_chain_file() {
	procLog << 222
		<< std::endl; return 222
		;
}

int SSL_CTX_set_verify_depth() {
	procLog << 225
		<< std::endl; return 225
		;
}

int SSL_set_verify_depth() {
	procLog << 226
		<< std::endl; return 226
		;
}

int SSL_CTX_get_verify_depth() {
	procLog << 228
		<< std::endl; return 228
		;
}

int SSL_get_verify_depth() {
	procLog << 229
		<< std::endl; return 229
		;
}

int SSL_CTX_set_session_id_context() {
	procLog << 231
		<< std::endl; return 231
		;
}

int SSL_CTX_set_cert_verify_callback() {
	procLog << 232
		<< std::endl; return 232
		;
}


int SSL_set_purpose() {
	procLog << 236
		<< std::endl; return 236
		;
}

int SSL_CTX_set_trust() {
	procLog << 237
		<< std::endl; return 237
		;
}

int SSL_CTX_set_purpose() {
	procLog << 238
		<< std::endl; return 238
		;
}

int SSL_set_trust() {
	procLog << 239
		<< std::endl; return 239
		;
}

int SSL_get_finished() {
	procLog << 240
		<< std::endl; return 240
		;
}

int SSL_get_peer_finished() {
	procLog << 241
		<< std::endl; return 241
		;
}

int SSL_get1_session() {
	procLog << 242
		<< std::endl; return 242
		;
}

int SSL_CTX_callback_ctrl() {
	procLog << 243
		<< std::endl; return 243
		;
}

int SSL_callback_ctrl() {
	procLog << 244
		<< std::endl; return 244
		;
}

int SSL_CTX_sessions() {
	procLog << 245
		<< std::endl; return 245
		;
}

int SSL_get_rfd() {
	procLog << 246
		<< std::endl; return 246
		;
}

int SSL_get_wfd() {
	procLog << 247
		<< std::endl; return 247
		;
}

int SSL_has_matching_session_id() {
	procLog << 249
		<< std::endl; return 249
		;
}

int SSL_set_generate_session_id() {
	procLog << 258
		<< std::endl; return 258
		;
}

int SSL_CTX_set_generate_session_id() {
	procLog << 264
		<< std::endl; return 264
		;
}

int SSL_renegotiate_pending() {
	procLog << 265
		<< std::endl; return 265
		;
}

int SSL_CTX_set_msg_callback() {
	procLog << 266
		<< std::endl; return 266
		;
}

int SSL_set_msg_callback() {
	procLog << 267
		<< std::endl; return 267
		;
}

int DTLSv1_client_method() {
	procLog << 268
		<< std::endl; return 268
		;
}

int SSL_CTX_set_tmp_ecdh_callback() {
	procLog << 269
		<< std::endl; return 269
		;
}

int SSL_set_tmp_ecdh_callback() {
	procLog << 270
		<< std::endl; return 270
		;
}

int SSL_COMP_get_name() {
	procLog << 271
		<< std::endl; return 271
		;
}

int SSL_get_current_compression() {
	procLog << 272
		<< std::endl; return 272
		;
}

int DTLSv1_method() {
	procLog << 273
		<< std::endl; return 273
		;
}

int SSL_get_current_expansion() {
	procLog << 274
		<< std::endl; return 274
		;
}

int DTLSv1_server_method() {
	procLog << 275
		<< std::endl; return 275
		;
}

int SSL_COMP_get_compression_methods() {
	procLog << 276
		<< std::endl; return 276
		;
}

int SSL_SESSION_get_id() {
	procLog << 277
		<< std::endl; return 277
		;
}

int SSL_CTX_sess_set_new_cb() {
	procLog << 278
		<< std::endl; return 278
		;
}

int SSL_CTX_sess_get_get_cb() {
	procLog << 279
		<< std::endl; return 279
		;
}

int SSL_CTX_sess_set_get_cb() {
	procLog << 280
		<< std::endl; return 280
		;
}

int SSL_CTX_set_cookie_verify_cb() {
	procLog << 281
		<< std::endl; return 281
		;
}

void SSL_CTX_get_info_callback() {
	procLog << 282
		<< std::endl;
}

int SSL_CTX_set_cookie_generate_cb() {
	procLog << 283
		<< std::endl; return 283
		;
}

int SSL_CTX_set_client_cert_cb() {
	procLog << 284
		<< std::endl; return 284
		;
}

int SSL_CTX_sess_set_remove_cb() {
	procLog << 285
		<< std::endl; return 285
		;
}

int SSL_CTX_set_info_callback() {
	procLog << 286
		<< std::endl; return 286
		;
}

int SSL_CTX_sess_get_new_cb() {
	procLog << 287
		<< std::endl; return 287
		;
}

int SSL_CTX_get_client_cert_cb() {
	procLog << 288
		<< std::endl; return 288
		;
}

int SSL_CTX_sess_get_remove_cb() {
	procLog << 289
		<< std::endl; return 289
		;
}

int SSL_set_SSL_CTX() {
	procLog << 290
		<< std::endl; return 290
		;
}

int SSL_get_servername() {
	procLog << 291
		<< std::endl; return 291
		;
}

int SSL_get_servername_type() {
	procLog << 292
		<< std::endl; return 292
		;
}

int SSL_CTX_set_client_cert_engine() {
	procLog << 293
		<< std::endl; return 293
		;
}

int SSL_CTX_use_psk_identity_hint() {
	procLog << 294
		<< std::endl; return 294
		;
}

int SSL_CTX_set_psk_client_callback() {
	procLog << 295
		<< std::endl; return 295
		;
}

int PEM_write_bio_SSL_SESSION() {
	procLog << 296
		<< std::endl; return 296
		;
}

int SSL_get_psk_identity_hint() {
	procLog << 297
		<< std::endl; return 297
		;
}

int SSL_set_psk_server_callback() {
	procLog << 298
		<< std::endl; return 298
		;
}

int SSL_use_psk_identity_hint() {
	procLog << 299
		<< std::endl; return 299
		;
}

int SSL_set_psk_client_callback() {
	procLog << 300
		<< std::endl; return 300
		;
}

int PEM_read_SSL_SESSION() {
	procLog << 301
		<< std::endl; return 301
		;
}

int PEM_read_bio_SSL_SESSION() {
	procLog << 302
		<< std::endl; return 302
		;
}

int SSL_CTX_set_psk_server_callback() {
	procLog << 303
		<< std::endl; return 303
		;
}

int SSL_get_psk_identity() {
	procLog << 304
		<< std::endl; return 304
		;
}

int PEM_write_SSL_SESSION() {
	procLog << 305
		<< std::endl; return 305
		;
}

int SSL_set_session_ticket_ext() {
	procLog << 306
		<< std::endl; return 306
		;
}

int SSL_set_session_secret_cb() {
	procLog << 307
		<< std::endl; return 307
		;
}

int SSL_set_session_ticket_ext_cb() {
	procLog << 308
		<< std::endl; return 308
		;
}

int SSL_set1_param() {
	procLog << 309
		<< std::endl; return 309
		;
}

int SSL_CTX_set1_param() {
	procLog << 310
		<< std::endl; return 310
		;
}

int SSL_renegotiate_abbreviated() {
	procLog << 312
		<< std::endl; return 312
		;
}

int TLSv1_1_method() {
	procLog << 313
		<< std::endl; return 313
		;
}

int TLSv1_1_client_method() {
	procLog << 314
		<< std::endl; return 314
		;
}

int TLSv1_1_server_method() {
	procLog << 315
		<< std::endl; return 315
		;
}

int SSL_CTX_set_srp_client_pwd_callback() {
	procLog << 316
		<< std::endl; return 316
		;
}

int SSL_get_srp_g() {
	procLog << 317
		<< std::endl; return 317
		;
}

int SSL_CTX_set_srp_username_callback() {
	procLog << 318
		<< std::endl; return 318
		;
}

int SSL_get_srp_userinfo() {
	procLog << 319
		<< std::endl; return 319
		;
}

int SSL_set_srp_server_param() {
	procLog << 320
		<< std::endl; return 320
		;
}

int SSL_set_srp_server_param_pw() {
	procLog << 321
		<< std::endl; return 321
		;
}

int SSL_get_srp_N() {
	procLog << 322
		<< std::endl; return 322
		;
}

int SSL_get_srp_username() {
	procLog << 323
		<< std::endl; return 323
		;
}

int SSL_CTX_set_srp_password() {
	procLog << 324
		<< std::endl; return 324
		;
}

int SSL_CTX_set_srp_strength() {
	procLog << 325
		<< std::endl; return 325
		;
}

int SSL_CTX_set_srp_verify_param_callback() {
	procLog << 326
		<< std::endl; return 326
		;
}

int SSL_CTX_set_srp_cb_arg() {
	procLog << 328
		<< std::endl; return 328
		;
}

int SSL_CTX_set_srp_username() {
	procLog << 329
		<< std::endl; return 329
		;
}

int SSL_CTX_SRP_CTX_init() {
	procLog << 330
		<< std::endl; return 330
		;
}

int SSL_SRP_CTX_init() {
	procLog << 331
		<< std::endl; return 331
		;
}

int SRP_Calc_A_param() {
	procLog << 332
		<< std::endl; return 332
		;
}

int SRP_generate_server_master_secret() {
	procLog << 333
		<< std::endl; return 333
		;
}

int SSL_CTX_SRP_CTX_free() {
	procLog << 334
		<< std::endl; return 334
		;
}

int SRP_generate_client_master_secret() {
	procLog << 335
		<< std::endl; return 335
		;
}

int SSL_srp_server_param_with_username() {
	procLog << 336
		<< std::endl; return 336
		;
}

int SSL_SRP_CTX_free() {
	procLog << 338
		<< std::endl; return 338
		;
}

int SSL_set_debug() {
	procLog << 339
		<< std::endl; return 339
		;
}

int SSL_SESSION_get0_peer() {
	procLog << 340
		<< std::endl; return 340
		;
}

void* TLSv1_2_client_method() {
	void* tmp = pTLSv1_client_method_u();
#ifdef _DEBUGT
	procLog << "TLSv1_2_client_method" << std::endl;
#endif
	return tmp;
}

int SSL_SESSION_set1_id_context() {
	procLog << 342
		<< std::endl; return 342
		;
}

int TLSv1_2_server_method() {
	procLog << 343
		<< std::endl; return 343
		;
}

int SSL_cache_hit() {
	procLog << 344
		<< std::endl; return 344
		;
}

int SSL_set_state() {
	procLog << 348
		<< std::endl; return 348
		;
}

int SSL_CIPHER_get_id() {
	procLog << 349
		<< std::endl; return 349
		;
}

int TLSv1_2_method() {
	procLog << 350
		<< std::endl; return 350
		;
}

int SSL_export_keying_material() {
	procLog << 353
		<< std::endl; return 353
		;
}

int SSL_set_tlsext_use_srtp() {
	procLog << 354
		<< std::endl; return 354
		;
}

int SSL_CTX_set_next_protos_advertised_cb() {
	procLog << 355
		<< std::endl; return 355
		;
}

int SSL_get0_next_proto_negotiated() {
	procLog << 356
		<< std::endl; return 356
		;
}

int SSL_get_selected_srtp_profile() {
	procLog << 357
		<< std::endl; return 357
		;
}

int SSL_CTX_set_tlsext_use_srtp(void* ctx, char* profiles) {
	//int tmp = pSSL_CTX_set_tlsext_use_srtp_u(ctx, profiles);
	procLog << 358 << std::endl;
	return 358;
}

int SSL_select_next_proto() {
	procLog << 359
		<< std::endl; return 359
		;
}

int SSL_get_srtp_profiles() {
	procLog << 360
		<< std::endl; return 360
		;
}

int SSL_CTX_set_next_proto_select_cb() {
	procLog << 361
		<< std::endl; return 361
		;
}

int SSL_SESSION_get_compress_id() {
	procLog << 362
		<< std::endl; return 362
		;
}

int SSL_get0_param() {
	procLog << 363
		<< std::endl; return 363
		;
}

int SSL_CTX_get0_privatekey() {
	procLog << 364
		<< std::endl; return 364
		;
}

int SSL_get_shared_sigalgs() {
	procLog << 365
		<< std::endl; return 365
		;
}

int SSL_CONF_CTX_finish() {
	procLog << 366
		<< std::endl; return 366
		;
}

int DTLS_method() {
	procLog << 367
		<< std::endl; return 367
		;
}

int DTLS_client_method() {
	procLog << 368
		<< std::endl; return 368
		;
}

int SSL_set_alpn_protos() {
	procLog << 370
		<< std::endl; return 370
		;
}

int SSL_CONF_cmd_argv() {
	procLog << 372
		<< std::endl; return 372
		;
}

int DTLSv1_2_server_method() {
	procLog << 373
		<< std::endl; return 373
		;
}

int SSL_COMP_set0_compression_methods() {
	procLog << 374
		<< std::endl; return 374
		;
}

int SSL_CTX_set_cert_cb() {
	procLog << 375
		<< std::endl; return 375
		;
}

int SSL_CTX_add_client_custom_ext() {
	procLog << 376
		<< std::endl; return 376
		;
}

int SSL_is_server() {
	procLog << 377
		<< std::endl; return 377
		;
}

int SSL_CTX_get0_param() {
	procLog << 378
		<< std::endl; return 378
		;
}

int SSL_CONF_cmd() {
	procLog << 379
		<< std::endl; return 379
		;
}

int SSL_CTX_get_ssl_method() {
	procLog << 380
		<< std::endl; return 380
		;
}

int SSL_CONF_CTX_set_ssl_ctx() {
	procLog << 381
		<< std::endl; return 381
		;
}

void* SSL_CIPHER_find() {
	procLog << 382
		<< std::endl; return (void*)382
		;
}

int SSL_CTX_use_serverinfo() {
	procLog << 383
		<< std::endl; return 383
		;
}

int DTLSv1_2_client_method() {
	procLog << 384
		<< std::endl; return 384
		;
}

int SSL_get0_alpn_selected() {
	procLog << 385
		<< std::endl; return 385
		;
}

int SSL_CONF_CTX_clear_flags() {
	procLog << 386
		<< std::endl; return 386
		;
}

int SSL_CTX_set_alpn_protos() {
	procLog << 387
		<< std::endl; return 387
		;
}

int SSL_CTX_add_server_custom_ext() {
	procLog << 389
		<< std::endl; return 389
		;
}

int SSL_CTX_get0_certificate() {
	procLog << 390
		<< std::endl; return 390
		;
}

int SSL_CTX_set_alpn_select_cb() {
	procLog << 391
		<< std::endl; return 391
		;
}

int SSL_CONF_cmd_value_type() {
	procLog << 392
		<< std::endl; return 392
		;
}

int SSL_set_cert_cb() {
	procLog << 393
		<< std::endl; return 393
		;
}

int SSL_get_sigalgs() {
	procLog << 394
		<< std::endl; return 394
		;
}

int SSL_CONF_CTX_set1_prefix() {
	procLog << 395
		<< std::endl; return 395
		;
}

int SSL_CONF_CTX_new() {
	procLog << 396
		<< std::endl; return 396
		;
}

int SSL_CONF_CTX_set_flags() {
	procLog << 397
		<< std::endl; return 397
		;
}

int SSL_CONF_CTX_set_ssl() {
	procLog << 398
		<< std::endl; return 398
		;
}

int SSL_check_chain() {
	procLog << 399
		<< std::endl; return 399
		;
}

int SSL_certs_clear() {
	procLog << 400
		<< std::endl; return 400
		;
}

int SSL_CONF_CTX_free() {
	procLog << 401
		<< std::endl; return 401
		;
}

int DTLSv1_2_method() {
	procLog << 404
		<< std::endl; return 404
		;
}

int DTLS_server_method() {
	procLog << 405
		<< std::endl; return 405
		;
}

int SSL_CTX_use_serverinfo_file() {
	procLog << 406
		<< std::endl; return 406
		;
}

int SSL_COMP_free_compression_methods() {
	procLog << 407
		<< std::endl; return 407
		;
}

int SSL_extension_supported() {
	procLog << 409
		<< std::endl; return 409
		;
}

