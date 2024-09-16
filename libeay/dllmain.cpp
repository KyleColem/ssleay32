#include <iostream>
#include <fstream>
#include "Header.h"
 unsigned char* buff;
 DWORD* tmpDword;
 void* v1, *v2, *v3;
 char* tmpChar;
HMODULE hLink;
std::ofstream logFile;

 
BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        logFile.open("layer.log", std::ios::out);
      //  hLink = LoadLibraryW(L"libcrypto-1_1.dll");
        //по идее тут загружать ничего не нужно, все грузится из другой длл
      //  if (hLink == 0) return 1;
      //  logFile << "load libcrypto-1_1.dll complete\n";
     //   if (!loadFunc()) return 2;
     //   logFile << "load function complete\n";
     //   buff = (unsigned char*)calloc(4096, 1);
     //   logFile << "allocate memory complete\n";
        
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
    {   
        if (hLink) { 
            FreeLibrary(hLink);
            logFile << "Unload libcrypto-1_1.dll complete\n";
        }
        if (!buff) free(buff);
        if(logFile.is_open()) logFile.close();
        break;
    }
    }
    return TRUE;
}

bool loadFunc() {
    func1 = (dPEM_read_bio_RSAPrivateKey)GetProcAddress(hLink, "PEM_read_bio_RSAPrivateKey");
    func2 = (dEVP_PKEY_assign)GetProcAddress(hLink, "EVP_PKEY_assign");
    func3 = (dEVP_SignFinal)GetProcAddress(hLink, "EVP_SignFinal");
    func4 = (dEVP_DigestUpdate)GetProcAddress(hLink, "EVP_DigestUpdate");
    func5 = (dEVP_DigestInit)GetProcAddress(hLink, "EVP_DigestInit");
    func6 = (dEVP_PKEY_size)GetProcAddress(hLink, "EVP_PKEY_size");
    func7 = (dEVP_PKEY_free)GetProcAddress(hLink, "EVP_PKEY_free");
    func8 = (dEVP_PKEY_new)GetProcAddress(hLink, "EVP_PKEY_new");
    func9 = (dEVP_sha1)GetProcAddress(hLink, "EVP_sha1");
    func10 = (dBIO_s_file)GetProcAddress(hLink, "BIO_s_file");
    func11 = (dBIO_ctrl)GetProcAddress(hLink, "BIO_ctrl");
    func12 = (dBIO_new)GetProcAddress(hLink, "BIO_new");
    func13 = (dERR_load_crypto_strings)GetProcAddress(hLink, "ERR_load_CRYPTO_strings");//в чём разница?
    func14 = (dERR_error_string)GetProcAddress(hLink, "ERR_error_string");
    func15 = (dERR_get_error)GetProcAddress(hLink, "ERR_get_error");
    //func16 = (dEVP_cleanup)GetProcAddress(hLink, "EVP_cleanup");
    //func17 = (dOpenSSL_add_all_digests)GetProcAddress(hLink, "OpenSSL_add_all_digests");
    //func18 = (dOpenSSL_add_all_ciphers)GetProcAddress(hLink, "OpenSSL_add_all_ciphers");
    func19 = (dEVP_MD_CTX_cleanup)GetProcAddress(hLink, "EVP_MD_CTX_reset");
    func20 = (dEVP_MD_CTX_init)GetProcAddress(hLink, "EVP_MD_CTX_reset");
    //return true;
    return func1 && func2 && func3 && func4 && func5 && func6 && func7 && func8 && func9 && func10 && func11 && func12 && func14 && func15;
}