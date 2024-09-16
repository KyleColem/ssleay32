#include <iostream>
#include <windows.h>
typedef int(*dEVP_MD_CTX_cleanup)(int a1);

int __cdecl main()
{
    char* buff;
    buff = (char*)calloc(1024, 1);
    std::cout << "Hello World!\n";
    HMODULE hLink = LoadLibraryW(L"libeay.dll");
    std::cout << hLink<<std::endl;

    dEVP_MD_CTX_cleanup func19;
    func19 = (dEVP_MD_CTX_cleanup)GetProcAddress(hLink, "EVP_MD_CTX_cleanup");
    int t=1;
    std::cout<<func19(*buff);
    
    free(buff);

}

