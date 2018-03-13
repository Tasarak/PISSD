#include "PISSD.h"

#include <iostream>
#include <iomanip>
#include <fstream>

#ifdef WIN32
#include <windows.h>
#include <Lmcons.h>
#include <tchar.h>
#include <Shlobj.h>
#include <functional>
#include <algorithm>
#endif

#ifdef __APPLE__
#include <unistd.h>
#include <uuid/uuid.h>
#include <sys/stat.h>

#endif

#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/hex.h>
#include <cryptopp/eax.h>

#define SALTSIZE 32

std::string SHA512HashString (std::string const aString)
{
    std::string digest;
    CryptoPP::SHA512 hash;

    CryptoPP::StringSource foo(aString, true,
                               new CryptoPP::HashFilter(hash,
                                                        new CryptoPP::Base64Encoder (new CryptoPP::StringSink(digest))));

    return digest;
}

std::string getUsername ()
{
#ifdef WIN32
    char username[UNLEN+1];
    DWORD username_len = UNLEN+1;
    GetUserName(username, &username_len);
    std::cout << username << std::endl;
    return username;
#endif
#ifdef __APPLE__
    return getlogin();
#endif
}

void createDir(std::string pathNames[])
{
#ifdef WIN32
    TCHAR szPath[MAX_PATH];

    if(SUCCEEDED(SHGetFolderPath(NULL,
                                 CSIDL_APPDATA|CSIDL_FLAG_CREATE,
                                 NULL,
                                 0,
                                 szPath)))
    {
        std::cout << szPath << std::endl;
        std::string path = szPath;
        path += "/PISSD";
        CreateDirectory(path.c_str(), NULL);
    }
#endif
#ifdef __APPLE__
    struct stat st = {0};

    std::string homePath = getenv("HOME");

    std::string configPath = homePath + "/.config/.PISSD";
    pathNames[3] = configPath;

    std::string documentsPath = homePath + "/Documents/.PISSD";
    pathNames[4] = documentsPath;

    std::string libraryPath = homePath + "/Library/.PISSD";
    pathNames[5] = libraryPath;


    if (stat(configPath.c_str(), &st) == -1)
    {
        mkdir(configPath.c_str(), 0700);
    }

    if (stat(documentsPath.c_str(), &st) == -1)
    {
        mkdir(documentsPath.c_str(), 0700);
    }

    if (stat(libraryPath.c_str(), &st) == -1)
    {
        mkdir(libraryPath.c_str(), 0700);
    }
#endif
}

void createFile()
{
    std::string pathNames[6];
    createDir(pathNames);
#ifdef __APPLE__
    for (int i = 3; i < 6; ++i)
    {
        std::ofstream outFile (pathNames[i] + "/test.jkl");
        outFile.close();
    }
#endif
}

std::string getUUID ()
{
#ifdef WIN32
    HW_PROFILE_INFO   HwProfInfo;
    if (!GetCurrentHwProfile(&HwProfInfo))
    {
        _tprintf(TEXT("GetCurrentHwProfile failed with error %lx\n"),
                 GetLastError());
    }
    else
    {
        return HwProfInfo.szHwProfileGuid;
    }
#endif

#ifdef __APPLE__
    struct timespec ts = { .tv_sec = 5, .tv_nsec = 0 };
    uuid_t uuid = {};

    if (gethostuuid(uuid, &ts) == -1) {
        switch (errno) {
            case EFAULT:
                fputs("Failed to get system UUID: unknown error", stderr);
                return NULL;
            case EWOULDBLOCK:
                fputs("Failed to get system UUID: timeout expired", stderr);
                return NULL;
        }
    }

    uuid_string_t uuid_string;
    uuid_unparse_upper(uuid, uuid_string);

    return uuid_string;
#endif

    return NULL;
}

int storeUserData(std::string *dataKey, std::string *data)
{
    //Key and IV setup
    //AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-
    //bit). MAX_KEYLENGTH = 32
    CryptoPP::HexEncoder hexEncoder;
    CryptoPP::RandomPool prng;
    CryptoPP::byte key[ CryptoPP::AES::MAX_KEYLENGTH ], iv[ CryptoPP::AES::MAX_BLOCKSIZE ];

    CryptoPP::SecByteBlock salt(SALTSIZE), derived(64);
    CryptoPP::OS_GenerateRandomBlock(true, salt, salt.size());

    std::string saltString((char*)salt.data(), salt.size());

    std::string password = getUsername() + getUUID();
    unsigned int iterations = 1000;

    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> kdf;
    kdf.DeriveKey(derived.data(), derived.size(), 0, (CryptoPP::byte*)password.data(), password.size(), nullptr, 0, iterations);
    std::string keyString, ivString;

    memcpy(key, derived.data(), CryptoPP::AES::MAX_KEYLENGTH);
    memcpy(iv, derived.data() + CryptoPP::AES::MAX_KEYLENGTH, CryptoPP::AES::MAX_BLOCKSIZE);


    std::string plaintext = "Now is the time for all good men to come to the aide...";
    std::string ciphertext;

    plaintext += saltString;

    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plaintext.c_str() ), plaintext.length() + 1 );
    stfEncryptor.MessageEnd();
    return 0;
}


int retrieveUserData(std::string *dataKey, std::string *data)
{
    CryptoPP::byte key[ CryptoPP::AES::MAX_KEYLENGTH ], iv[ CryptoPP::AES::MAX_BLOCKSIZE ];

    std::string ciphertext;
    std::string decryptedtext;

    std::string password = getUsername() + getUUID();
    unsigned int iterations = 1000;

    CryptoPP::SecByteBlock derived(64);

    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> kdf;
    kdf.DeriveKey(derived.data(), derived.size(), 0, (CryptoPP::byte*)password.data(), password.size(), nullptr, 0, iterations);
    std::string keyString, ivString;

    memcpy(key, derived.data(), CryptoPP::AES::MAX_KEYLENGTH);
    memcpy(iv, derived.data() + CryptoPP::AES::MAX_KEYLENGTH, CryptoPP::AES::MAX_BLOCKSIZE);

    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv);

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedtext ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( ciphertext.c_str() ), ciphertext.size() );
    stfDecryptor.MessageEnd();

    decryptedtext.erase(decryptedtext.end() - SALTSIZE-1, decryptedtext.end());

    //system("pause");
    return 0;
}