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


std::string SHA512HashString(std::string const aString)
{
    std::string digest;
    CryptoPP::SHA512 hash;

    CryptoPP::StringSource foo(aString, true,
                               new CryptoPP::HashFilter(hash,
                                                        new CryptoPP::Base64Encoder(new CryptoPP::StringSink(digest))));

    return digest;
}

std::string getUsername()
{
#ifdef WIN32
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    GetUserName(username, &username_len);
    return username;
#endif
#ifdef __APPLE__
    return getlogin();
#endif
}

void getDirPath(std::string pathNames[])
{
#ifdef WIN32
    TCHAR szPath[MAX_PATH];

    if (SUCCEEDED(SHGetFolderPath(NULL,
                                  CSIDL_APPDATA | CSIDL_FLAG_CREATE,
                                  NULL,
                                  0,
                                  szPath)))
    {
        std::string path = szPath;
        path += "/PISSD";
        pathNames[0] = path;
        CreateDirectory(path.c_str(), NULL);
        SetFileAttributes(path.c_str(), FILE_ATTRIBUTE_HIDDEN);
    }

    if (SUCCEEDED(SHGetFolderPath(NULL,
                                  CSIDL_LOCAL_APPDATA | CSIDL_FLAG_CREATE,
                                  NULL,
                                  0,
                                  szPath)))
    {
        std::string path = szPath;
        path += "/PISSD";
        pathNames[1] = path;
        CreateDirectory(path.c_str(), NULL);
        SetFileAttributes(path.c_str(), FILE_ATTRIBUTE_HIDDEN);
    }

    if (SUCCEEDED(SHGetFolderPath(NULL,
                                  CSIDL_PERSONAL | CSIDL_FLAG_CREATE,
                                  NULL,
                                  0,
                                  szPath)))
    {
        std::string path = szPath;
        path += "/PISSD";
        pathNames[2] = path;
        CreateDirectory(path.c_str(), NULL);
        SetFileAttributes(path.c_str(), FILE_ATTRIBUTE_HIDDEN);
    }
#endif
#ifdef __APPLE__
    struct stat st = {0};

    std::string homePath = getenv("HOME");

    std::string configPath = homePath + "/.config/.PISSD";
    pathNames[0] = configPath;

    std::string documentsPath = homePath + "/Documents/.PISSD";
    pathNames[1] = documentsPath;

    std::string libraryPath = homePath + "/Library/.PISSD";
    pathNames[2] = libraryPath;


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

void createFile(std::string fileName, std::string data)
{
    std::string pathNames[3];
    getDirPath(pathNames);

    for (int i = 0; i < 3; ++i)
    {
        pathNames[i].append("/." + fileName + ".jkl");
#ifdef WIN32
        DeleteFile(pathNames[i].c_str());
#endif
        std::ofstream outFile(pathNames[i], std::ios::out | std::ios::binary);
        outFile << data;
        outFile.close();
    }

#ifdef WIN32

    for (int i = 0; i < 3; ++i)
    {
        SetFileAttributes(pathNames[i].c_str(), FILE_ATTRIBUTE_HIDDEN);
    }

#endif
}


std::string getUUID()
{
#ifdef WIN32
    HW_PROFILE_INFO HwProfInfo;
    if (!GetCurrentHwProfile(&HwProfInfo))
    {
        _tprintf(TEXT("GetCurrentHwProfile failed with error %lx\n"),
                 GetLastError());
    } else
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

int compareCiphertext(std::string data[])
{
    int equalCounter = 0;

    for (int i = 0; i < 3; ++i)
    {
        for (int j = i; j < 3; ++j)
        {
            if (data[i] == data[j])
            {
                equalCounter++;
            }

            if (i == j)
            {
                equalCounter--;
            }
        }
    }

    return equalCounter;
}

int loadFile(std::string data[], std::string fileName)
{
    std::string dirPath[6];
    int emptyFileCounter = 0;

    getDirPath(dirPath);

    for (int i = 0; i < 3; ++i)
    {

        dirPath[i].append("/." + fileName + ".jkl");
        std::ifstream infile(dirPath[i], std::ifstream::binary);
        if (infile.is_open())
        {
            std::string str((std::istreambuf_iterator<char>(infile)),
                            std::istreambuf_iterator<char>());
            infile.close();

            data[i] = str;
        }

        if (data[i].empty())
        {
            emptyFileCounter++;
        }
    }

    if (emptyFileCounter == 3)
    {
        return 2;
    }

    if (emptyFileCounter == 2)
    {
        return 1;
    }

    return 0;
}

std::string decrypthData(std::string dataKey, std::string data)
{
    CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH], iv[CryptoPP::AES::MAX_BLOCKSIZE];

    std::string ciphertext = data;
    std::string decryptedtext;

    std::string password = getUsername() + getUUID() + dataKey;
    unsigned int iterations = 1000;

    CryptoPP::SecByteBlock derived(64);

    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> kdf;
    kdf.DeriveKey(derived.data(), derived.size(), 0, (CryptoPP::byte *) password.data(), password.size(), nullptr,
                  0, iterations);

    memcpy(key, derived.data(), CryptoPP::AES::MAX_KEYLENGTH);
    memcpy(iv, derived.data() + CryptoPP::AES::MAX_KEYLENGTH, CryptoPP::AES::MAX_BLOCKSIZE);

    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
    stfDecryptor.Put(reinterpret_cast<const unsigned char *>( ciphertext.c_str()), ciphertext.size());
    stfDecryptor.MessageEnd();

    decryptedtext.erase(decryptedtext.end() - SALTSIZE - 1, decryptedtext.end());

    return decryptedtext;

}

int checkHash(std::string data)
{
    if (data.size() < 90)
    {
        return 2;
    }
    std::string originalHash = data.substr(data.size() - 90);
    data.erase(data.end() - 90, data.end());
    std::string newHash = SHA512HashString(data);
    if (originalHash != newHash)
    {
        return 1;
    }

    return 0;
}

std::string findSameStrings(std::vector<std::string> possibleData)
{
    if (possibleData.size() == 1)
    {
        return possibleData.front();
    }
    for (int i = 0; i < possibleData.size(); ++i)
    {
        for (int j = i; j < possibleData.size(); ++j)
        {
            if (i != j && possibleData[i] == possibleData[j])
            {
                return possibleData[i];
            }
        }
    }

    return "";
}

namespace PISSD
{

    int SecureDataStorage::storeUserData(const std::string &dataKey, std::string &data)
    {
        CryptoPP::RandomPool prng;
        CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH], iv[CryptoPP::AES::MAX_BLOCKSIZE];

        CryptoPP::SecByteBlock salt(SALTSIZE), derived(64);
        CryptoPP::OS_GenerateRandomBlock(true, salt, salt.size());

        std::string saltString((char *) salt.data(), salt.size());

        std::string password = getUsername() + getUUID() + dataKey;
        unsigned int iterations = 1000;

        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> kdf;
        kdf.DeriveKey(derived.data(), derived.size(), 0, (CryptoPP::byte *) password.data(), password.size(), nullptr,
                      0, iterations);

        memcpy(key, derived.data(), CryptoPP::AES::MAX_KEYLENGTH);
        memcpy(iv, derived.data() + CryptoPP::AES::MAX_KEYLENGTH, CryptoPP::AES::MAX_BLOCKSIZE);


        std::string plaintext = data;
        std::string ciphertext;

        plaintext += saltString;

        CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::MAX_KEYLENGTH);
        CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

        CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
        stfEncryptor.Put(reinterpret_cast<const unsigned char *>( plaintext.c_str()), plaintext.length() + 1);
        stfEncryptor.MessageEnd();

        createFile(dataKey.c_str(), ciphertext);

        return 0;
    }


    int SecureDataStorage::retrieveUserData(const std::string &dataKey, std::string &data)
    {

        std::string dataToRead[3];
        std::string temp[3];
        std::string final[3];

        std::vector<std::string> possibleData;

        int loadedFileCheck = loadFile(dataToRead, dataKey);
        if (loadedFileCheck == 0)
        {
            if (compareCiphertext(dataToRead) > 1)
            {
                for (int i = 0; i < 3; ++i)
                {
                    temp[i] = decrypthData(dataKey, dataToRead[i]);
                    if (checkHash(temp[i]) == 0)
                    {
                        temp[i].erase(temp[i].end() - 90, temp[i].end());
                        possibleData.push_back(temp[i]);
                    }
                }
            } else
            {

            }
        }

        if (loadedFileCheck == 3 || possibleData.empty())
        {
            std::cerr << "No file found\n";
            data = "";
            return -1;
        }

        data = findSameStrings(possibleData);

        return 0;
    }

    void SecureDataStorage::deleteStoredData(std::string &key)
    {
        std::string pathsToFile[3];

        getDirPath(pathsToFile);
        for (auto &path : pathsToFile)
        {
            path += "/." + key + ".jkl";
#ifdef WIN32
            DeleteFile(path.c_str());
#endif
#ifdef __APPLE__
            std::remove(path.c_str());
#endif
        }
    }
}