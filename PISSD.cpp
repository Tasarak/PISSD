#include <iostream>
#include <iomanip>
#include <fstream>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>

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

#include "PISSD.h"


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

std::string stripExtension(std::string fileName)
{
    fileName.erase(0, 1);
    fileName.erase(fileName.end()-4, fileName.end());
    return fileName;
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
        mkpath_np(configPath.c_str(), 0700);
    }

    if (stat(documentsPath.c_str(), &st) == -1)
    {
        mkpath_np(documentsPath.c_str(), 0700);
    }

    if (stat(libraryPath.c_str(), &st) == -1)
    {
        mkpath_np(libraryPath.c_str(), 0700);
    }
#endif
}

void addModuleToPath(std::string module, std::string paths[])
{
    if (module.find('/') != 0)
    {
        module = '/' + module;
    }

    if (module.back() == '/')
    {
        module.erase(module.size());
    }
    for (int i = 0; i < 3; i++)
    {
        paths[i] += module;
    }
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

void createFile(std::string module, std::string fileName, std::string data)
{
    std::string pathNames[3];
    getDirPath(pathNames);
    addModuleToPath(module, pathNames);

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
    std::string dirPath[3];
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

int loadFile(std::string module, std::string data[], std::string fileName)
{
    std::string dirPath[3];
    int emptyFileCounter = 0;

    getDirPath(dirPath);
    addModuleToPath(module, dirPath);

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

void initializeKeyAndIV(const std::string &dataKey, CryptoPP::byte key[], CryptoPP::byte iv[])
{
    CryptoPP::SecByteBlock derived(64);
    std::string password = getUsername() + getUUID() + dataKey;
    unsigned int iterations = 1000;

    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> kdf;
    kdf.DeriveKey(derived.data(), derived.size(), 0,
                  (CryptoPP::byte *) password.data(),
                  password.size(), nullptr, 0, iterations);

    memcpy(key, derived.data(), CryptoPP::AES::MAX_KEYLENGTH);
    memcpy(iv, derived.data() + CryptoPP::AES::MAX_KEYLENGTH, CryptoPP::AES::MAX_BLOCKSIZE);
}

std::string decrypthData(std::string dataKey, std::string cipherText)
{
    CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH], iv[CryptoPP::AES::MAX_BLOCKSIZE];

    std::string decryptedText;

    initializeKeyAndIV(dataKey, key, iv);

    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedText));
    stfDecryptor.Put(reinterpret_cast<const unsigned char *>( cipherText.c_str()), cipherText.size());
    stfDecryptor.MessageEnd();

    decryptedText.erase(decryptedText.end() - SALTSIZE - 1, decryptedText.end());

    return decryptedText;

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

void encryptData(std::string &plaintext, std::string &ciphertext, CryptoPP::byte key[], CryptoPP::byte iv[])
{
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
    stfEncryptor.Put(reinterpret_cast<const unsigned char *>( plaintext.c_str()), plaintext.length() + 1);
    stfEncryptor.MessageEnd();
}

void generateSalt(std::string &salt)
{
    CryptoPP::SecByteBlock saltGen(SALTSIZE);
    CryptoPP::OS_GenerateRandomBlock(true, saltGen, saltGen.size());

    std::string saltString((char *) saltGen.data(), saltGen.size());
    salt = saltString;
}

void createPath(std::string &pathToDir, const std::string &module, const std::string &name)
{
    if (module.front() == '/')
    {
        pathToDir += module;
    } else
    {
        pathToDir += "/" + module;
    }

    if (module.back() == '/')
    {
        pathToDir += name;
    } else
    {
        pathToDir += "/" + name;
    }
}

namespace PISSD
{
    SecureDataStorage::SecureDataStorage(std::mutex * mMutex)
    {
        lgMutex = mMutex;
    }

    int SecureDataStorage::storeData(const std::string &dataKey, std::string &data)
    {
        CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH], iv[CryptoPP::AES::MAX_KEYLENGTH];

        CryptoPP::SecByteBlock derived(64);

        std::string saltString;
        generateSalt(saltString);

        std::string plaintext = "str" + data;
        std::string ciphertext;

        plaintext += SHA512HashString(plaintext) + saltString;

        initializeKeyAndIV(dataKey, key, iv);

        encryptData(plaintext, ciphertext, key, iv);
        std::lock_guard<std::mutex> lock(*lgMutex);

        createFile(dataKey.c_str(), ciphertext);

        return 0;
    }

    int SecureDataStorage::storeData(const std::string &dataKey, double &data)
    {
        CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH], iv[CryptoPP::AES::MAX_KEYLENGTH];

        CryptoPP::SecByteBlock derived(64);

        std::string saltString;
        generateSalt(saltString);

        std::string plaintext = "dbl" + std::to_string(data);
        std::string ciphertext;

        plaintext += SHA512HashString(plaintext) + saltString;

        initializeKeyAndIV(dataKey, key, iv);

        encryptData(plaintext, ciphertext, key, iv);

        std::lock_guard<std::mutex> lock(*lgMutex);

        createFile(dataKey.c_str(), ciphertext);

        return 0;
    }

    int SecureDataStorage::storeData(const std::string &dataKey, float &data)
    {
        CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH], iv[CryptoPP::AES::MAX_KEYLENGTH];

        CryptoPP::SecByteBlock derived(64);

        std::string saltString;
        generateSalt(saltString);

        std::string plaintext = "flt" + std::to_string(data);
        std::string ciphertext;

        plaintext += SHA512HashString(plaintext) + saltString;

        initializeKeyAndIV(dataKey, key, iv);

        encryptData(plaintext, ciphertext, key, iv);

        std::lock_guard<std::mutex> lock(*lgMutex);

        createFile(dataKey.c_str(), ciphertext);

        return 0;
    }

    int SecureDataStorage::storeData(const std::string &dataKey, int64_t &data)
    {
        CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH], iv[CryptoPP::AES::MAX_KEYLENGTH];

        CryptoPP::SecByteBlock derived(64);

        std::string saltString;
        generateSalt(saltString);

        std::string plaintext = "int" + std::to_string(data);
        std::string ciphertext;

        plaintext += SHA512HashString(plaintext) + saltString;

        initializeKeyAndIV(dataKey, key, iv);

        encryptData(plaintext, ciphertext, key, iv);

        std::lock_guard<std::mutex> lock(*lgMutex);

        createFile(dataKey.c_str(), ciphertext);

        return 0;
    }

    int SecureDataStorage::storeData(const std::string &dataKey, bool &data)
    {
        CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH], iv[CryptoPP::AES::MAX_KEYLENGTH];

        CryptoPP::SecByteBlock derived(64);

        std::string saltString;
        generateSalt(saltString);

        std::string plaintext = "bol";
        if (data)
        {
            plaintext += "true";
        } else
        {
            plaintext += "false";
        }
        std::string ciphertext;

        plaintext += SHA512HashString(plaintext) + saltString;

        initializeKeyAndIV(dataKey, key, iv);

        encryptData(plaintext, ciphertext, key, iv);

        std::lock_guard<std::mutex> lock(*lgMutex);

        createFile(dataKey.c_str(), ciphertext);

        return 0;
    }


    int SecureDataStorage::retrieveData(const std::string &dataKey, std::string &data)
    {
        std::string dataToRead[3];
        std::string temp[3];
        std::vector<std::string> possibleData;

        std::lock_guard<std::mutex> lock(*lgMutex);

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
                        if (temp[i].substr(0, 3) == "str")
                        {
                            temp[i].erase(0, 3);
                            possibleData.push_back(temp[i]);
                        }
                    }
                }
            } else
            {

            }
        } else if (loadedFileCheck < 3)
        {
            std::string temp;
            for (int i = 0; i < loadedFileCheck; ++i)
            {
                temp = decrypthData(dataKey, dataToRead[i]);
                if (checkHash(temp) == 0)
                {
                    temp.erase(temp.end() - 90, temp.end());
                    if (temp.substr(0, 3) == "str")
                    {
                        temp.erase(0, 3);
                        possibleData.push_back(temp);
                    }
                }
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

    int SecureDataStorage::retrieveData(const std::string &dataKey, double &data)
    {
        std::string dataToRead[3];
        std::string temp[3];
        std::vector<std::string> possibleData;

        std::lock_guard<std::mutex> lock(*lgMutex);

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
                        if (temp[i].substr(0, 3) == "dbl")
                        {
                            temp[i].erase(0, 3);
                            possibleData.push_back(temp[i]);
                        }
                    }
                }
            } else
            {

            }
        } else if (loadedFileCheck < 3)
        {
            std::string temp;
            for (int i = 0; i < loadedFileCheck; ++i)
            {
                temp = decrypthData(dataKey, dataToRead[i]);
                if (checkHash(temp) == 0)
                {
                    temp.erase(temp.end() - 90, temp.end());
                    if (temp.substr(0, 3) == "dbl")
                    {
                        temp.erase(0, 3);
                        possibleData.push_back(temp);
                    }
                }
            }
        }

        if (loadedFileCheck == 3 || possibleData.empty())
        {
            std::cerr << "No file found\n";
            return -1;
        }

        data = std::stod(findSameStrings(possibleData));

        return 0;
    }

    int SecureDataStorage::retrieveData(const std::string &dataKey, float &data)
    {
        std::string dataToRead[3];
        std::string temp[3];
        std::vector<std::string> possibleData;

        std::lock_guard<std::mutex> lock(*lgMutex);

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
                        if (temp[i].substr(0, 3) == "flt")
                        {
                            temp[i].erase(0, 3);
                            possibleData.push_back(temp[i]);
                        }
                    }
                }
            } else
            {

            }
        } else if (loadedFileCheck < 3)
        {
            std::string temp;
            for (int i = 0; i < loadedFileCheck; ++i)
            {
                temp = decrypthData(dataKey, dataToRead[i]);
                if (checkHash(temp) == 0)
                {
                    temp.erase(temp.end() - 90, temp.end());
                    if (temp.substr(0, 3) == "flt")
                    {
                        temp.erase(0, 3);
                        possibleData.push_back(temp);
                    }
                }
            }
        }

        if (loadedFileCheck == 3 || possibleData.empty())
        {
            std::cerr << "No file found\n";
            return -1;
        }

        data = std::stof(findSameStrings(possibleData));

        return 0;
    }

    int SecureDataStorage::retrieveData(const std::string &dataKey, int64_t &data)
    {
        std::string dataToRead[3];
        std::string temp[3];
        std::vector<std::string> possibleData;

        std::lock_guard<std::mutex> lock(*lgMutex);

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
                        if (temp[i].substr(0, 3) == "int")
                        {
                            temp[i].erase(0, 3);
                            possibleData.push_back(temp[i]);
                        }
                    }
                }
            } else
            {

            }
        } else if (loadedFileCheck < 3)
        {
            std::string temp;
            for (int i = 0; i < loadedFileCheck; ++i)
            {
                temp = decrypthData(dataKey, dataToRead[i]);
                if (checkHash(temp) == 0)
                {
                    temp.erase(temp.end() - 90, temp.end());
                    if (temp.substr(0, 3) == "int")
                    {
                        temp.erase(0, 3);
                        possibleData.push_back(temp);
                    }
                }
            }
        }

        if (loadedFileCheck == 3 || possibleData.empty())
        {
            std::cerr << "No file found\n";
            return -1;
        }

        data = std::stoll(findSameStrings(possibleData));

        return 0;
    }

    int SecureDataStorage::retrieveData(const std::string &dataKey, bool &data)
    {
        std::string dataToRead[3];
        std::string temp[3];
        std::vector<std::string> possibleData;

        std::lock_guard<std::mutex> lock(*lgMutex);

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
                        if (temp[i].substr(0, 3) == "bol")
                        {
                            temp[i].erase(0, 3);
                            possibleData.push_back(temp[i]);
                        }
                    }
                }
            } else
            {

            }
        } else if (loadedFileCheck < 3)
        {
            std::string temp;
            for (int i = 0; i < loadedFileCheck; ++i)
            {
                temp = decrypthData(dataKey, dataToRead[i]);
                if (checkHash(temp) == 0)
                {
                    temp.erase(temp.end() - 90, temp.end());
                    if (temp.substr(0, 3) == "bol")
                    {
                        temp.erase(0, 3);
                        possibleData.push_back(temp);
                    }
                }
            }
        }

        if (loadedFileCheck == 3 || possibleData.empty())
        {
            std::cerr << "No file found\n";
            return -1;
        }

        if (findSameStrings(possibleData) == "true")
        {
            data = true;
        } else if (findSameStrings(possibleData) == "false")
        {
            data = false;
        } else
        {
            return 1;
        }

        return 0;
    }

    void SecureDataStorage::deleteStoredData(std::string &dataKey)
    {
        std::string pathsToFile[3];

        std::lock_guard<std::mutex> lock(*lgMutex);
        getDirPath(pathsToFile);
        for (auto &path : pathsToFile)
        {
            path += "/." + dataKey + ".jkl";
#ifdef WIN32
            DeleteFile(path.c_str());
#endif
#ifdef __APPLE__
            std::remove(path.c_str());
#endif
        }
    }

    void SecureDataStorage::deleteAllData()
    {
        boost::filesystem::path boostPath;
        std::string dirPath[3];

        std::lock_guard<std::mutex> lock(*lgMutex);
        getDirPath(dirPath);
        for (int i = 0; i < 3; ++i)
        {
            boostPath = dirPath[i] + "/";
            boost::filesystem::remove_all(boostPath);
        }
    }

    int SecureDataStorage::createModule(const std::string &path, const std::string &name)
    {
        std::string dirPath[3];
        struct stat st = {0};

        std::lock_guard<std::mutex> lock(*lgMutex);
        getDirPath(dirPath);
        if (path == "*" || path.empty())
        {
            for (int i = 0; i < 3; ++i)
            {
                dirPath[i] += "/" + name;
#ifdef __APPLE__
                if (stat(dirPath[i].c_str(), &st) == -1)
                {
                    mkdir(dirPath[i].c_str() ,0700);
                }
#endif
            }
        } else
        {
            for (int i = 0; i < 3; ++i)
            {
                createPath(dirPath[i], path, name);

#ifdef __APPLE__
                if (stat(dirPath[i].c_str(), &st) == -1)
                {
                    mkpath_np(dirPath[i].c_str() ,0700);
                }
#endif
            }
        }

        return 0;
    }

    int SecureDataStorage::removeModule(const std::string &path)
    {
        boost::filesystem::path boostPath;
        std::string dirPath[3];

        std::lock_guard<std::mutex> lock(*lgMutex);
        getDirPath(dirPath);
        for (int i = 0; i < 3; ++i)
        {
            boostPath = dirPath[i] + "/" + path;
            boost::filesystem::remove_all(boostPath);
        }
        return 0;
    }

    void SecureDataStorage::deleteAllDataFromModule(std::string &path)
    {
        boost::filesystem::path boostPath;
        std::string dirPath[3];

        std::lock_guard<std::mutex> lock(*lgMutex);
        getDirPath(dirPath);
        for (int i = 0; i < 3; ++i)
        {
            boostPath = dirPath[i] + "/" + path;
            boost::filesystem::remove(boostPath);
        }
    }

    void SecureDataStorage::getAllKeys(std::vector<std::string> &paths, std::vector<std::string> &keys)
    {
        std::string dirPath[3];
        getDirPath(dirPath);

        std::lock_guard<std::mutex> lock(*lgMutex);
        std::vector<std::string> lPaths[3], lKeys[3];
        for (int i = 0; i < 3; ++i)
        {
            boost::filesystem::path targetDir = dirPath[i];
            boost::filesystem::recursive_directory_iterator it( targetDir ), eod;


            BOOST_FOREACH(boost::filesystem::path const &p, std::make_pair(it, eod))
                        {
                            if(is_regular_file(p))
                            {
                                if (p.filename().string() != ".DS_Store")
                                {
                                    std::string filepath = p.branch_path().string();
                                    filepath.erase(0, dirPath[i].size());
                                    lPaths[i].push_back(filepath);
                                    lKeys[i].push_back(stripExtension(p.filename().string()));
                                }
                            }
                        }
        }

        int max = 0;
        for (int i = 0; i < 3; ++i)
        {
            for (int j = i; j < 3; ++j)
            {
                if (lPaths[i].size() == lPaths[j].size())
                {
                    paths = lPaths[i];
                    keys = lKeys[i];
                    return;
                } else if (lPaths[i].size() > lPaths[j].size())
                {
                    max = i;
                } else
                {
                    max = j;
                }
            }
        }
        paths = lPaths[max];
        keys = lKeys[max];
    }

    void SecureDataStorage::getAllModules(std::vector<std::string> &modules)
    {
        std::string dirPath[3];
        getDirPath(dirPath);

        std::lock_guard<std::mutex> lock(*lgMutex);
        for (int i = 0; i < 3; ++i)
        {
            boost::filesystem::path targetDir = dirPath[i];
            boost::filesystem::recursive_directory_iterator it( targetDir ), eod;

            BOOST_FOREACH(boost::filesystem::path const &p, std::make_pair(it, eod))
                        {
                            if(is_directory(p))
                            {
                                std::string modulePath = p.generic_path().string();
                                modulePath.erase(0, dirPath[i].size() + 1);
                                modules.push_back(modulePath);
                            }
                        }
        }
    }

    void SecureDataStorage::getAllSubmodules(std::string path, std::vector<std::string> &modules)
    {
        std::string dirPath[3];
        getDirPath(dirPath);

        std::lock_guard<std::mutex> lock(*lgMutex);
        for (int i = 0; i < 3; ++i)
        {
            boost::filesystem::path targetDir = dirPath[i];
            boost::filesystem::recursive_directory_iterator it( targetDir ), eod;

            BOOST_FOREACH(boost::filesystem::path const &p, std::make_pair(it, eod))
                        {
                            if(is_directory(p))
                            {
                                std::string modulePath = p.generic_path().string();
                                modulePath.erase(0, dirPath[i].size() + 1);
                                if (modulePath.find(path) != std::string::npos)
                                {
                                    modules.push_back(modulePath);
                                }
                            }
                        }
        }
    }

    bool SecureDataStorage::contains(const std::string &dataKey)
    {
        std::vector<std::string> paths, keys;

        std::lock_guard<std::mutex> lock(*lgMutex);
        getAllKeys(paths, keys);
        for (auto key : keys)
        {
            if (key == dataKey)
            {
                return true;
            }
        }
        return false;
    }

    void SecureDataStorage::getAllKeysFromModule(std::string module,
                                                 std::vector<std::string> &paths,
                                                 std::vector<std::string> &keys)
    {
        std::string dirPath[3];
        getDirPath(dirPath);

        std::lock_guard<std::mutex> lock(*lgMutex);
        std::vector<std::string> lPaths[3], lKeys[3];
        for (int i = 0; i < 3; ++i)
        {
            boost::filesystem::path targetDir = dirPath[i];
            boost::filesystem::recursive_directory_iterator it( targetDir ), eod;


            BOOST_FOREACH(boost::filesystem::path const &p, std::make_pair(it, eod))
                        {
                            if(is_regular_file(p))
                            {
                                if (p.filename().string() != ".DS_Store")
                                {
                                    std::string filepath = p.branch_path().string();
                                    filepath.erase(0, dirPath[i].size());
                                    if (filepath.find(module) != std::string::npos)
                                    {
                                        lPaths[i].push_back(filepath);
                                        lKeys[i].push_back(stripExtension(p.filename().string()));
                                    }
                                }
                            }
                        }
        }

        int max = 0;
        for (int i = 0; i < 3; ++i)
        {
            for (int j = i; j < 3; ++j)
            {
                if (lPaths[i].size() == lPaths[j].size())
                {
                    paths = lPaths[i];
                    keys = lKeys[i];
                    return;
                } else if (lPaths[i].size() > lPaths[j].size())
                {
                    max = i;
                } else
                {
                    max = j;
                }
            }
        }
        paths = lPaths[max];
        keys = lKeys[max];
    }

    void SecureDataStorage::getDirectKeysFromModule(std::string module,
                                                    std::vector<std::string> &paths,
                                                    std::vector<std::string> &keys)
    {
        std::string dirPath[3];
        getDirPath(dirPath);
        std::vector<std::string> lPaths[3], lKeys[3];

        std::lock_guard<std::mutex> lock(*lgMutex);

        for (int i = 0; i < 3; ++i)
        {
            boost::filesystem::path targetDir = dirPath[i];
            boost::filesystem::recursive_directory_iterator it( targetDir ), eod;


            BOOST_FOREACH(boost::filesystem::path const &p, std::make_pair(it, eod))
                        {
                            if(is_regular_file(p))
                            {
                                if (p.filename().string() != ".DS_Store")
                                {
                                    std::string filepath = p.branch_path().string();
                                    filepath.erase(0, dirPath[i].size());
                                    if (std::equal(module.rbegin(), module.rend(), filepath.rbegin()))
                                    {
                                        lPaths[i].push_back(filepath);
                                        lKeys[i].push_back(stripExtension(p.filename().string()));
                                    }
                                }
                            }
                        }
        }

        int max = 0;
        for (int i = 0; i < 3; ++i)
        {
            for (int j = i; j < 3; ++j)
            {
                if (lPaths[i].size() == lPaths[j].size())
                {
                    paths = lPaths[i];
                    keys = lKeys[i];
                    return;
                } else if (lPaths[i].size() > lPaths[j].size())
                {
                    max = i;
                } else
                {
                    max = j;
                }
            }
        }
        paths = lPaths[max];
        keys = lKeys[max];
    }

    int SecureDataStorage::storeDataToModule(std::string module, const std::string &dataKey, std::string &data)
    {
        CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH], iv[CryptoPP::AES::MAX_KEYLENGTH];
        CryptoPP::SecByteBlock derived(64);
        std::string saltString;
        std::string ciphertext;

        std::lock_guard<std::mutex> lock(*lgMutex);
        generateSalt(saltString);

        std::string plaintext = "str" + data;

        plaintext += SHA512HashString(plaintext) + saltString;

        initializeKeyAndIV(dataKey, key, iv);

        encryptData(plaintext, ciphertext, key, iv);

        createFile(module, dataKey.c_str(), ciphertext);

        return 0;
    }

    int SecureDataStorage::storeDataToModule(std::string module, const std::string &dataKey, double &data)
    {
        CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH], iv[CryptoPP::AES::MAX_KEYLENGTH];
        CryptoPP::SecByteBlock derived(64);
        std::string saltString;
        std::string ciphertext;

        std::lock_guard<std::mutex> lock(*lgMutex);

        generateSalt(saltString);

        std::string plaintext = "dbl" + std::to_string(data);

        plaintext += SHA512HashString(plaintext) + saltString;

        initializeKeyAndIV(dataKey, key, iv);

        encryptData(plaintext, ciphertext, key, iv);

        createFile(module, dataKey.c_str(), ciphertext);

        return 0;
    }

    int SecureDataStorage::storeDataToModule(std::string module, const std::string &dataKey, float &data)
    {
        CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH], iv[CryptoPP::AES::MAX_KEYLENGTH];
        CryptoPP::SecByteBlock derived(64);
        std::string saltString;
        std::string ciphertext;

        std::lock_guard<std::mutex> lock(*lgMutex);
        generateSalt(saltString);

        std::string plaintext = "flt" + std::to_string(data);

        plaintext += SHA512HashString(plaintext) + saltString;

        initializeKeyAndIV(dataKey, key, iv);

        encryptData(plaintext, ciphertext, key, iv);

        createFile(module, dataKey.c_str(), ciphertext);

        return 0;
    }

    int SecureDataStorage::storeDataToModule(std::string module, const std::string &dataKey, int64_t &data)
    {
        CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH], iv[CryptoPP::AES::MAX_KEYLENGTH];
        CryptoPP::SecByteBlock derived(64);
        std::string saltString;
        std::string ciphertext;

        std::lock_guard<std::mutex> lock(*lgMutex);
        generateSalt(saltString);

        std::string plaintext = "int" + std::to_string(data);

        plaintext += SHA512HashString(plaintext) + saltString;

        initializeKeyAndIV(dataKey, key, iv);

        encryptData(plaintext, ciphertext, key, iv);

        createFile(module, dataKey.c_str(), ciphertext);

        return 0;
    }

    int SecureDataStorage::storeDataToModule(std::string module, const std::string &dataKey, bool &data)
    {
        CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH], iv[CryptoPP::AES::MAX_KEYLENGTH];
        CryptoPP::SecByteBlock derived(64);
        std::string saltString;
        std::string ciphertext;

        std::lock_guard<std::mutex> lock(*lgMutex);
        generateSalt(saltString);

        std::string plaintext = "bol";
        if (data)
        {
            plaintext += "true";
        } else
        {
            plaintext += "false";
        }

        plaintext += SHA512HashString(plaintext) + saltString;

        initializeKeyAndIV(dataKey, key, iv);

        encryptData(plaintext, ciphertext, key, iv);

        createFile(module, dataKey.c_str(), ciphertext);

        return 0;
    }

    int SecureDataStorage::retrieveDataFromModule(std::string module, const std::string &dataKey, std::string &data)
    {
        std::string dataToRead[3];
        std::vector<std::string> possibleData;

        std::lock_guard<std::mutex> lock(*lgMutex);

        int loadedFileCheck = loadFile(module, dataToRead, dataKey);
        if (loadedFileCheck == 0)
        {
            if (compareCiphertext(dataToRead) > 1)
            {
                std::string temp[3];
                for (int i = 0; i < 3; ++i)
                {
                    temp[i] = decrypthData(dataKey, dataToRead[i]);
                    if (checkHash(temp[i]) == 0)
                    {
                        temp[i].erase(temp[i].end() - 90, temp[i].end());
                        if (temp[i].substr(0, 3) == "str")
                        {
                            temp[i].erase(0, 3);
                            possibleData.push_back(temp[i]);
                        }
                    }
                }
            } else
            {

            }
        } else if (loadedFileCheck < 3)
        {
            std::string temp;
            for (int i = 0; i < loadedFileCheck; ++i)
            {
                temp = decrypthData(dataKey, dataToRead[i]);
                if (checkHash(temp) == 0)
                {
                    temp.erase(temp.end() - 90, temp.end());
                    if (temp.substr(0, 3) == "str")
                    {
                        temp.erase(0, 3);
                        possibleData.push_back(temp);
                    }
                }
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

    int SecureDataStorage::retrieveDataFromModule(std::string module, const std::string &dataKey, double &data)
    {
        std::string dataToRead[3];
        std::vector<std::string> possibleData;

        std::lock_guard<std::mutex> lock(*lgMutex);

        int loadedFileCheck = loadFile(module, dataToRead, dataKey);
        if (loadedFileCheck == 0)
        {
            if (compareCiphertext(dataToRead) > 1)
            {
                std::string temp[3];
                for (int i = 0; i < 3; ++i)
                {
                    temp[i] = decrypthData(dataKey, dataToRead[i]);
                    if (checkHash(temp[i]) == 0)
                    {
                        temp[i].erase(temp[i].end() - 90, temp[i].end());
                        if (temp[i].substr(0, 3) == "dbl")
                        {
                            temp[i].erase(0, 3);
                            possibleData.push_back(temp[i]);
                        }
                    }
                }
            } else
            {

            }
        } else if (loadedFileCheck < 3)
        {
            std::string temp;
            for (int i = 0; i < loadedFileCheck; ++i)
            {
                temp = decrypthData(dataKey, dataToRead[i]);
                if (checkHash(temp) == 0)
                {
                    temp.erase(temp.end() - 90, temp.end());
                    if (temp.substr(0, 3) == "dbl")
                    {
                        temp.erase(0, 3);
                        possibleData.push_back(temp);
                    }
                }
            }
        }

        if (loadedFileCheck == 3 || possibleData.empty())
        {
            std::cerr << "No file found\n";
            return -1;
        }

        data = std::stod(findSameStrings(possibleData));
        return 0;
    }

    int SecureDataStorage::retrieveDataFromModule(std::string module, const std::string &dataKey, float &data)
    {
        std::string dataToRead[3];
        std::vector<std::string> possibleData;

        std::lock_guard<std::mutex> lock(*lgMutex);

        int loadedFileCheck = loadFile(module, dataToRead, dataKey);
        if (loadedFileCheck == 0)
        {
            if (compareCiphertext(dataToRead) > 1)
            {
                std::string temp[3];
                for (int i = 0; i < 3; ++i)
                {
                    temp[i] = decrypthData(dataKey, dataToRead[i]);
                    if (checkHash(temp[i]) == 0)
                    {
                        temp[i].erase(temp[i].end() - 90, temp[i].end());
                        if (temp[i].substr(0, 3) == "flt")
                        {
                            temp[i].erase(0, 3);
                            possibleData.push_back(temp[i]);
                        }
                    }
                }
            } else
            {

            }
        } else if (loadedFileCheck < 3)
        {
            std::string temp;
            for (int i = 0; i < loadedFileCheck; ++i)
            {
                temp = decrypthData(dataKey, dataToRead[i]);
                if (checkHash(temp) == 0)
                {
                    temp.erase(temp.end() - 90, temp.end());
                    if (temp.substr(0, 3) == "flt")
                    {
                        temp.erase(0, 3);
                        possibleData.push_back(temp);
                    }
                }
            }
        }

        if (loadedFileCheck == 3 || possibleData.empty())
        {
            std::cerr << "No file found\n";
            return -1;
        }

        data = std::stof(findSameStrings(possibleData));
        return 0;
    }

    int SecureDataStorage::retrieveDataFromModule(std::string module, const std::string &dataKey, int64_t &data)
    {
        std::string dataToRead[3];
        std::vector<std::string> possibleData;

        std::lock_guard<std::mutex> lock(*lgMutex);

        int loadedFileCheck = loadFile(module, dataToRead, dataKey);
        if (loadedFileCheck == 0)
        {
            if (compareCiphertext(dataToRead) > 1)
            {
                std::string temp[3];
                for (int i = 0; i < 3; ++i)
                {
                    temp[i] = decrypthData(dataKey, dataToRead[i]);
                    if (checkHash(temp[i]) == 0)
                    {
                        temp[i].erase(temp[i].end() - 90, temp[i].end());
                        if (temp[i].substr(0, 3) == "int")
                        {
                            temp[i].erase(0, 3);
                            possibleData.push_back(temp[i]);
                        }
                    }
                }
            } else
            {

            }
        } else if (loadedFileCheck < 3)
        {
            std::string temp;
            for (int i = 0; i < loadedFileCheck; ++i)
            {
                temp = decrypthData(dataKey, dataToRead[i]);
                if (checkHash(temp) == 0)
                {
                    temp.erase(temp.end() - 90, temp.end());
                    if (temp.substr(0, 3) == "int")
                    {
                        temp.erase(0, 3);
                        possibleData.push_back(temp);
                    }
                }
            }
        }

        if (loadedFileCheck == 3 || possibleData.empty())
        {
            std::cerr << "No file found\n";
            return -1;
        }

        data = std::stoll(findSameStrings(possibleData));
        return 0;
    }

    int SecureDataStorage::retrieveDataFromModule(std::string module, const std::string &dataKey, bool &data)
    {
        std::string dataToRead[3];
        std::vector<std::string> possibleData;

        std::lock_guard<std::mutex> lock(*lgMutex);

        int loadedFileCheck = loadFile(module, dataToRead, dataKey);
        if (loadedFileCheck == 0)
        {
            if (compareCiphertext(dataToRead) > 1)
            {
                std::string temp[3];
                for (int i = 0; i < 3; ++i)
                {
                    temp[i] = decrypthData(dataKey, dataToRead[i]);
                    if (checkHash(temp[i]) == 0)
                    {
                        temp[i].erase(temp[i].end() - 90, temp[i].end());
                        if (temp[i].substr(0, 3) == "bol")
                        {
                            temp[i].erase(0, 3);
                            possibleData.push_back(temp[i]);
                        }
                    }
                }
            } else
            {

            }
        } else if (loadedFileCheck < 3)
        {
            std::string temp;
            for (int i = 0; i < loadedFileCheck; ++i)
            {
                temp = decrypthData(dataKey, dataToRead[i]);
                if (checkHash(temp) == 0)
                {
                    temp.erase(temp.end() - 90, temp.end());
                    if (temp.substr(0, 3) == "bol")
                    {
                        temp.erase(0, 3);
                        possibleData.push_back(temp);
                    }
                }
            }
        }

        if (loadedFileCheck == 3 || possibleData.empty())
        {
            std::cerr << "No file found\n";
            return -1;
        }

        if (findSameStrings(possibleData) == "true")
        {
            data = true;
        } else if (findSameStrings(possibleData) == "false")
        {
            data = false;
        } else
        {
            return 1;
        }

        return 0;
    }
}