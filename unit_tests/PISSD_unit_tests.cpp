/**
*  @file    PISSD_unit_tests.cpp
*  @author  Jakub Klemens
*  @date    14/05/2018
*  @version 1.0
*/
#include <iostream>
#include <algorithm>
#include <vector>
#include <mutex>
#include <sys/stat.h>
#include <unistd.h>

#ifdef WIN32
#include <Shlobj.h>
#include <Shlwapi.h>
#endif

#include "../PISSD.hpp"
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"

std::mutex mutex;

void getPath(std::string &path)
{
#ifdef WIN32
    TCHAR szPath[MAX_PATH];

    if (SUCCEEDED(SHGetFolderPath(NULL,
                                  CSIDL_APPDATA | CSIDL_FLAG_CREATE,
                                  NULL,
                                  0,
                                  szPath)))
    {
        path = szPath;
        path += "/PISSD";
    }
#endif
#ifdef __APPLE__
    std::string homePath = getenv("HOME");
    path = homePath + "/.config/.PISSD";
#endif
}


bool fileExists(std::string dataKey)
{
    std::string path;
    getPath(path);
    path += "/." + dataKey + ".jkl";

    struct stat info;
    return (stat (path.c_str(), &info) == 0);
}

bool folderExists(std::string module)
{
    std::string path;
    getPath(path);
    path += "/" + module;

    if( !path.empty() )
    {
        if( access(path.c_str(), 0) == 0 )
        {
            struct stat status;
            stat( path.c_str(), &status );
            if( status.st_mode & S_IFDIR )
                return true;
        }
    }
    // if any condition fails
    return false;
}


bool folderWithFileExists(std::string dataKey, std::string modulePath) {
    std::string path;
    getPath(path);
    path += "/" + modulePath + "/." + dataKey + ".jkl";

    struct stat info;
    return (stat(path.c_str(), &info) == 0);
}


TEST_CASE("Store and Retrieve String")
{
    PISSD::SecureDataStorage secureDataStorage(&mutex);

    std::string data = "Unit test";
    std::string dataKey = "Test";
    REQUIRE(secureDataStorage.storeData(dataKey, data) == 0);
    REQUIRE(fileExists(dataKey));
    REQUIRE(secureDataStorage.retrieveData(dataKey, data) == 0);
    REQUIRE(data == "Unit test");
}

TEST_CASE("Store and Retrieve Double")
{
    PISSD::SecureDataStorage secureDataStorage(&mutex);

    double data = 5.5;
    std::string dataKey = "Test";
    REQUIRE(secureDataStorage.storeData(dataKey, data) == 0);
    REQUIRE(fileExists(dataKey));
    REQUIRE(secureDataStorage.retrieveData(dataKey, data) == 0);
    REQUIRE(data == 5.5);
}

TEST_CASE("Store and Retrieve Float")
{
    PISSD::SecureDataStorage secureDataStorage(&mutex);

    float data = 5.5;
    std::string dataKey = "Test";
    REQUIRE(secureDataStorage.storeData(dataKey, data) == 0);
    REQUIRE(fileExists(dataKey));
    REQUIRE(secureDataStorage.retrieveData(dataKey, data) == 0);
    REQUIRE(data == 5.5);
}

TEST_CASE("Store and Retrieve Int64")
{
    PISSD::SecureDataStorage secureDataStorage(&mutex);

    int64_t data = 42;
    std::string dataKey = "Test";
    REQUIRE(secureDataStorage.storeData(dataKey, data) == 0);
    REQUIRE(fileExists(dataKey));
    REQUIRE(secureDataStorage.retrieveData(dataKey, data) == 0);
    REQUIRE(data == 42);
}

TEST_CASE("Store and Retrieve Bool")
{
    PISSD::SecureDataStorage secureDataStorage(&mutex);

    bool dataTrue = true;
    bool dataFalse = false;
    std::string dataKey = "Test";

    SECTION("Bool False")
    {
        REQUIRE(secureDataStorage.storeData(dataKey, dataFalse) == 0);
        REQUIRE(fileExists(dataKey));
        dataFalse = true;
        REQUIRE(secureDataStorage.retrieveData(dataKey, dataFalse) == 0);
        REQUIRE(!dataFalse);
    }

    SECTION("Bool True")
    {
        REQUIRE(secureDataStorage.storeData(dataKey, dataTrue) == 0);
        REQUIRE(fileExists(dataKey));
        dataTrue = false;
        REQUIRE(secureDataStorage.retrieveData(dataKey, dataTrue) == 0);
        REQUIRE(dataTrue);
    }
}

TEST_CASE("Delete Stored Data")
{
    PISSD::SecureDataStorage secureDataStorage(&mutex);

    std::string dataKey = "Test";
    if (fileExists(dataKey))
    {
        secureDataStorage.deleteStoredData(dataKey);
        REQUIRE_FALSE(fileExists(dataKey));
    }
}

TEST_CASE("Create and Remove Module")
{
    PISSD::SecureDataStorage secureDataStorage(&mutex);

    std::string module = "Lorem";
    std::string nestedModule = "Ipsum";
    std::string modulePath = module + "/" + nestedModule;

    SECTION("Creating a folder")
    {
        REQUIRE(secureDataStorage.createModule("*", module) == 0);
        REQUIRE(folderExists(module));
        REQUIRE(secureDataStorage.createModule(module, nestedModule) == 0);
        REQUIRE(folderExists(modulePath));
    }

    SECTION("Removing Folder")
    {
        REQUIRE(secureDataStorage.removeModule(modulePath) == 0);
        REQUIRE_FALSE(folderExists(modulePath));
        REQUIRE(folderExists(module));
        REQUIRE(secureDataStorage.removeModule(module) == 0);
        REQUIRE_FALSE(folderExists(module));
    }
}

TEST_CASE("Store/Retrieve Data to/from Module")
{
    PISSD::SecureDataStorage secureDataStorage(&mutex);
    std::string module = "Lorem";
    secureDataStorage.createModule("*", module);
    std::string dataKey = "TEST";

    SECTION("STRING")
    {
        std::string data = "TEST1";
        std::string outputData = "";
        REQUIRE(secureDataStorage.storeDataToModule(module, dataKey, data) == 0);
        REQUIRE(folderExists(module));
        REQUIRE(folderWithFileExists(dataKey, module));
        REQUIRE(secureDataStorage.retrieveDataFromModule(module, dataKey, outputData) == 0);
        REQUIRE(data == outputData);
    }

    SECTION("DOUBLE")
    {
        double data = 42.3;
        double outputData = 0;
        REQUIRE(secureDataStorage.storeDataToModule(module, dataKey, data) == 0);
        REQUIRE(folderExists(module));
        REQUIRE(folderWithFileExists(dataKey, module));
        REQUIRE(secureDataStorage.retrieveDataFromModule(module, dataKey, outputData) == 0);
        REQUIRE(data == outputData);
    }

    SECTION("FLOAT")
    {
        float data = 42.3;
        float outputData = 0;
        REQUIRE(secureDataStorage.storeDataToModule(module, dataKey, data) == 0);
        REQUIRE(folderExists(module));
        REQUIRE(folderWithFileExists(dataKey, module));
        REQUIRE(secureDataStorage.retrieveDataFromModule(module, dataKey, outputData) == 0);
        REQUIRE(data == outputData);
    }

    SECTION("INT")
    {
        int64_t data = 42;
        int64_t outputData = 0;
        REQUIRE(secureDataStorage.storeDataToModule(module, dataKey, data) == 0);
        REQUIRE(folderExists(module));
        REQUIRE(folderWithFileExists(dataKey, module));
        REQUIRE(secureDataStorage.retrieveDataFromModule(module, dataKey, outputData) == 0);
        REQUIRE(data == outputData);
    }

    SECTION("BOOL")
    {
        bool data = true;
        bool outputData = false;
        REQUIRE(secureDataStorage.storeDataToModule(module, dataKey, data) == 0);
        REQUIRE(folderExists(module));
        REQUIRE(folderWithFileExists(dataKey, module));
        REQUIRE(secureDataStorage.retrieveDataFromModule(module, dataKey, outputData) == 0);
        REQUIRE(data == outputData);
    }

    secureDataStorage.removeModule(module);
}

TEST_CASE("Get Keys")
{
    PISSD::SecureDataStorage secureDataStorage(&mutex);

    std::vector<std::string> dataKeys;
    std::vector<std::string> modules;
    std::string data = "Lorem ipsum";

    for (int i = 0; i < 20; ++i)
    {
        dataKeys.push_back("Key" + std::to_string(i));
        modules.push_back("Module" + std::to_string(i));

        secureDataStorage.createModule("*", modules.back());
        secureDataStorage.storeDataToModule(modules.back(), dataKeys.back(), data);
    }

    SECTION("All modules")
    {
        std::vector<std::string> outputModules;
        secureDataStorage.getAllModules(outputModules);
        std::sort(modules.begin(), modules.end());

        REQUIRE(modules == outputModules);
    }

    SECTION("All Keys")
    {
        std::vector<std::string> outputPaths;
        std::vector<std::string> outputKeys;
        secureDataStorage.getAllKeys(outputPaths, outputKeys);

        REQUIRE(outputKeys.size() == outputPaths.size());
        REQUIRE(outputKeys.size() == 20);
    }

    SECTION("All Keys from Module")
    {
        std::vector<std::string> outputPaths;
        std::vector<std::string> outputKeys;

        secureDataStorage.getAllKeysFromModule("Module1", outputPaths, outputKeys);
        REQUIRE(outputKeys.size() == outputPaths.size());
        REQUIRE(outputKeys.size() == 1);
        REQUIRE(outputKeys.front() == "Key1");
    }

    SECTION("All Direct Keys from Module")
    {
        secureDataStorage.createModule("Module1", "Module1_1");
        secureDataStorage.storeDataToModule("Module1/Module1_1", "NotBeCount", data);
        std::vector<std::string> outputPaths;
        std::vector<std::string> outputKeys;

        secureDataStorage.getDirectKeysFromModule("Module1", outputPaths, outputKeys);
        REQUIRE(outputKeys.size() == outputPaths.size());
        REQUIRE(outputKeys.size() == 1);
        REQUIRE(outputKeys.front() == "Key1");
        secureDataStorage.removeModule("Module1/Module1_1");
    }
}

TEST_CASE("Delete All Data")
{
    PISSD::SecureDataStorage secureDataStorage(&mutex);

    secureDataStorage.deleteAllData();
    REQUIRE_FALSE(folderExists(""));
}