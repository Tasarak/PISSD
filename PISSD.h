#ifndef LIBPISSD_LIBRARY_H
#define LIBPISSD_LIBRARY_H

#include <string>

namespace PISSD
{
    class SecureDataStorage
    {
    public:
        int storeData(const std::string &dataKey, std::string &data);
        int storeData(const std::string &dataKey, double &data);
        int storeData(const std::string &dataKey, float &data);
        int storeData(const std::string &dataKey, int64_t &data);
        int storeData(const std::string &dataKey, bool &data);

        int retrieveData(const std::string &dataKey, std::string &data);
        int retrieveData(const std::string &dataKey, double &data);
        int retrieveData(const std::string &dataKey, float &data);
        int retrieveData(const std::string &dataKey, int64_t &data);
        int retrieveData(const std::string &dataKey, bool &data);

        void deleteStoredData(std::string &dataKey);
        void deleteAllData();
        void deleteAllDataFromModule(std::string &path);

        void createModule(const std::string &path, const std::string &name);
        void removeModule(const std::string &path);
        void storeDataToModule();
        void retrieveDataFromModule();
        void getAllKeys();
        void getKeysFromModule();
        void getAllModules();
        void getAllSubmodules();
        bool contains(const std::string &dataKey);

    };
}
#endif