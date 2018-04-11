#ifndef LIBPISSD_LIBRARY_H
#define LIBPISSD_LIBRARY_H

#include <string>
#include <mutex>
namespace PISSD
{
    class SecureDataStorage
    {
    private:
        std::mutex * lgMutex;
    public:
        SecureDataStorage(std::mutex *mMutex);
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

        int storeDataToModule(std::string module, const std::string &dataKey, std::string &data);
        int storeDataToModule(std::string module, const std::string &dataKey, double &data);
        int storeDataToModule(std::string module, const std::string &dataKey, float &data);
        int storeDataToModule(std::string module, const std::string &dataKey, int64_t &data);
        int storeDataToModule(std::string module, const std::string &dataKey, bool &data);

        int retrieveDataFromModule(std::string module, const std::string &dataKey, std::string &data);
        int retrieveDataFromModule(std::string module, const std::string &dataKey, double &data);
        int retrieveDataFromModule(std::string module, const std::string &dataKey, float &data);
        int retrieveDataFromModule(std::string module, const std::string &dataKey, int64_t &data);
        int retrieveDataFromModule(std::string module, const std::string &dataKey, bool &data);

        void deleteStoredData(std::string &dataKey);
        void deleteAllData();
        void deleteAllDataFromModule(std::string &path);

        int createModule(const std::string &path, const std::string &name);
        int removeModule(const std::string &path);

        void getAllKeys(std::vector<std::string> &paths, std::vector<std::string> &keys);
        void getAllKeysFromModule(std::string module,
                                  std::vector<std::string> &paths,
                                  std::vector<std::string> &keys);
        void getDirectKeysFromModule(std::string module,
                                     std::vector<std::string> &paths,
                                     std::vector<std::string> &keys);
        void getAllModules(std::vector<std::string> &modules);
        void getAllSubmodules(std::string path, std::vector<std::string> &modules);
        bool contains(const std::string &dataKey);

    };
}
#endif