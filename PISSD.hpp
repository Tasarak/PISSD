/**
*  @file    PISSD.hpp
*  @author  Jakub Klemens
*  @date    14/05/2018
*  @version 1.0
*/

#ifndef LIBPISSD_LIBRARY_H
#define LIBPISSD_LIBRARY_H

namespace PISSD
{
    class SecureDataStorage
    {
    private:
        std::mutex * lgMutex;
    public:

        /// Create instance of SecureDataStorage
        explicit SecureDataStorage(std::mutex *mMutex);
        /// Store data
        int storeData(const std::string &dataKey, std::string &data);
        int storeData(const std::string &dataKey, double &data);
        int storeData(const std::string &dataKey, float &data);
        int storeData(const std::string &dataKey, int64_t &data);
        int storeData(const std::string &dataKey, bool &data);

        /// Get stored data back
        int retrieveData(const std::string &dataKey, std::string &data);
        int retrieveData(const std::string &dataKey, double &data);
        int retrieveData(const std::string &dataKey, float &data);
        int retrieveData(const std::string &dataKey, int64_t &data);
        int retrieveData(const std::string &dataKey, bool &data);

        /// Store data to module
        int storeDataToModule(std::string module, const std::string &dataKey, std::string &data);
        int storeDataToModule(std::string module, const std::string &dataKey, double &data);
        int storeDataToModule(std::string module, const std::string &dataKey, float &data);
        int storeDataToModule(std::string module, const std::string &dataKey, int64_t &data);
        int storeDataToModule(std::string module, const std::string &dataKey, bool &data);

        /// Get stored data back from module
        int retrieveDataFromModule(std::string module, const std::string &dataKey, std::string &data);
        int retrieveDataFromModule(std::string module, const std::string &dataKey, double &data);
        int retrieveDataFromModule(std::string module, const std::string &dataKey, float &data);
        int retrieveDataFromModule(std::string module, const std::string &dataKey, int64_t &data);
        int retrieveDataFromModule(std::string module, const std::string &dataKey, bool &data);

        /// Delete a single pack of data by key
        void deleteStoredData(std::string &dataKey);

        /// Delete everything created by this library
        void deleteAllData();

        /// Delete everything in one module
        void deleteAllDataFromModule(std::string &path);

        /// Create module
        int createModule(const std::string &path, const std::string &name);

        /// Remove module and everything in it
        int removeModule(const std::string &path);

        /// Return vector of all available keys
        void getAllKeys(std::vector<std::string> &paths, std::vector<std::string> &keys);

        /// Return vector of all available keys in particular module and its submodules
        void getAllKeysFromModule(std::string module,
                                  std::vector<std::string> &paths,
                                  std::vector<std::string> &keys);

        /// Return vector of all available keys in particular module
        void getDirectKeysFromModule(std::string module,
                                     std::vector<std::string> &paths,
                                     std::vector<std::string> &keys);

        /// Return vector of all available modules
        void getAllModules(std::vector<std::string> &modules);

        /// Return vector of submodules in particular path
        void getAllSubmodules(std::string path, std::vector<std::string> &modules);

        /// Return true if demanded key exists
        bool contains(const std::string &dataKey);
    };
}
#endif