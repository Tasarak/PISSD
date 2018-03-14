#ifndef LIBPISSD_LIBRARY_H
#define LIBPISSD_LIBRARY_H

#include <string>

namespace PISSD
{
    class SecureDataStorage
    {
    public:
        int storeUserData(const std::string &key, std::string &data);
        int retrieveUserData(const std::string &key, std::string &data);
        void deleteStoredData(std::string &key);
    };
}
#endif