#ifndef LIBPISSD_LIBRARY_H
#define LIBPISSD_LIBRARY_H

#include <string>

int storeUserData(std::string *key, std::string *data);
int retrieveUserData(std::string *key, std::string *data);

#endif