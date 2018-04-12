#include <iostream>
#include <mutex>

#include "../PISSD.h"
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"

std::mutex mutex;

TEST_CASE("TEST1")
{
    PISSD::SecureDataStorage secureDataStorage(&mutex);

    std::string data;
    secureDataStorage.retrieveData("test1", data);
    REQUIRE(data == "Kuba je frajer");
}