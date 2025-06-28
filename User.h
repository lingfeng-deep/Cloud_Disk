#pragma once

#include <string>
namespace CloudDisk {

struct User 
{
    int id;
    std::string username;
    std::string hashcode;
    std::string salt;
    std::string createdAt;
};

}
