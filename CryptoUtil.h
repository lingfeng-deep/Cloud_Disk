#pragma once
#include <string>
#include "User.h"

class CryptoUtil
{
public:
    static std::string generate_salt(int length = 8);
    static std::string hash_password(const std::string& password, const std::string& salt);
    static std::string generate_hashcode(const char* data, size_t n);
    static std::string generate_token(const CloudDisk::User& user);
    static bool verify_token(const std::string& token, CloudDisk::User& user);
private:
    /* 禁止构造对象 */
    CryptoUtil() = delete;
};
