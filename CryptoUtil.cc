#include "CryptoUtil.h"
#include "User.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <jwt.h>
#include <random>
#include <string.h>

/* static 全局变量: 其它编译单元引用不了这个变量 */
static std::mt19937 rng { std::random_device{}() };
static const char* SECRET_KEY = "$Rv&O98@";

std::string CryptoUtil::generate_salt(int length)
{
    const char* alpha = "0123456789"
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::uniform_int_distribution<int> dist{ 0, 61 };   /* alpha的长度为62 */

    std::string result {};
    for (int i = 0; i < length; ++i) {
        result += alpha[dist(rng)];
    }

    return result;
}

// OpenSSL 3.0 及更新版本推荐使用 EVP(Envelope) 接口
std::string CryptoUtil::hash_password(const std::string& password, const std::string& salt)
{
    EVP_MD_CTX* context = EVP_MD_CTX_new(); // 创建 EVP 上下文

    // 初始化上下文，采用 sha256 哈希算法
    EVP_DigestInit_ex(context, EVP_sha256(), NULL);
    // 更新上下文
    EVP_DigestUpdate(context, salt.c_str(), salt.size());
    EVP_DigestUpdate(context, password.c_str(), password.size());
    // 计算哈希值
    unsigned char hash[EVP_MAX_MD_SIZE];    // 最大哈希长度
    unsigned int len = 0;                   // 用来接收实际哈希长度
    EVP_DigestFinal(context, hash, &len);

    // 转换成十六进制字符，存储到result中
    char result[EVP_MAX_MD_SIZE * 2 + 1] = { '\0' };
    for(unsigned i = 0; i < len; i++) {
        sprintf(result + 2 * i, "%02x", hash[i]);
    }

    EVP_MD_CTX_free(context);               // 释放上下文

    return result;
}

std::string CryptoUtil::generate_token(const CloudDisk::User& user)
{
    jwt_t* jwt;
    jwt_new(&jwt);  // 创建 JWT

    // 设置算法为 HS256
    jwt_set_alg(jwt, JWT_ALG_HS256, (unsigned char*)SECRET_KEY, strlen(SECRET_KEY));

    // 设置载荷(Payload): 用户自定义数据
    jwt_add_grant(jwt, "sub", "LoginToken");
    jwt_add_grant_int(jwt, "id", user.id);
    jwt_add_grant(jwt, "username", user.username.c_str());	    // 用户ID
    jwt_add_grant(jwt, "created_at", user.createdAt.c_str());   // 注册时间
    jwt_add_grant_int(jwt, "exp", time(NULL) + 3600);   // 过期时间 (1小时)

    char* token = jwt_encode_str(jwt);		// token长度是不确定的，100-300字节
    std::string result { token };

    // 释放资源
    jwt_free(jwt);
    free(token);

    return result;
}

bool CryptoUtil::verify_token(const std::string& token, CloudDisk::User& user)
{
    jwt_t* jwt;
    int err = jwt_decode(&jwt, token.c_str(), (unsigned char*)SECRET_KEY, strlen(SECRET_KEY));
    if (err) {
        return false;
    }

    // 验证主题
    const char* subject = jwt_get_grant(jwt, "sub");    
    if (subject == nullptr || strcmp(subject, "LoginToken") != 0) {
        return false;
    }

    // 验证是否超时
    long expire = jwt_get_grant_int(jwt, "exp");
    if (expire < time(NULL)) {
        return false;
    }

    user.id = jwt_get_grant_int(jwt, "id");
    user.username = jwt_get_grant(jwt, "username");
    user.createdAt = jwt_get_grant(jwt, "created_at");

    jwt_free(jwt);
    return true;
}

std::string CryptoUtil::generate_hashcode(const char* data, size_t n)
{
    EVP_MD_CTX* context = EVP_MD_CTX_new();     // 创建 EVP 上下文
    // 初始化上下文, 采用 sha256 哈希算法
    EVP_DigestInit_ex(context, EVP_sha256(), NULL);

    EVP_DigestUpdate(context, data, n);

    // 计算哈希值
    unsigned char hash[EVP_MAX_MD_SIZE];    // 最大哈希长度
    unsigned int len = 0;                   // 用来接收实际哈希长度
    EVP_DigestFinal(context, hash, &len);   

    char result[EVP_MAX_MD_SIZE * 2 + 1] = { '\0' };
    // 转换成十六进制字符，存储到output中
    for (unsigned i = 0; i < len; i++) {
        sprintf(result + 2 * i, "%02x", hash[i]);
    }
    EVP_MD_CTX_free(context);               // 释放上下文

    return result;
}
