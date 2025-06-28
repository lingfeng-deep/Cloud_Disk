#include "OssManager.h"

bool OssManager::upload_object(std::string& key, std::string& file)
{
    auto outcome = m_client.PutObject(m_bucket, key, file);
    return outcome.isSuccess(); 
}

bool OssManager::upload_object(std::string& key, std::shared_ptr<std::iostream> content)
{
    auto outcome = m_client.PutObject(m_bucket, key, content);
    return outcome.isSuccess();
}

