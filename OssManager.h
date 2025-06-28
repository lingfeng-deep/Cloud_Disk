#pragma once
#include <alibabacloud/oss/OssClient.h>

class OssManager
{
public:
    OssManager()
    {
        m_client.SetRegion(m_region);
        AlibabaCloud::OSS::InitializeSdk();        
    }

    ~OssManager() 
    {
        AlibabaCloud::OSS::ShutdownSdk();
    }

    bool upload_object(std::string& key, std::string& file);
    bool upload_object(std::string& key, std::shared_ptr<std::iostream> content);
private:
    std::string m_endpoint = "oss-cn-wuhan-lr.aliyuncs.com";
    std::string m_region = "cn-wuhan";
    std::string m_accessKeyId = "LTAI5t7SqTtbX4UcwBGnWRuG";
    std::string m_accessKeySecret = "u32JnGRv5zgWf5y0nDZcOXlrlzzepv";
    std::string m_bucket = "peanutixx-cpp63";
    AlibabaCloud::OSS::ClientConfiguration m_conf {};
    AlibabaCloud::OSS::OssClient m_client { m_endpoint, m_accessKeyId, m_accessKeySecret, m_conf};
};

