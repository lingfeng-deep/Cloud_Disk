#include <iostream>
#include <string>
#include <SimpleAmqpClient/SimpleAmqpClient.h>
#include <nlohmann/json.hpp>
#include "OssManager.h"

int main()
{
    using std::string;
    using namespace AmqpClient;

    string uri = "amqp://guest:guest@localhost:5672/%2f";
    const std::string& q = "oss.queue";

    Channel::ptr_t channel = Channel::CreateFromUri(uri);

    // 告诉channel，从队列q中获取消息
    channel->BasicConsume(q);

    for(;;) {
        using Json = nlohmann::json;            
        // 获取一封消息
        // 如果队列中没有消息，则一直等待
        Envelope::ptr_t envelope = channel->BasicConsumeMessage();

        if (envelope && envelope->Message()) {
            Json message = Json::parse(envelope->Message()->Body());
            string object = message["object"].get<string>();
            string file = message["file"].get<string>();
#ifdef DEBUG
            std::cout << "object: " << object
                << ", file: " << file << "\n";
#endif
            OssManager oss{};
            oss.upload_object(object, file);
        }
    }

}

