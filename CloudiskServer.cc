#include <workflow/MySQLResult.h>
#include <workflow/WFTaskFactory.h>
#include <workflow/MySQLUtil.h>
#include <wfrest/PathUtil.h>
#include <vector>
#include <string>
#include <functional>
#include <sstream>
#include <memory>
#include <sys/stat.h>
#include <sys/types.h>

#include <nlohmann/json.hpp>
#include <SimpleAmqpClient/SimpleAmqpClient.h>
#include "CloudiskServer.h"
#include "CryptoUtil.h"
#include "UserService.srpc.h"
#include "UserService.pb.h"

using namespace std::placeholders;
using namespace wfrest;
using namespace protocol;
using std::string;
using std::cout;

static const std::string MYSQL_URL = "mysql://root:1234@localhost/cloudisk";
static const int RETRY_MAX = 3;

static const std::string RABBITMQ_URL = "amqp://guest:guest@localhost:5672/%2f";

void CloudiskServer::register_modules()
{
    // 设置静态资源的路由
    register_static_resources_module();
    register_signup_module();
    register_signin_module();
    register_userinfo_module();
    register_fileupload_module();
    register_filelist_module();
    register_filedownload_module();
}

void CloudiskServer::register_static_resources_module()
{
    m_server.GET("/user/signup", [](const HttpReq *, HttpResp * resp){
        resp->File("static/view/signup.html");
    });

    m_server.GET("/static/view/signin.html", [](const HttpReq *, HttpResp * resp){
        resp->File("static/view/signin.html");
    });

    m_server.GET("/static/view/home.html", [](const HttpReq *, HttpResp * resp){
        resp->File("static/view/home.html");
    });

    m_server.GET("/static/js/auth.js", [](const HttpReq *, HttpResp * resp){
        resp->File("static/js/auth.js");
    });

    m_server.GET("/static/img/avatar.jpeg", [](const HttpReq *, HttpResp * resp){
        resp->File("static/img/avatar.jpeg");
    });

    m_server.GET("/file/upload", [](const HttpReq *, HttpResp * resp){
        resp->File("static/view/index.html");
    });

    m_server.Static("/file/upload_files","static/view/upload_files");
}

/*********************************************************************************
 *                               注册                                            *
 *********************************************************************************/

void CloudiskServer::register_signup_module()
{
    m_server.POST("/user/signup", [](const HttpReq* req, HttpResp* resp)
    {
        if (req->content_type() != APPLICATION_URLENCODED) {
            resp->set_status(HttpStatusBadRequest);  
            resp->String("<html>400 Bad Request</html>");
            return ;
        }        
        // 1. 解析表单数据(application/x-www-form-urlencoded)，获取用户名和密码
        std::map<string, string>& form_kv = req->form_kv();
        string& username = form_kv["username"]; 
        string& password = form_kv["password"];
#ifdef DEBUG
        cout << "[INFO] username: " << username << ", password: " << password << "\n"; /* 调试信息 */
#endif
        // 2. 校验用户名和密码(用户名是否在黑名单内，密码是否符合强度要求...)
        // 这些校验可能前端也会做 (提升用户体验)
        // 但是后端永远不要相信前端传过来的数据 (因为很容易绕过前端，直接给后端发发送请求，比如用 curl)
        if (username == "" || password == "") {
            resp->set_status(HttpStatusBadRequest);
            resp->String("<html>400 Bad Request</html>");
            return ;
        }
        // 3. 访问Consul获取服务的Address和Port
        // Consul: http://localhost:8500/v1/agent/service/{serviceId}
        string ip;
        unsigned short port = 0;
        WFFacilities::WaitGroup waitGroup { 1 };
        string consulURL = "http://localhost:8500/v1/health/service/UserService?passing=true";
        WFHttpTask* consulTask = WFTaskFactory::create_http_task(consulURL, 3, 3, [&](WFHttpTask* task)
        {
            if (task->get_state() != WFT_STATE_SUCCESS) {
                waitGroup.done();
                return ;
            }
            // 获取请求体
            const void* body = nullptr;
            size_t size = 0;
            task->get_resp()->get_parsed_body(&body, &size);
            using Json = nlohmann::json;
            Json data = Json::parse(string{(const char*)body, size});
            // assert(data.is_array() && data.size() > 0);
            if (data.size() == 0) {
                return ;
            }
            ip = data[0]["Service"]["Address"].get<string>();
            port = data[0]["Service"]["Port"].get<int>();
            waitGroup.done();
        });
        consulTask->start();
        waitGroup.wait();

        if (ip == "") {
            resp->set_status(HttpStatusInternalServerError);
            resp->String("<html>500 Internal Server Error</html>");
            return ;
        }
        // 4. 远程同步调用UserService的sign_up方法
        User::SRPCClient client{ ip.c_str(), port };
        // 设置请求
        UserRequest request;
        request.set_username(username);
        request.set_password(password);
        // 同步调用
        UserResponse response;
        srpc::RPCSyncContext ctx;
        client.sign_up(&request, &response, &ctx);

        // 5. 返回响应
        if (ctx.success && response.success()) {
            resp->String("SUCCESS");
        } else {
            resp->set_status(HttpStatusBadRequest);
            resp->String("<html>用户名已存在</html>");
        }
    });
}


/*********************************************************************************
 *                               登录                                            *
 *********************************************************************************/
void CloudiskServer::register_signin_module()
{
    // 精确路由
    m_server.POST("/user/signin", [](const HttpReq* req, HttpResp* resp)
    {
        if (req->content_type() != APPLICATION_URLENCODED) {
            resp->set_status(HttpStatusBadRequest);  /* 400 Bad Request */
            resp->String("<html>400 Bad Request</html>");
            return ;
        }

        // 1. 解析表单数据(application/x-www-form-urlencoded)，获取用户名和密码
        std::map<string, string>& form_kv = req->form_kv();
        string& username = form_kv["username"]; 
        string& password = form_kv["password"];
#ifdef DEBUG
        cout << "[INFO] username: " << username << ", password: " << password << "\n"; /* 调试信息 */
#endif

        // 2. 校验用户名和密码(用户名是否在黑名单内，密码是否符合强度要求...)
        // 这些校验可能前端也会做 (提升用户体验)
        // 但是后端永远不要相信前端传过来的数据 (因为很容易绕过前端，直接给后端发发送请求，比如用 curl)
        if (username == "" || password == "") {
            resp->set_status(HttpStatusBadRequest);  /* 400 Bad Request */
            resp->String("<html>400 Bad Request</html>");
            return ;
        }

        // 3.校验通过后，远程同步调用UserService的sign_in方法
        const char* ip = "127.0.0.1";
        unsigned short port  = 1314;
        User::SRPCClient client{ ip, port };
        // 设置请求
        UserRequest request;
        request.set_username(username);
        request.set_password(password);
        // 同步调用
        UserResponse response;
        srpc::RPCSyncContext ctx;
        client.sign_in(&request, &response, &ctx);

        // 4. 返回响应
        if (ctx.success && response.success()) {
            using Json = nlohmann::json;
            Json data;
            data["Username"] = response.username();
            data["Token"] = response.token();
            data["Location"] = "/static/view/home.html";    /* 跳转到用户中心页面 */

            Json json;
            json["data"] = data;
            resp->String(json.dump());
        } else {
            resp->set_status(HttpStatusBadRequest);
            resp->String("<html>用户名或密码错误</html>");
        }
    });
}


/*********************************************************************************
 *                               用户信息                                        *
 *********************************************************************************/
void CloudiskServer::register_userinfo_module()
{
    m_server.GET("/user/info", [](const HttpReq* req, HttpResp* resp)
    {
        string username = req->query("username");   
        string token = req->query("token");
#ifdef DEBUG
        cout << "username: " << username 
            << "token: " << token << "\n";
#endif
        // 校验Token
        CloudDisk::User user;
        if (!CryptoUtil::verify_token(token, user)) {
            resp->set_status(HttpStatusBadRequest);
            resp->String("<html>400 Bad Request</html>");
            return ;
        }
        
        using Json = nlohmann::json;
        Json data {};
        data["Username"] = user.username;
        data["SignupAt"] = user.createdAt;

        Json json {};
        json["data"] = data;
        resp->String(json.dump(2));
    });
}

/*********************************************************************************
 *                               上传文件                                        *
 *********************************************************************************/

void CloudiskServer::register_fileupload_module()
{
    m_server.POST("/file/upload", [](const HttpReq* req, HttpResp* resp)
    {
        // 1. 解析请求参数
        string username = req->query("username");
        string token = req->query("token");
        // 2. 校验token
        CloudDisk::User user;
        if (!CryptoUtil::verify_token(token, user)) {
            resp->set_status(HttpStatusUnauthorized);
            resp->String("<html>401 Unauthorized</html>");
            return ;
        }
        // 3. 处理文件
        if (req->content_type() != MULTIPART_FORM_DATA) {
            resp->set_status(HttpStatusBadRequest);
            resp->String("<html>400 Bad Request</html>");
            return ;
        }

        Form& form = req->form();
        for (const auto& [_, file] : form) {
            const auto& [filename, content] = file;
            string hashcode = CryptoUtil::generate_hashcode(content.c_str(), content.size());
            
            string directory = "files/" + user.username + "/";  /* 为每个用户单独创建一个文件夹 */

            // access测试文件的权限, F_OK用来判断文件是否存在
            if (access(directory.c_str(), F_OK)) {
                // 如果文件夹不存在，则创建文件夹
                mkdir(directory.c_str(), 0777);
            }

            string filepath = directory + PathUtil::base(filename);
#ifdef DEBUG
            cout << "filepath: " << filepath << "\n";
#endif
            int fd = open(filepath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (fd < 0) {
                resp->set_status(500);
                resp->String("<html>500 Internal Server Error</html>");
                return ;
            }

            // 写入文件
            write(fd, content.c_str(), content.size());
            close(fd);

            // 异步备份，往消息队列中写入一条消息
            using namespace AmqpClient;
            using Json = nlohmann::json;
            Channel::ptr_t channel = Channel::CreateFromUri(RABBITMQ_URL);
            // 构建消息
            Json obj{};
            obj["object"] = filepath; 
            obj["file"] = filepath;
            BasicMessage::ptr_t message = BasicMessage::Create(obj.dump()); 
            // 发送消息
            string exchange = "oss.direct";
            string routingKey = "oss";
            channel->BasicPublish(exchange, routingKey, message);

            // 写`tbl_file`表
            string sql = "REPLACE INTO tbl_file (uid, filename, hashcode, size) VALUES ("
                + std::to_string(user.id) + ", '"
                + filename + "', '"
                + hashcode + "', "
                + std::to_string(content.size()) + ")";

            cout << "[SQL] " << sql << "\n";

            resp->MySQL(MYSQL_URL, sql, [resp](MySQLResultCursor* cursor)
            {
                if (cursor->get_cursor_status() != MYSQL_STATUS_OK) {
                    resp->set_status(HttpStatusInternalServerError);
                    resp->String("<html>500 Internal Server Error");
                    return ;
                }
                resp->Redirect("/static/view/home.html", HttpStatusSeeOther);
            });
        }
    });
}


/*********************************************************************************
 *                               文件列表                                        *
 *********************************************************************************/
void filelist_callback(wfrest::HttpResp* resp, protocol::MySQLResultCursor* cursor)
{
    /* MySQL任务失败 */
    if (cursor->get_cursor_status() != MYSQL_STATUS_GET_RESULT) {
        resp->set_status(HttpStatusInternalServerError);
        resp->String("<html>500 Internal Server Error");
        return ;
    } 

    /* 任务执行成功 */
    using namespace protocol;
    using Json = nlohmann::json;

    std::vector<MySQLCell> record {};

    Json result = Json::array();
    while (cursor->fetch_row(record)) {
        Json file {};        
        file["FileName"] = record[0].as_string();
        file["FileHash"] = record[1].as_string();
        file["FileSize"] = record[2].as_ulonglong();
        file["UploadAt"] = record[3].as_datetime();
        file["LastUpdated"] = record[4].as_datetime();

        result.push_back(std::move(file));
    }
    resp->String(result.dump(2));
}

void CloudiskServer::register_filelist_module()
{
    m_server.POST("/file/query", [](const HttpReq* req, HttpResp* resp)
    {
        // 1. 解析请求
        string username = req->query("username");    
        string token = req->query("token");
        string limit = req->form_kv()["limit"];

        // 2. 校验请求参数 (这里只是简单输出)
#ifdef DEBUG
        std::cout << "username: " << username
            << ", token: " << token
            << ", limit: " << limit << "\n";
#endif
        // 3. 校验Token
        CloudDisk::User user;
        if (!CryptoUtil::verify_token(token, user)) {
            resp->set_status(HttpStatusUnauthorized);
            resp->String("<html>401 Unauthorized</html>");
            return ;
        }
        // 4. 构建SQL语句，查询数据库
        string sql = "SELECT filename, hashcode, size, created_at, last_update FROM tbl_file WHERE uid="
            + std::to_string(user.id)
            + " LIMIT " + limit;

        std::cout << "[SQL] " << sql << "\n";

        std::function<void(MySQLResultCursor*)> callable = std::bind(filelist_callback, resp, _1);
        resp->MySQL(MYSQL_URL, sql, callable);
    });
}

/*********************************************************************************
 *                               下载文件                                        *
 *********************************************************************************/
void CloudiskServer::register_filedownload_module()
{
    m_server.GET("/file/download", [](const HttpReq* req, HttpResp* resp)
    {
       // 1. 获取请求参数
       const string& filename = req->query("filename");
       const string& filehash = req->query("filehash");
       const string& username = req->query("username");
       const string& token = req->query("token");
       // 2. 校验请求参数 (这里只是打印)
#ifdef DEBUG
        std::cout << "filename: " << filename
            << ", filehash: " << filehash
            << ", username: " << username
            << ", token: " << token << "\n";
#endif
        CloudDisk::User user;
        if (!CryptoUtil::verify_token(token, user)) {
            resp->set_status(HttpStatusUnauthorized);
            resp->String("<html>401 Unauthorized</html>");
            return ;
        }

        string filepath = "files/" + user.username + "/" + filename;
#ifdef DEBUG
        std::cout << "filepath: " << filepath << "\n";
#endif
        resp->File(filepath);
    });
}
