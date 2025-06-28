#include <signal.h>
#include <string>
#include <iostream>
#include "workflow/WFFacilities.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/MySQLResult.h"
#include "workflow/MySQLUtil.h"
#include "ppconsul/agent.h"

#include "UserService.srpc.h"
#include "CryptoUtil.h"
#include "User.h"

using namespace srpc;
using namespace ppconsul::agent;
using ppconsul::Consul;
using std::string;
using std::cout;

static const std::string MYSQL_URL = "mysql://root:1234@localhost/cloudisk";
static const int RETRY_MAX = 3;

static WFFacilities::WaitGroup waitGroup{ 1 };

static void sighandler(int)
{
	waitGroup.done();
}

class UserServiceImpl : public User::Service
{
public:
    void sign_up(UserRequest* req, UserResponse* resp, RPCContext* ctx) override
    {
        // 1. 参数校验应该是API网关要做的事情
        const string& username = req->username();
        const string& password = req->password();
        // 2. 注册
        string salt = CryptoUtil::generate_salt();
        string hashcode = CryptoUtil::hash_password(password, salt);
        string sql = "INSERT INTO tbl_user (username, password, salt) VALUES ('"
            + username + "', '"
            + hashcode + "', '"
            + salt + "')";
        cout << "[SQL] " << sql << "\n";   /* 日志 */

        WFMySQLTask* mysqlTask = WFTaskFactory::create_mysql_task(MYSQL_URL, RETRY_MAX, [resp](WFMySQLTask* task)
        {
            // 任务失败或者SQL语句执行失败
            if (task->get_state() != WFT_STATE_SUCCESS || 
                task->get_resp()->get_packet_type() == MYSQL_PACKET_ERROR) {
                resp->set_success(false); 
            } else {
                resp->set_success(true);
            }
        });
        mysqlTask->get_req()->set_query(sql); 

        SeriesWork* series = ctx->get_series();
        series->push_back(mysqlTask);
    }

    void sign_in(UserRequest* req, UserResponse* resp, srpc::RPCContext* ctx) override
    {
        // 1. 解析请求参数
        const string& username = req->username();
        const string& password = req->password();
        // 2. 构建SQL语句
        string sql = "SELECT * FROM tbl_user WHERE username='"
            + username + "' AND tomb=0";
        cout << "[SQL] " << sql << "\n";   /* 日志 */

        auto callable = std::bind(signin_callback, resp, password, std::placeholders::_1);
        WFMySQLTask* mysqlTask = WFTaskFactory::create_mysql_task(MYSQL_URL, RETRY_MAX, callable);
        mysqlTask->get_req()->set_query(sql);

        SeriesWork* series = ctx->get_series();
        series->push_back(mysqlTask);
    }
private:
    static void signin_callback(UserResponse* resp, const std::string& password, WFMySQLTask* task)
    {
        using namespace protocol;
        if (task->get_state() != WFT_STATE_SUCCESS ||
            task->get_resp()->get_packet_type() == MYSQL_PACKET_ERROR) {
            resp->set_success(false);
            return ;
        }
        // MySQL 任务执行成功
        MySQLResultCursor cursor { task->get_resp() };
        std::vector<MySQLCell> record;
        
        if (!cursor.fetch_row(record)) {
            resp->set_success(false);
            return ;
        }

        CloudDisk::User user;
        user.id = record[0].as_int();
        user.username = record[1].as_string();
        user.hashcode = record[2].as_string();
        user.salt = record[3].as_string();
        user.createdAt = record[4].as_datetime();
#ifdef DEBUG
        cout << "[INFO] id: " << user.id
            << ", username: " << user.username
            << ", hashcode: " << user.hashcode
            << ", salt: " << user.salt
            << ", createdAt: " << user.createdAt << "\n";
#endif
        string h = CryptoUtil::hash_password(password, user.salt);
#ifdef DEBUG
        std::cout << "generated hashcode: " << h << "\n";
#endif
        if (h == user.hashcode) {
            resp->set_success(true); 
            resp->set_id(user.id);
            resp->set_username(user.username);
            resp->set_createdat(user.createdAt);
            resp->set_token(CryptoUtil::generate_token(user));
            return ;
        }
        // 密码错误
        resp->set_success(false);
    }
};

static void timer_callback(WFTimerTask* task)
{
    Agent* agent = (Agent*)task->user_data;    
    agent->servicePass("UserService1");

    WFTimerTask* nextTask = WFTaskFactory::create_timer_task(5, 0, timer_callback);
    nextTask->user_data = task->user_data;
    series_of(task)->push_back(nextTask);
}

int main()
{
    // 注册信号处理函数
    signal(SIGINT, sighandler);

	SRPCServer server{};

	UserServiceImpl service{};
	server.add_service(&service);

    if (server.start(1314) == 0) {
        // 向注册中心 consul 注册服务
    
        // Consul consul;
        Consul consul { "http://127.0.0.1:8500", ppconsul::kw::dc = "dc1" };
        Agent agent{ consul };
        // 注册服务
        agent.registerService(
            kw::id = "UserService1",
            kw::name = "UserService",
            kw::address = "127.0.0.1",
            kw::port = 1314,
            kw::check = TtlCheck(std::chrono::seconds{ 10 })
        );

        // 每 5 秒发送一个心跳检测包
        WFTimerTask* timerTask = WFTaskFactory::create_timer_task(5, 0, timer_callback);
        timerTask->user_data = &agent;
        timerTask->start();

        waitGroup.wait();
        server.stop();
    } else {
        std::cerr << "Error: UserService start failed!\n";
        std::exit(1);
    }

	return 0;
}
