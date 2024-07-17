#include <iostream>
#include <iterator>
#include <memory>
#include <ostream>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <string>
#include <string.h>
#include <assert.h>
#include <curl/curl.h>

static bool globalInitCalled = false;

void doInit()
{
    static bool initialized = ([] {
        curl_global_init(CURL_GLOBAL_ALL);
        globalInitCalled = true;
        return true;
    })();

    // silence unused warning
    (void)initialized;
}

enum Method
{
    HEAD,
    GET,
    POST,
    PUT,
};

class Session
{
public:
    enum State
    {
        NEW,
        PERFORMING,
        ABORTED,
        HTTP_OK,
        HTTP_ERR,
        OTHER_ERR
    };

    Session(Method method, const std::string& url)
        : state_(NEW)
        , statusStr_("new")
        , origUrl_(url)
        , added_(false)
    {
        doInit();
        curl_ = curl_easy_init();

        // Set URL
        setopt(CURLOPT_URL, url.c_str());

        // Set method
        switch (method)
        {
            case HEAD:
                setopt(CURLOPT_NOBODY, 1L);
                break;
            case GET:
                setopt(CURLOPT_HTTPGET, 1L);
                break;
            case POST:
                setopt(CURLOPT_POST, 1L);
                break;
            case PUT:
                setopt(CURLOPT_CUSTOMREQUEST, "PUT");
                setopt(CURLOPT_UPLOAD, 1L);
                break;
        }

        // encoding
        setopt(CURLOPT_ACCEPT_ENCODING, "");
        setopt(CURLOPT_SSL_VERIFYPEER, 0L);
    }

    ~Session()
    {
        if (curl_ != nullptr)
        {
            assert(!added_);
            std::cout << "> easy_cleanup: " << curl_ << std::endl;
            curl_easy_cleanup(curl_);
            curl_ = nullptr;
        }
    }

    void setAbortFlag(std::shared_ptr<std::atomic_bool> f)
    {
        assert(state_ == NEW);
        isAborted_ = [f]()
        {
            bool ret = f->load();
            if (ret)
            {
                std::cout << "> abort flag set." << std::endl;
            }

            return f->load();
        };
    }

    void enableDoH(const std::string& v)
    {
        assert(state_ == NEW);

        setopt(CURLOPT_DOH_URL, v.c_str());
        setopt(CURLOPT_DOH_SSL_VERIFYPEER, 0);
        setopt(CURLOPT_DOH_SSL_VERIFYHOST, 0);
    }

    bool checkAborted()
    {
        return isAborted_();
    }

    void start()
    {
        assert(state_ == NEW);
        setopt(CURLOPT_PRIVATE, this);
        state_ = PERFORMING;
        statusStr_ = "performing";
    }

    void abort()
    {
        assert(state_ == PERFORMING);
        state_ = ABORTED;
        statusStr_ = "aborted";
    }

    void added()
    {
        assert(!added_);
        added_ = true;
    }

    void removed()
    {
        assert(added_);
        added_ = false;
    }

    State getState()
    {
        return state_;
    }

    const std::string& getStatusStr() const
    {
        return statusStr_;
    }

    CURL* handle() const
    {
        return curl_;
    }

    void finish(CURLcode res)
    {
        if (res == CURLE_OK)
        {
            state_ = HTTP_OK;
            statusStr_ = "OK";
        }
        else
        {
            state_ = OTHER_ERR;
            statusStr_ = "error";
        }
    }

private:
    template <typename T>
    void setopt(CURLoption opt, T&& v) const
    {
        curl_easy_setopt(curl_, opt, v);
    }

private:
    State state_;
    std::string statusStr_;
    std::string origUrl_;
    bool added_;
    CURL* curl_ = nullptr;

    std::function<bool()> isAborted_ = []() {
        return false;
    };
};

class Client
{
public:
    Client()
    {
        doInit();
        curlm_ = curl_multi_init();
    }

    ~Client()
    {
        if (curlm_ != nullptr)
        {
            std::cout << "> multi_cleanup: " << curlm_ << std::endl;
            curl_multi_cleanup(curlm_);
            curlm_ = nullptr;
        }
    }

    std::unique_ptr<Session> get(const std::string& url, bool enable_DoH, std::shared_ptr<std::atomic_bool> v)
    {
        auto session = create(Method::GET, url);
        if (v)
        {
            session->setAbortFlag(v);
        }

        if (enable_DoH)
        {
            session->enableDoH("https://1.1.1.1/dns-query");
        }

        add(*session);

        while (!session->checkAborted() && step() > 0)
        {
            wait();
        }

        abortIfInProgress(*session);

        return std::move(session);
    }

private:
    std::unique_ptr<Session> create(Method method, const std::string& url)
    {
        return std::make_unique<Session>(method, url);
    }

    void add(Session& s)
    {
        s.start();
        std::cout << "> multi_add: " << s.handle() << std::endl;
        curl_multi_add_handle(curlm_, s.handle());
        s.added();
    }

    void remove(Session& s)
    {
        std::cout << "> multi_remove: " << s.handle() << std::endl;
        curl_multi_remove_handle(curlm_, s.handle());
        s.removed();
    }

    void abortIfInProgress(Session& s)
    {
        if (s.getState() == Session::PERFORMING)
        {
            std::cout << ">> abort session" << std::endl;
            remove(s);
            s.abort();
        }
    }

    void wait(int timeoutMs = 20)
    {
        curl_multi_poll(curlm_, NULL, 0, timeoutMs, NULL);
    }

    int step()
    {
        int active = 0;
        CURLMcode mc = curl_multi_perform(curlm_, &active);
        if (!mc)
        {
            CURLMsg* msg = 0;

            do {
                int nmsg = 0;
                msg = curl_multi_info_read(curlm_, &nmsg);
                if (msg && (msg->msg == CURLMSG_DONE))
                {
                    Session* session = nullptr;
                    curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &session);
                    assert(session);
                    session->finish(msg->data.result);
                    remove(*session);
                }

                std::cout << "-- active: " << active << ", number of message: " << nmsg << std::endl;
            }
            while(msg);
        }
        else
        {
            std::cout << "curl_multi_perform() failed. [curl error "
                << mc << "]: " << curl_multi_strerror(mc) << std::endl;
        }

        return active;
    }

private:
    CURLM* curlm_ = nullptr;
};

int main(int argc, char* argv[])
{
    std::cout << "=== curl test ===" << std::endl;

    auto url = "https://httpbin.org/delay/5";
    auto test_abort_func = [=](Client& cli, bool enable_DoH, int abortAfterMs) {
        std::cout << "\n\n=== abort request after " << abortAfterMs << " ms." << std::endl;

        auto abort_flag = std::make_shared<std::atomic_bool>(false);
        auto th = std::thread{[&]()
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(abortAfterMs));
            abort_flag->store(true);
        }};

        auto session = cli.get(url, enable_DoH, abort_flag);
        std::cout << ">> abort test " << abortAfterMs << " ms: " << session->getStatusStr() << std::endl;

        th.join();
    };

    // the program may crash if enable DoH
    bool enable_DoH = true;
    for (uint32_t loop = 0; loop < 50; ++loop)
    {
        for (uint32_t t = 1; t < 500; t = t + 10)
        {
            std::unique_ptr<Client> client(new Client());
            // auto session = client->get(url, false, nullptr);
            // std::cout << ">> normal request " << session->getStatusStr() << std::endl;

            test_abort_func(*client, enable_DoH, t);
        }
    }

    return 0;
}
