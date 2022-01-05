#include "daScript/misc/platform.h"
#include "daScript/misc/string_writer.h"

#include "daScript/ast/ast.h"
#include "daScript/ast/ast_interop.h"
#include "daScript/ast/ast_typefactory_bind.h"
#include "daScript/ast/ast_handle.h"

#include <curl/curl.h>

#include <list>

#if __cplusplus >= 201703L
#define HAS_STRING_VIEW 1
#include <string_view>
typedef std::string_view  RespHeaderString;
#else
#define HAS_STRING_VIEW 0
typedef std::string  RespHeaderString;
#endif


namespace das
{

namespace requests
{

static CURLM *curlm = nullptr;
static CURLSH *curlsh = nullptr;

static const unsigned int TCP_CONNECT_TIMEOUT_SEC = 12;

static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata);
static size_t header_callback(char *ptr, size_t size, size_t nmemb, void *userdata);

static int progress_callback(void *userdata, curl_off_t dltotal, curl_off_t dlnow,
                             curl_off_t, curl_off_t);

static string default_user_agent = "daScript";


using Header = pair<const char*, const char*>;
using StringMap = map<RespHeaderString, RespHeaderString>;


enum class RequestStatus
{
    SUCCESS,
    FAILED,
    ABORTED
};


struct RequestParams {
    RequestParams() {
        puts("DBG: RequestParams::ctor()");
        LOG(LogLevel::error) << "RequestParams::ctor()";
    }

    ~RequestParams() {
        puts("DBG: RequestParams::dtor()");
        LOG(LogLevel::error) << "RequestParams::dtor()";
    }

    const char  *method = "GET";
    const char  *url = nullptr;
    das::Lambda callback;
    das::Lambda onProgress;

    vector<Header> headers;
};

struct Response {
    int code = 0;
    das::TArray<uint8_t> body;
    // TODO: headers table

    const char* text()
    {
        return body.data; // a traling zero is manually appended to body
    }
};


static CURL *make_curl_handle(const char *url, const char *user_agent, bool verify_host, void *user_data)
{
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress_callback);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);
    curl_easy_setopt(curl, CURLOPT_SHARE, curlsh);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);

    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, TCP_CONNECT_TIMEOUT_SEC);
    curl_easy_setopt(curl, CURLOPT_DNS_USE_GLOBAL_CACHE, 0);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, user_data);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, user_data);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, user_data);
    curl_easy_setopt(curl, CURLOPT_PRIVATE, user_data);
    // curl_easy_setopt(curl, CURLOPT_VERBOSE, verbose_debug ? 1L : 0L);
    // curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_debug);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_host ? 2L : 0L);

    return curl;
}


class RequestState
{
public:
    RequestState(RequestParams const& params, Context *context_, LineInfoArg *at_)
      : context(context_)
      , at(at_)
    {
        urlStr = params.url;
        callback = params.callback;
        onProgress = params.onProgress;
        assert(callback.capture);
        curlHandle = make_curl_handle(urlStr.c_str(),
                                    /*params.userAgent ? params.userAgent : */default_user_agent.c_str(),
                                    /*params.verifyCert*/false, this);
    }

    ~RequestState()
    {
        if (headersList)
            curl_slist_free_all(headersList);

        if (curlHandle)
        {
            curl_easy_setopt(curlHandle, CURLOPT_NOPROGRESS, 1);
            curl_easy_setopt(curlHandle, CURLOPT_HEADERFUNCTION, nullptr);
            curl_easy_setopt(curlHandle, CURLOPT_XFERINFOFUNCTION, nullptr);
            curl_easy_cleanup(curlHandle);
        }
    }


    CURL *getCurlHandle()
    {
        return curlHandle;
    }


    void onRequestFinished(int http_code, CURLcode curl_code)
    {
        httpCode = http_code;
        curlResult = curl_code;

        LOG(LogLevel::trace) << "onRequestFinish http_code: " << http_code
          << "| error: " << curl_easy_strerror(curl_code);
    }


    void sendResult()
    {
        //assert(callback);
        // TODO: pass headers as table in Response
/*
        StringMap headersMap;

        for (string const& header: responseHeaders)
        {
            //DEBUG_VERBOSE("sendResult header: %.*s", header.size(), header.data());
            RespHeaderString hv(header.data(), header.size());
            auto delimPos = hv.find(":");
            if (delimPos != hv.npos)
            {
                auto key = hv.substr(0, delimPos);
                auto value = hv.substr(delimPos+1);

                auto crlfPos = value.find("\r\n");
                if (crlfPos != value.npos)
                {
                    #if HAS_STRING_VIEW
                    value.remove_suffix(value.size() - crlfPos);
                    #else
                    value = value.substr(0, crlfPos);
                    #endif
                }

                auto nonSpacePos = value.find_first_not_of(' ');
                if (nonSpacePos != value.npos)
                {
                    #if HAS_STRING_VIEW
                    value.remove_prefix(nonSpacePos);
                    #else
                    value = value.substr(nonSpacePos, value.length());
                    #endif
                    headersMap[key] = value;
                }
            }
        }
*/
        RequestStatus result;
        if (abortFlag)
            result = RequestStatus::ABORTED;
        else
            result = curlResult == CURLE_OK ? RequestStatus::SUCCESS : RequestStatus::FAILED;

        LOG(LogLevel::trace) << "sendResult result: " << (int)result;

        if (callback.capture)
        {
          Response resp;
          resp.code = httpCode;

          uint32_t size = uint32_t(responseBody.size());
          responseBody.push_back(0); // trailing zero for using as string

          resp.body.data = (char *)responseBody.data();
          resp.body.size = resp.body.capacity = size;
          resp.body.lock = 1;
          resp.body.flags = 0;

          das_invoke_lambda<void>::invoke<Response*>(context, at, callback, &resp);
        }
    }

    void abort()
    {
        LOG(LogLevel::info) << "request to '" << urlStr << "' aborted";
        abortFlag = true;
    }

    bool isAborted() const
    {
        return abortFlag;
    }

    size_t updateResponse(const char *ptr, size_t sz)
    {
        size_t bytesAfterUpdate = sz + responseBody.size();

        if (maxDownloadSize != 0 && bytesAfterUpdate > maxDownloadSize)
        {
            LOG(LogLevel::info) << "warning: response from '" << urlStr
              << "' exceeded maximum limit of " << maxDownloadSize << " bytes. Request aborted";
            return 0;
        }

        responseBody.insert(responseBody.end(), ptr, ptr+sz);
        return sz;
    }

    void addResponseHeader(const char *ptr, size_t sz)
    {
        //DEBUG_VERBOSE("add response header:%.*s", header.count(), header.ptr());
        responseHeaders.emplace_back(ptr, sz);
    }

    void onDownloadProgress(size_t dltotal, size_t dlnow)
    {
        if (onProgress.capture)
          das_invoke_lambda<void>::invoke<size_t, size_t>(context, at, onProgress, dltotal, dlnow);
    }

    size_t responseSize() const
    {
        return responseBody.size();
    }

private:
    CURL        *curlHandle = nullptr;
    size_t      maxDownloadSize;
    curl_slist  *headersList = nullptr;
    string      urlStr;

    Context       *context = nullptr;
    LineInfoArg   *at = nullptr;
    das::Lambda   callback,
                  onProgress;

    bool abortFlag = false;

    int httpCode = 0;
    CURLcode curlResult = CURLE_OK;

    vector<char>    responseBody;
    list<string>    responseHeaders;
};


using RequestStatePtr = unique_ptr<RequestState>;

static list<RequestStatePtr> active_requests;


static int progress_callback(void *userdata, curl_off_t dltotal, curl_off_t dlnow,
                             curl_off_t, curl_off_t)
{
  RequestState *context = (RequestState *)userdata;
  if (dlnow > 0 || dltotal > 0)
    context->onDownloadProgress(dltotal, dlnow);
  return 0;
}

static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata)
{
  RequestState *context = (RequestState *)userdata;
  size_t nbytes = size * nmemb;
  return context->updateResponse((const char*)ptr, nbytes);
}

static size_t header_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  RequestState *context = (RequestState *)userdata;
  size_t nbytes = size * nmemb;
  context->addResponseHeader((const char *)ptr, nbytes);
  return nbytes;
}


struct RequestParamsTypeAnnotation : ManagedStructureAnnotation <RequestParams> {
    RequestParamsTypeAnnotation(ModuleLibrary & ml) : ManagedStructureAnnotation ("RequestParams",ml) {
        addField<DAS_BIND_MANAGED_FIELD(method)>("method", "method");
        addField<DAS_BIND_MANAGED_FIELD(url)>("url", "url");
        addField<DAS_BIND_MANAGED_FIELD(callback)>("callback", "callback");
        addField<DAS_BIND_MANAGED_FIELD(onProgress)>("onProgress", "onProgress");
    }
    virtual bool isLocal() const override { return true; }  // this ref-value can appear as local variable in das
    virtual bool canCopy() const override { return true; }  // this ref-value can be copied
    virtual bool canMove() const override { return true; }  // this ref-value can be moved
};

struct ResponseTypeAnnotation : ManagedStructureAnnotation <Response> {
    ResponseTypeAnnotation(ModuleLibrary & ml) : ManagedStructureAnnotation ("Response",ml) {
        addField<DAS_BIND_MANAGED_FIELD(code)>("code","code");
        addField<DAS_BIND_MANAGED_FIELD(body)>("body","body");
        addProperty<DAS_BIND_MANAGED_PROP(text)>("text");
    }
};


static intptr_t request(const RequestParams &params, Context * context, LineInfoArg * at) {
    LOG(LogLevel::error) << "request for " << params.url;

    RequestStatePtr rsp = make_unique<RequestState>(params, context, at);
    RequestState *reqStatePtr = rsp.get();
    {
        //WinAutoLock lock(mutex);
        active_requests.push_back(move(rsp));
        curl_multi_add_handle(curlm, reqStatePtr->getCurlHandle());
        int handles = 0;
        curl_multi_socket_action(curlm, CURL_SOCKET_TIMEOUT, 0, &handles);
    }
    LOG(LogLevel::trace) << "send request to '" << params.url << "'";
    return intptr_t(reqStatePtr);
}


static int timer_func(CURLM *, long /*timeout*/, void *)
{
  return 0;
}


static void abort_all_requests()
{
    std::list<RequestStatePtr> aborted = std::move(active_requests);
    for (RequestStatePtr &rstate : aborted)
        curl_multi_remove_handle(curlm, rstate->getCurlHandle());

    for (RequestStatePtr &rstate : aborted)
    {
        rstate->abort();
        rstate->sendResult();
    }
}


static void update_multi_nolock(list<RequestStatePtr> &finished)
{
  fd_set fdread, fdwrite, fdexcep;
  int maxfd = -1;

  FD_ZERO(&fdread);
  FD_ZERO(&fdwrite);
  FD_ZERO(&fdexcep);

  curl_multi_fdset(curlm, &fdread, &fdwrite, &fdexcep, &maxfd);

  struct timeval pollTimeout = {0, 0}; // without timeout. non-blocking poll
  int rc = maxfd == -1 ? -1 : select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &pollTimeout);
  int nrunning = 0;
  const bool needPerform = rc != -1 || // there are sockets IO ready
//    (timeout_ms > 0 && get_time_msec() >= timeout_ms) || // timeout was hit
    (maxfd == -1 && !active_requests.empty()); // curl does not know about sockets yet

  if (needPerform)
  {
    curl_multi_perform(curlm, &nrunning);
    int msgInQueue = 0;

    while (CURLMsg *msg = curl_multi_info_read(curlm, &msgInQueue))
    {
      if (msg->msg != CURLMSG_DONE)
      {
        LOG(LogLevel::trace) << "curl msg not done. msgInQueue: " << msgInQueue;
        if (!msgInQueue)
          break;
        else
          continue;
      }

      long respCode = 0;
      CURL *easy = msg->easy_handle;
      CURLcode code = msg->data.result;
      LOG(LogLevel::trace) << "Curl error code: " << curl_easy_strerror(code);

      curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &respCode);
      LOG(LogLevel::trace) << "Curl response code: " << respCode;

      const char *url = nullptr;
      curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &url);
      if (url == nullptr)
        url = "<unknown url>";
      LOG(LogLevel::trace) << "Curl url: " << url;

      char *addr = NULL;
      curl_easy_getinfo(easy, CURLINFO_PRIMARY_IP, &addr);
      LOG(LogLevel::trace) << "Curl addr: " << addr;

      double connectTime = 0;
      double totalTime = 0;
      double nameLookupTime = 0;

      curl_easy_getinfo(easy, CURLINFO_TOTAL_TIME, &totalTime);
      curl_easy_getinfo(easy, CURLINFO_CONNECT_TIME, &connectTime);
      curl_easy_getinfo(easy, CURLINFO_NAMELOOKUP_TIME, &nameLookupTime);
      LOG(LogLevel::trace) << "Curl totalTime: " << totalTime << " | connectTime: " << connectTime <<
        " | nameLookupTime: " << nameLookupTime;

      void *ptr = nullptr;
      curl_easy_getinfo(easy, CURLINFO_PRIVATE, &ptr);
      curl_multi_remove_handle(curlm, easy);

      RequestState *reqState = static_cast<RequestState *>(ptr);
    //   if (code != CURLE_OK)
    //   {
    //     debug("request to '%s' ip: %s failed: %s. times: total %.2fms, conn %.2fms, "
    //           "nl %.2fms. size: %d",
    //           url, addr, curl_easy_strerror(code), totalTime * 1000, connectTime * 1000,
    //           nameLookupTime * 1000, reqState->responseSize());
    //   }
    //   else
    //   {
    //     debug("request to '%s' ip: %s succeed with code %d. times: total %.2fms, conn %.2fms, "
    //           "nl %.2fms. size: %d",
    //           url, addr, (int)respCode, totalTime * 1000, connectTime * 1000,
    //           nameLookupTime * 1000, reqState->responseSize());
    //   }

      reqState->onRequestFinished(respCode, code);

      auto it = find_if(active_requests.begin(), active_requests.end(),
                       [reqState](RequestStatePtr const &ptr) { return ptr.get() == reqState; });

      if (it != active_requests.end())
      {
        finished.push_back(move(*it));
        active_requests.erase(it);
      }
    }
  }
}


static void collect_aborted_requests_nolock(list<RequestStatePtr> &finished)
{
  for (auto it = active_requests.begin(); it != active_requests.end();)
  {
    if ((*it)->isAborted())
    {
      curl_multi_remove_handle(curlm, (*it)->getCurlHandle());
      finished.push_back(move(*it));
      it = active_requests.erase(it);
    }
    else
    {
      ++it;
    }
  }
}


static void requests_poll()
{
  list<RequestStatePtr> finished;

  update_multi_nolock(finished);
  collect_aborted_requests_nolock(finished);

  for (RequestStatePtr &request : finished)
    request->sendResult();
}

} // requests

using namespace requests;

class Module_Requests : public Module {
public:
    Module_Requests() : Module("requests") {
        ModuleLibrary lib;
        lib.addModule(this);
        lib.addBuiltInModule();
        addAnnotation(make_smart<RequestParamsTypeAnnotation>(lib));
        addAnnotation(make_smart<ResponseTypeAnnotation>(lib));
        addExtern<DAS_BIND_FUN(request)> (*this, lib, "request",
            SideEffects::modifyExternal, "request")
                ->args({"params", "context","at"});

        addExtern<DAS_BIND_FUN(requests_poll)>(*this, lib, "requests_poll",
            SideEffects::modifyExternal, "requests_poll");

        int cres = curl_global_init(CURL_GLOBAL_DEFAULT);
        if (cres)
            LOG(LogLevel::error) << "CURL initialization failed";

        curlm = curl_multi_init();
        curl_multi_setopt(curlm, CURLMOPT_TIMERFUNCTION, &timer_func);
        curl_multi_setopt(curlm, CURLMOPT_TIMERDATA, NULL);
        curl_multi_setopt(curlm, CURLMOPT_PIPELINING, 1);
        curl_multi_setopt(curlm, CURLMOPT_MAX_TOTAL_CONNECTIONS, 10);

        curlsh = curl_share_init();
        curl_share_setopt(curlsh, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
        curl_share_setopt(curlsh, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
        curl_share_setopt(curlsh, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
    }

    // virtual ModuleAotType aotRequire ( TextWriter & tw ) const override {
    //     tw << "#include \"../modules/dasHttp/src/dasHttp.h\"\n";
    //     return ModuleAotType::cpp;
    // }

    virtual ~Module_Requests() {
        abort_all_requests();

        if (curlm) {
            curl_multi_cleanup(curlm);
            curlm = nullptr;
        }
        if (curlsh) {
            curl_share_cleanup(curlsh);
            curlsh = nullptr;
        }

        curl_global_cleanup();
    }
};

} // das


REGISTER_MODULE_IN_NAMESPACE(Module_Requests, das);

MAKE_TYPE_FACTORY(requests::RequestParams, requests::RequestParams);
MAKE_TYPE_FACTORY(requests::Response, requests::Response);
