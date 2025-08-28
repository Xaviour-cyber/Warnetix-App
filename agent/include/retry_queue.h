#pragma once
#include <string>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <algorithm>

#include "http_client.h"  // http_post_json(url, body, token, &code, &resp)

struct RetryCfg {
  std::wstring apiUrl;
  std::wstring token;
  std::wstring spoolDir;
  int maxInMem   = 1024;
  int minBackoff = 500;
  int maxBackoff = 15000;
};

class RetrySender {
public:
  inline explicit RetrySender(const RetryCfg& cfg) : cfg_(cfg) {
    std::error_code ec; std::filesystem::create_directories(cfg_.spoolDir, ec);
  }
  inline ~RetrySender(){ stop(); }

  inline void start(){
    if (th_.joinable()) return;
    stop_ = false;
    load_spool_();
    th_ = std::thread(&RetrySender::loop_, this);
  }
  inline void stop(){
    stop_ = true;
    cv_.notify_all();
    if (th_.joinable()) th_.join();
  }
  inline void enqueue(const std::string& json){
    std::unique_lock<std::mutex> lk(mu_);
    if ((int)q_.size() >= cfg_.maxInMem){
      std::wstring p = write_spool_file_(json);
      q_.push_back(Item{json, p, 0});
    } else {
      q_.push_back(Item{json, L"", 0});
    }
    lk.unlock(); cv_.notify_one();
  }

private:
  struct Item {
    std::string json;
    std::wstring spoolPath;
    int attempts = 0;
  };

  RetryCfg cfg_;
  std::deque<Item> q_;
  std::mutex mu_;
  std::condition_variable cv_;
  std::thread th_;
  std::atomic<bool> stop_{false};

  inline void load_spool_(){
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::exists(cfg_.spoolDir, ec)) return;
    for (auto& e : fs::directory_iterator(cfg_.spoolDir)){
      if (!e.is_regular_file()) continue;
      if (e.path().extension().wstring() != L".json") continue;
      std::ifstream f(e.path(), std::ios::binary);
      std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
      q_.push_back(Item{s, e.path().wstring(), 0});
    }
  }

  inline std::wstring write_spool_file_(const std::string& json){
    using namespace std::chrono;
    auto ts = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    std::wstring name = L"spool_" + std::to_wstring(ts) + L".json";
    std::filesystem::path p = std::filesystem::path(cfg_.spoolDir) / name;
    std::ofstream f(p, std::ios::binary); f.write(json.data(), (std::streamsize)json.size());
    return p.wstring();
  }

  inline bool send_once_(Item& it, unsigned long& http, std::string& resp){
    return http_post_json(cfg_.apiUrl, it.json, cfg_.token, &http, &resp);
  }

  inline void loop_(){
    while (!stop_){
      Item cur;
      {
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait(lk, [&]{ return stop_ || !q_.empty(); });
        if (stop_) break;
        cur = q_.front(); q_.pop_front();
      }

      unsigned long code = 0; std::string resp;
      bool ok = send_once_(cur, code, resp);
      if (ok && code >= 200 && code < 300){
        if (!cur.spoolPath.empty()){
          std::error_code ec; std::filesystem::remove(cur.spoolPath, ec);
        }
        // OK, lanjut item berikut
      } else {
        cur.attempts++;
        int back = cfg_.minBackoff * (1 << std::min(cur.attempts, 5));
        if (back > cfg_.maxBackoff) back = cfg_.maxBackoff;
        if (cur.spoolPath.empty()) cur.spoolPath = write_spool_file_(cur.json);
        std::this_thread::sleep_for(std::chrono::milliseconds(back));
        std::unique_lock<std::mutex> lk(mu_);
        q_.push_back(cur);
        lk.unlock(); cv_.notify_one();
      }
    }
  }
};
