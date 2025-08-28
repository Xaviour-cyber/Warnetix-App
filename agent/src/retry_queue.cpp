#pragma once
#include <string>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>

struct RetryCfg {
  std::wstring apiUrl;
  std::wstring token;
  std::wstring spoolDir;        // folder simpan .json saat gagal kirim
  int maxInMem   = 1024;        // maksimum antrian di memori
  int minBackoff = 500;         // ms
  int maxBackoff = 15000;       // ms
};

class RetrySender {
public:
  explicit RetrySender(const RetryCfg& cfg);
  ~RetrySender();
  void start();
  void stop();
  void enqueue(const std::string& json);  // thread-safe

private:
  struct Item {
    std::string json;
    std::wstring spoolPath;  // "" kalau cuma in-mem
    int attempts = 0;
  };

  RetryCfg cfg_;
  std::deque<Item> q_;
  std::mutex mu_;
  std::condition_variable cv_;
  std::thread th_;
  std::atomic<bool> stop_{false};

  void loop_();
  void load_spool_();
  std::wstring write_spool_file_(const std::string& json);
  bool send_once_(Item& it, unsigned long& http, std::string& resp);
};
