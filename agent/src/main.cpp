#include "agent_config.h"
#include "json_min.h"
#include "entropy.h"
#include "hash_sha256.h"
#include "http_client.h"
#include "watcher_win.h"
#include "retry_queue.h"
#include "signature_fast.h"
#include "log.h"

#include <filesystem>
#include <fstream>
#include <chrono>
#include <thread>
#include <atomic>
#include <set>
#include <windows.h>

using namespace std;
namespace fs = std::filesystem;

// --- helper ENV untuk main.cpp ---
static std::wstring env_w(const wchar_t* key) {
  wchar_t buf[4096]; DWORD n = GetEnvironmentVariableW(key, buf, 4096);
  if (n == 0 || n >= 4096) return L"";
  return std::wstring(buf);
}

static bool file_exists_regular(const wstring& p) {
  std::error_code ec; return fs::exists(p, ec) && fs::is_regular_file(p, ec);
}

static bool file_stable(const wstring& p, int tries=3, int ms=400) {
  uintmax_t last = (uintmax_t)-1;
  for (int i=0;i<tries;i++){
    std::error_code ec; auto now = fs::file_size(p, ec);
    if (ec) return false;
    if (now == last) return true;
    last = now;
    this_thread::sleep_for(chrono::milliseconds(ms));
  }
  return true;
}

static vector<uint8_t> read_head(const wstring& p, size_t n=128*1024) {
  vector<uint8_t> out; out.reserve(n);
  ifstream f(p, ios::binary); if (!f) return out;
  out.resize(n); f.read((char*)out.data(), out.size());
  out.resize((size_t)f.gcount());
  return out;
}

static string extension_lower(const wstring& p) {
  wstring ext = fs::path(p).extension().wstring();
  for (auto& ch : ext) ch = (wchar_t)towlower(ch);
  return utf8(ext);
}

static bool ensure_dir(const wstring& d) {
  error_code ec; fs::create_directories(d, ec); return !ec;
}
static wstring unique_target(const wstring& base) {
  fs::path p(base); if (!fs::exists(p)) return base;
  for (int i=1;i<10000;i++){
    fs::path q = p.parent_path() / (p.stem().wstring() + L"_" + to_wstring(i) + p.extension().wstring());
    if (!fs::exists(q)) return q.wstring();
  }
  return base + L"_dup";
}
static bool move_quarantine(const wstring& src, const wstring& qdir, wstring& out_target) {
  ensure_dir(qdir);
  fs::path dest = fs::path(qdir) / fs::path(src).filename();
  wstring t = unique_target(dest.wstring());
  error_code ec; fs::rename(src, t, ec);
  if (ec) { ec.clear(); fs::copy_file(src, t, fs::copy_options::overwrite_existing, ec);
    if (ec) return false; ec.clear(); fs::remove(src, ec); }
  out_target = t; return true;
}
static bool rename_blocked(const wstring& src, wstring& out_target) {
  fs::path p(src); fs::path q = p; q += L".blocked";
  wstring t = unique_target(q.wstring());
  error_code ec; fs::rename(src, t, ec);
  if (ec) return false; out_target = t; return true;
}

static int sev_rank(const std::string& s){
  if (s=="critical") return 3;
  if (s=="high") return 2;
  if (s=="medium") return 1;
  return 0;
}
static int sev_rank_w(const std::wstring& s) noexcept {
    if (s == L"critical") return 3;
    if (s == L"high")     return 2;
    if (s == L"medium")   return 1;
    return 0; // low/unknown
}
int wmain(int argc, wchar_t** argv) {
  AgentConfig cfg = loadConfigFromEnv();

  // arg path opsional
  for (int i=1;i<argc;i++){ std::wstring a = argv[i]; if (a.rfind(L"--",0)!=0) cfg.watchPaths.push_back(a); }
  if (cfg.watchPaths.empty()) addDefaultUserDirs(cfg);

  // Retry sender
  RetryCfg rcfg;
  rcfg.apiUrl    = cfg.apiUrl;
  rcfg.token     = cfg.token;
  rcfg.spoolDir  = cfg.spoolDir;
  rcfg.minBackoff= cfg.minBackoffMs;
  rcfg.maxBackoff= cfg.maxBackoffMs;
  RetrySender sender(rcfg); sender.start();

  LOGI(L"agent url=" + cfg.apiUrl);
  LOGI(L"policy=" + cfg.policyMode + L" >= " + cfg.policyMin);
  LOGI(L"quarantine=" + cfg.quarantineDir);
  LOGI(L"spool=" + cfg.spoolDir);
  for (auto& p : cfg.watchPaths) LOGI(L"watch: " + p);

  auto cb = [&](const std::wstring& full, bool created, bool modified) {
    (void)created; (void)modified;

    if (!file_exists_regular(full)) return;
    if (!file_stable(full)) return;

    auto head = read_head(full);
    double H = entropy_8bit(head);
    error_code ec; uintmax_t sz = fs::file_size(full, ec);
    string sha = sha256_file(full);
    string ext = extension_lower(full);

    // --- fast signature + severity estimation
    auto sig = fast_signature_scan(full, head, H, (uint64_t)sz);
    string severity_est = sig.severity;

    // --- policy quick
std::string  action  = "simulate";
std::wstring targetW;

const int est_rank = sev_rank(severity_est);
const int min_rank = sev_rank_w(cfg.policyMin);
const std::wstring wsev(severity_est.begin(), severity_est.end());

LOGI(L"[policy] file=" + full +
     L" | fast_sev=" + wsev +
     L" (" + std::to_wstring(est_rank) + L") >= min=" +
     cfg.policyMin + L" (" + std::to_wstring(min_rank) + L") ?");

// Ambang terpenuhi?
if (est_rank >= min_rank) {
    if (cfg.policyMode == L"rename") {
        if (rename_blocked(full, targetW)) {
            action = "rename";
            LOGI(L"[policy] RENAME OK  : " + full + L" -> " + targetW);
        } else {
            LOGW(L"[policy] RENAME FAIL: " + full + L" (tetap simulate)");
        }
    } else if (cfg.policyMode == L"quarantine") {
        if (move_quarantine(full, cfg.quarantineDir, targetW)) {
            action = "quarantine";
            LOGI(L"[policy] QUARANTINE OK  : " + full + L" -> " + targetW);
        } else {
            LOGW(L"[policy] QUARANTINE FAIL: " + full + L" (tetap simulate)");
        }
    } else {
        LOGW(L"[policy] unknown mode='" + cfg.policyMode + L"', fallback simulate");
    }
} else {
    LOGI(L"[policy] below threshold, simulate: " + full);
}

// --- Ringkasan hasil akhir (tempatkan SETELAH aksi diputuskan)
if      (action == "simulate")   LOGI(L"[policy] RESULT = simulate   : " + full);
else if (action == "rename")     LOGI(L"[policy] RESULT = rename     -> " + targetW);
else if (action == "quarantine") LOGI(L"[policy] RESULT = quarantine -> " + targetW);


    // --- build JSON payload
    string body = "{";
    body += "\"kind\":\"agent_fast\",";
    body += "\"ts\":" + to_string(chrono::duration<double>(chrono::system_clock::now().time_since_epoch()).count()) + ",";
    body += "\"path\":\"" + jsonEscapeW(full) + "\",";
    body += "\"meta\":{";
      body += "\"sha256\":\"" + jsonEscape(sha) + "\",";
      body += "\"size\":" + to_string((double)sz) + ",";
      body += "\"ext\":\"" + jsonEscape(ext) + "\",";
      body += "\"entropy\":" + to_string(H) + ",";
      body += "\"sig_score\":" + to_string(sig.score) + ",";
      body += "\"sig_reason\":\"" + jsonEscape(sig.reason) + "\",";
      body += "\"severity_fast\":\"" + jsonEscape(severity_est) + "\"";
    body += "},";
    body += "\"policy\":{";
  body += "\"mode\":\""  + jsonEscapeW(cfg.policyMode) + "\","; // TAMBAH
  body += "\"min\":\""   + jsonEscapeW(cfg.policyMin)  + "\","; // TAMBAH
  body += "\"action\":\"" + action + "\"";
  if (!targetW.empty()) body += ",\"target\":\"" + jsonEscapeW(targetW) + "\"";
body += "},";
    body += "\"agent\":{";
      body += "\"ver\":\"0.2.0\",\"host\":\"" + jsonEscapeW(env_w(L"COMPUTERNAME")) + "\"";
    body += "},";
    body += "\"enqueue_deep_scan\":true";
    body += "}";

    sender.enqueue(body);
  };

  // start watcher(s)
  for (auto& dir : cfg.watchPaths) if (!dir.empty()) watch_directory_thread(dir, cfg.recursive, cb);

  LOGI(L"running. Ctrl+C to exit.");
  while (true) this_thread::sleep_for(chrono::seconds(60));
  return 0;
}