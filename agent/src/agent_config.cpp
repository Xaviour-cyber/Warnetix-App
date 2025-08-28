#include "agent_config.h"
#include <windows.h>
#include <shlwapi.h>
#include <filesystem>

using std::wstring;
namespace fs = std::filesystem;

static wstring wenv(const wchar_t* key, const wchar_t* def = L"") {
  wchar_t buf[4096]; DWORD n = GetEnvironmentVariableW(key, buf, 4096);
  if (n == 0 || n >= 4096) return def ? def : L"";
  return wstring(buf);
}

void addDefaultUserDirs(AgentConfig& cfg) {
  wstring home = wenv(L"USERPROFILE");
  if (home.empty()) return;
  auto join = [&](const wstring& sub){ return home + L"\\" + sub; };
  if (cfg.watchPaths.empty()) cfg.watchPaths = { join(L"Downloads"), join(L"Desktop"), join(L"Documents") };
}

AgentConfig loadConfigFromEnv() {
  AgentConfig c;
  c.apiUrl        = wenv(L"WARNETIX_API", L"http://127.0.0.1:8000/events/push");
  c.token         = wenv(L"WARNETIX_AGENT_TOKEN", L"");
  c.quarantineDir = wenv(L"WARNETIX_QUARANTINE_DIR", L"");
  c.policyMode    = wenv(L"WARNETIX_POLICY", L"simulate");
  c.policyMin     = wenv(L"WARNETIX_POLICY_MIN", L"high");
  for (auto& ch : c.policyMin) ch = (wchar_t)towlower(ch);

  wstring spool = wenv(L"WARNETIX_AGENT_SPOOL_DIR", L"");
  if (!spool.empty()) c.spoolDir = spool;

  addDefaultUserDirs(c);

  if (c.quarantineDir.empty()) {
    wchar_t cwd[MAX_PATH]; GetCurrentDirectoryW(MAX_PATH, cwd);
    c.quarantineDir = wstring(cwd) + L"\\quarantine";
  }
  std::error_code ec; fs::create_directories(c.quarantineDir, ec);
  fs::create_directories(c.spoolDir, ec);
  return c;
}
