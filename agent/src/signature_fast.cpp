#include "signature_fast.h"
#include <filesystem>
#include <algorithm>

static std::string to_ascii_lower(const std::vector<uint8_t>& b){
  std::string s; s.reserve(b.size());
  for (auto c : b){
    if (c >= 32 && c <= 126) s.push_back((char)std::tolower(c));
    else s.push_back(' ');
  }
  return s;
}

static std::string severity_of(double sc){
  if (sc >= 0.80) return "critical";
  if (sc >= 0.60) return "high";
  if (sc >= 0.40) return "medium";
  return "low";
}

FastSigOut fast_signature_scan(const std::wstring& path,
                               const std::vector<uint8_t>& head,
                               double H,
                               uint64_t sz)
{
  using namespace std;
  namespace fs = std::filesystem;

  double score = 0.0;
  string reason;

  auto extw = fs::path(path).extension().wstring();
  wstring extwl = extw;
  for (auto& ch : extwl) ch = (wchar_t)towlower(ch);
  string ext(extwl.begin(), extwl.end());

  // header magic
  if (head.size() >= 2 && head[0] == 'M' && head[1] == 'Z'){ score += 0.50; reason += "MZ;"; }

  // extension weights
  const vector<string> execs = {".exe",".dll",".scr",".sys",".msi",".lnk",".jar"};
  const vector<string> scripts = {".js",".vbs",".bat",".ps1",".hta",".cmd",".wsf"};
  const vector<string> archives = {".zip",".rar",".7z",".cab",".iso",".img"};
  const vector<string> officem = {".docm",".xlsm",".pptm"};

  auto has = [&](const vector<string>& v){ return find(v.begin(), v.end(), ext) != v.end(); };
  if (has(execs))   { score += 0.40; reason += "ext:exec;"; }
  if (has(scripts)) { score += 0.30; reason += "ext:script;"; }
  if (has(archives)){ score += 0.20; reason += "ext:archive;"; }
  if (has(officem)) { score += 0.30; reason += "ext:office-macro;"; }

  // entropy
  if (H >= 7.2){ score += 0.30; reason += "entropy>7.2;"; }
  if (H >= 7.8){ score += 0.10; reason += "entropy>7.8;"; }

  // suspicious strings
  string s = to_ascii_lower(head);
  auto add_if = [&](const char* needle, double w, const char* tag){
    if (s.find(needle) != string::npos){ score += w; reason += tag; reason += ';'; }
  };
  add_if("powershell", 0.25, "kw:powershell");
  add_if("cmd.exe",    0.20, "kw:cmd");
  add_if("wscript",    0.20, "kw:wscript");
  add_if("http://",    0.15, "kw:http");
  add_if("https://",   0.15, "kw:https");
  add_if("document_open", 0.25, "kw:vba_auto");
  add_if("autoopen",       0.25, "kw:vba_auto2");
  add_if("base64",     0.15, "kw:base64");

  if (sz > (50ull<<20)) { score += 0.05; reason += "size>50MB;"; } // dikit aja

  if (score > 1.0) score = 1.0;
  return FastSigOut{score, severity_of(score), reason};
}
