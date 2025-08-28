// src/routing/router.cpp
#include "routing/router.hpp"
#include <filesystem>
#include <fstream>
#include <array>
#include <algorithm>
#include <cctype>

namespace fs = std::filesystem;

namespace wntx {

static std::string extLower(const fs::path& p) {
  std::string e = p.extension().string();
  if (!e.empty() && e[0] == '.') e.erase(0, 1);
  std::transform(e.begin(), e.end(), e.begin(),
                 [](unsigned char c){ return (char)std::tolower(c); });
  return e;
}

RoutingDecision routeToHandler(const fs::path& path) {
  RoutingDecision rd{};

  // Magic check: ZIP = 'P' 'K'
  std::array<unsigned char, 4> buf{0,0,0,0};
  std::ifstream f(path, std::ios::binary);
  if (f) f.read(reinterpret_cast<char*>(buf.data()), buf.size());
  if (buf[0] == 0x50 && buf[1] == 0x4B) { // "PK"
    rd.handler = "zip";
    rd.reason  = "magic";
    return rd;
  }

  // Fallback by extension
  auto e = extLower(path);
  if (e == "zip" || e == "jar" || e == "apk" ||
      e == "docx" || e == "xlsx" || e == "pptx") {
    rd.handler = "zip";
    rd.reason  = "ext";
    return rd;
  }

  // unknown
  return rd;
}

} // namespace wntx
