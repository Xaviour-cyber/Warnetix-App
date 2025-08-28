// src/core/stubs_link.cpp
#include "core/scan_archive.hpp"
#include <filesystem>
#include <string>
#include <map>
#include <iostream>

namespace fs = std::filesystem;

namespace wntx {

// forward-declare tipe non-ekspos (cukup ref, gak perlu definisi lengkap)
struct FileMeta;
struct DetectHints;

// --- LOGGING SEDERHANA ---
void logEvent(const std::string& rootScanId,
              const std::string& eventType,
              const std::map<std::string,std::string>& kv)
{
  std::cout << "[LOG][" << eventType << "] id=" << rootScanId;
  for (auto& [k,v] : kv) std::cout << " " << k << "=" << v;
  std::cout << "\n";
}

// --- QUARANTINE SEDERHANA (move/copy) ---
bool safeQuarantine(const fs::path& src,
                    const fs::path& quarantDir,
                    std::string& outNewPath,
                    std::string& err)
{
  try {
    std::error_code ec;
    fs::create_directories(quarantDir, ec);
    auto dst = quarantDir / (src.filename().string() + ".quarantine");
    // kalau sudah ada, tambah suffix random kecil
    int i = 0;
    while (fs::exists(dst)) {
      dst = quarantDir / (src.filename().string() + ".quarantine." + std::to_string(++i));
    }
    // coba rename dulu (cepat), kalau beda volume → copy then remove
    fs::rename(src, dst, ec);
    if (ec) {
      ec.clear();
      fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
      if (ec) { err = "copy failed"; return false; }
      fs::remove(src, ec);
    }
    outNewPath = dst.string();
    return true;
  } catch (const std::exception& e) {
    err = e.what();
    return false;
  }
}

// --- SCORING MINIMAL ---
Severity scoreSeverity(const FileMeta&, const DetectHints&) {
  // untuk tes awal, anggap low
  return Severity::Low;
}

// --- KEBIJAKAN MINIMAL ---
Action chooseAction(Severity sev,
                    const PolicyContext&,
                    const std::string& /*extLower*/,
                    const DetectHints& /*h*/)
{
  return (sev >= Severity::High) ? Action::Quarantine : Action::Simulate;
}

// --- APPLY ACTION MINIMAL ---
Action applyAction(Action a, const fs::path& p, ScanContext& ctx)
{
  if (a == Action::Quarantine) {
    std::string newPath, err;
    if (safeQuarantine(p, ctx.quarantineDir, newPath, err)) {
      logEvent(ctx.rootScanId, "quarantine_child", {{"path", p.string()}, {"to", newPath}});
      return Action::Quarantine;
    } else {
      logEvent(ctx.rootScanId, "error", {{"where","quarantine_child"},{"msg", err}});
      return Action::Error;
    }
  }
  // Simulate/Rename/Delete bisa lu lengkapi nanti
  return a;
}

// --- HASH STUB ---
std::string computeHash(const fs::path&, const char*) {
  return "sha256_stub";
}

} // namespace wntx
