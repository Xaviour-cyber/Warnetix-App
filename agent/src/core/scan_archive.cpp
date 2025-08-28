// src/core/scan_archive.cpp
#include "core/scan_archive.hpp"
#include "readers/IArchiveReader.hpp"   // EntryInfo, makeZipReader()
#include "routing/router.hpp"           // routeToHandler(path)

#include <chrono>
#include <filesystem>
#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <cctype>

using namespace std::chrono_literals;

namespace wntx {

// ====== Tipe pendukung ringan (dipakai analisis anak) ======
struct FileMeta {
  std::filesystem::path absPath;
  std::string nameInArchive;
  uint64_t sizeOnDisk = 0;
  std::string sha256;
};

struct DetectHints {
  bool isArchive = false;
  // kalau punya heuristik lain, tambahkan di sini:
  // bool highEntropy=false, macroPresent=false, hasJavascript=false, suspiciousImports=false, packedUPX=false;
};

// ====== Deklarasi fungsi yang diimplementasikan di TU lain ======
void logEvent(const std::string& rootScanId,
              const std::string& eventType,
              const std::map<std::string,std::string>& kv);

bool safeQuarantine(const std::filesystem::path& src,
                    const std::filesystem::path& quarantDir,
                    std::string& outNewPath,
                    std::string& err);

Severity scoreSeverity(const FileMeta& m, const DetectHints& h);
Action   chooseAction(Severity sev,
                      const PolicyContext& policy,
                      const std::string& extLower,
                      const DetectHints& h /*, const AppConfig& cfg */);
Action   applyAction(Action a, const std::filesystem::path& p, ScanContext& ctx);

// util (implementasi real ada di tempat lain; kalau belum, bikin stub sederhana)
std::string computeHash(const std::filesystem::path& p, const char* algo);

// stringify kecil
static inline const char* toString(Severity s){
  switch (s) { case Severity::Low: return "low";
               case Severity::Medium: return "medium";
               case Severity::High: return "high";
               case Severity::Critical: return "critical"; }
  return "low";
}
static inline const char* toString(Action a){
  switch (a) { case Action::Simulate: return "simulate";
               case Action::Rename: return "rename";
               case Action::Quarantine: return "quarantine";
               case Action::Delete: return "delete";
               case Action::Skip: return "skip";
               default: return "error"; }
}

// ====== Helpers lokal ======
static bool exceedsDeadline(const std::chrono::steady_clock::time_point& start, uint32_t ms){
  return (std::chrono::steady_clock::now() - start) > std::chrono::milliseconds(ms);
}

static bool violatesSizeBudget(uint64_t add, uint64_t& total, uint64_t maxTotal){
  if (add > maxTotal) return true;
  if (total > (maxTotal - add)) return true; // cegah overflow
  total += add;
  return false;
}

// deteksi zip-bomb via rasio ekspansi
static bool isZipBombRatio(uint64_t unpackedSize, uint64_t packedSize, double maxRatio){
  if (packedSize == 0) return false; // versi longgar; kalau mau ketat, return true
  long double ratio = (long double)unpackedSize / (long double)packedSize;
  return ratio > (long double)maxRatio;
}

// guard zip-slip/path traversal
static bool isPathTraversal(const std::filesystem::path& base, const std::filesystem::path& target){
  std::error_code ec1, ec2;
  auto canonBase = std::filesystem::weakly_canonical(base, ec1);
  auto canonTgt  = std::filesystem::weakly_canonical(target, ec2);
  if (ec1 || ec2) {
    // fallback: perbandingan string biasa
    auto b = base.lexically_normal().native();
    auto t = target.lexically_normal().native();
    return t.rfind(b, 0) != 0;
  }
  return canonTgt.native().rfind(canonBase.native(), 0) != 0;
}

// ====== INTI: scanArchive ======
Action scanArchive(const std::filesystem::path& absPath,
                   const std::string& parentNameInArchive,
                   ScanContext& ctx,
                   Severity& outSeverity)
{
  outSeverity = Severity::Low;
  const auto start = std::chrono::steady_clock::now();

  if (!std::filesystem::exists(absPath)) {
    logEvent(ctx.rootScanId, "error", {{"where","scanArchive"},{"msg","file_not_found"},{"path",absPath.string()}});
    return Action::Error;
  }

  const uint64_t packedSize = std::filesystem::file_size(absPath);

  // batas arsip & depth
  if (packedSize > ctx.limits.maxArchiveSize) {
    logEvent(ctx.rootScanId, "violation", {{"type","archive_too_large"},{"size",std::to_string(packedSize)}});
    outSeverity = Severity::High;
    return Action::Quarantine;
  }
  if (ctx.depth > ctx.limits.maxDepth) {
    logEvent(ctx.rootScanId, "violation", {{"type","depth_exceeded"},{"depth",std::to_string(ctx.depth)}});
    outSeverity = Severity::High;
    return Action::Quarantine;
  }

  // Router → sekarang kita handle ZIP dulu
  RoutingDecision rd = routeToHandler(absPath);
  if (rd.handler != "zip") {
    // bukan arsip/supported di fase ini → serahkan ke parent
    return Action::Simulate;
  }

  // Buka reader ZIP
  std::string err;
  auto reader = wntx::makeZipReader();
  if (!reader || !reader->open(absPath, err)) {
    logEvent(ctx.rootScanId, "error", {{"where","zip_open"},{"msg",err},{"path",absPath.string()}});
    outSeverity = Severity::Medium;
    return Action::Quarantine;
  }

  uint64_t localUnpackedSum = 0;
  uint32_t childrenCount = 0;
  bool bombFlagged = false;

  while (true) {
    if (childrenCount >= ctx.limits.maxChildrenPerNode) { bombFlagged = true; break; }
    if (exceedsDeadline(start, ctx.limits.timeoutArchiveMs)) { bombFlagged = true; break; }

    EntryInfo ei{};
    if (!reader->nextEntry(ei, err)) {
      if (!err.empty()) logEvent(ctx.rootScanId, "error", {{"where","nextEntry"},{"msg",err}});
      break; // selesai / error ringan
    }
    childrenCount++;

    // ===== Opsi A: kalau entry TERENKRIPSI → tandai bahaya & hentikan arsip =====
    if (ei.isEncrypted) {
      logEvent(ctx.rootScanId, "encrypted_entry", {{"entry", ei.name}});
      outSeverity = std::max(outSeverity, Severity::High);
      bombFlagged = true;
      // majukan index agar tidak loop (ekstrak dummy; ZipReader kita selalu idx_++ di semua jalur)
      std::filesystem::path tmpOut = (ctx.tempDir / ctx.rootScanId / std::to_string(ctx.depth)) / ei.name;
      (void)reader->extractToTemp(ei, tmpOut, err);
      break;
    }

    // Siapkan path tujuan
    std::filesystem::path dstBase = ctx.tempDir / ctx.rootScanId / std::to_string(ctx.depth);
    std::error_code ec; std::filesystem::create_directories(dstBase, ec);
    std::filesystem::path outFile = dstBase / ei.name;

    // symlink guard
    if (ei.isSymlink && !ctx.limits.allowSymlink) {
      logEvent(ctx.rootScanId, "skip", {{"entry", ei.name},{"reason","symlink"}});
      (void)reader->extractToTemp(ei, outFile, err); // advance index
      continue;
    }

    // direktori → buat & lanjut
    if (ei.isDir) {
      (void)reader->extractToTemp(ei, outFile, err); // advance index
      continue;
    }

    // batas ukuran single file
    if (ei.size > ctx.limits.maxSingleFile) {
      logEvent(ctx.rootScanId, "violation", {{"entry", ei.name},{"type","single_file_too_large"},{"size",std::to_string(ei.size)}});
      outSeverity = std::max(outSeverity, Severity::High);
      bombFlagged = true;
      (void)reader->extractToTemp(ei, outFile, err); // advance index
      continue;
    }

    // budget global (sebelum ekstrak)
    if (violatesSizeBudget(ei.size, ctx.totalUnpacked, ctx.limits.maxTotalUnpacked)) {
      logEvent(ctx.rootScanId, "violation", {{"type","unpacked_budget_exceeded"}});
      outSeverity = std::max(outSeverity, Severity::High);
      bombFlagged = true;
      break;
    }

    // path traversal guard
    if (ctx.limits.preventPathTraversal && isPathTraversal(dstBase, outFile)) {
      logEvent(ctx.rootScanId, "violation", {{"entry", ei.name},{"type","path_traversal"}});
      outSeverity = std::max(outSeverity, Severity::High);
      (void)reader->extractToTemp(ei, outFile, err); // advance index
      continue;
    }

    // ===== Ekstrak file =====
    if (!reader->extractToTemp(ei, outFile, err)) {
      logEvent(ctx.rootScanId, "error", {{"where","extract"},{"entry", ei.name},{"msg",err}});
      outSeverity = std::max(outSeverity, Severity::Medium);
      continue;
    }

    // akumulasi untuk rasio zip-bomb arsip ini
    localUnpackedSum += ei.size;

    // ===== Analisis file anak (panjang) =====
    FileMeta meta;
    meta.absPath        = outFile;
    meta.nameInArchive  = parentNameInArchive.empty() ? ei.name
                        : (parentNameInArchive + ">" + ei.name);
    meta.sizeOnDisk     = ei.size;

    // (opsional sesuai telemetry) hash
    meta.sha256         = computeHash(outFile, "sha256");

    DetectHints hints{};
    // routing anak → tahu apakah ini arsip lagi
    auto childRd = routeToHandler(outFile);
    if (!childRd.handler.empty()) hints.isArchive = true;

    // (opsional) isi heuristik tambahan ke hints.* di sini

    // scoring severity per-file
    Severity childSev = scoreSeverity(meta, hints);

    // rekursi ke anak arsip (saat ini: ZIP saja)
    if (childRd.handler == "zip" && (ctx.depth + 1) <= ctx.limits.maxDepth) {
      ctx.depth++;
      Severity nestedSev = Severity::Low;
      Action nestedAct = scanArchive(outFile, meta.nameInArchive, ctx, nestedSev);
      ctx.depth--;
      (void)nestedAct;
      childSev = std::max(childSev, nestedSev);
    }

    // pilih aksi per policy + format
    std::string extLower = outFile.extension().string();
    if (!extLower.empty() && extLower[0]=='.') extLower.erase(0,1);
    std::transform(extLower.begin(), extLower.end(), extLower.begin(),
                   [](unsigned char c){ return (char)std::tolower(c); });

    Action act = chooseAction(childSev, ctx.policy, extLower, hints /*, cfg*/);
    applyAction(act, outFile, ctx);

    // logging anak
    logEvent(ctx.rootScanId, "child",
      { {"entry", meta.nameInArchive},
        {"sha256", meta.sha256},
        {"size", std::to_string(meta.sizeOnDisk)},
        {"severity", toString(childSev)},
        {"action", toString(act)} });

    // eskalasi severity parent
    outSeverity = std::max(outSeverity, childSev);

    // timeout per-arsip
    if (exceedsDeadline(start, ctx.limits.timeoutArchiveMs)) {
      logEvent(ctx.rootScanId, "timeout", {{"scope","archive"},{"ms",std::to_string(ctx.limits.timeoutArchiveMs)}});
      outSeverity = std::max(outSeverity, Severity::High);
      bombFlagged = true;
      break;
    }
  }

  reader->close();

  // ===== Ratio-check zip-bomb (akhir loop) =====
  if (isZipBombRatio(localUnpackedSum, packedSize, ctx.limits.maxExpansionRatio)) {
    logEvent(ctx.rootScanId, "violation",
      {{"type","expansion_ratio"},{"packed",std::to_string(packedSize)},{"unpacked",std::to_string(localUnpackedSum)}});
    outSeverity = std::max(outSeverity, Severity::High);
    bombFlagged = true;
  }

  if (bombFlagged) {
    // karantina arsip induk
    std::string qpath, qerr;
    if (safeQuarantine(absPath, ctx.quarantineDir, qpath, qerr)) {
      logEvent(ctx.rootScanId, "quarantine_parent", {{"path", absPath.string()}, {"to", qpath}});
      return Action::Quarantine;
    } else {
      logEvent(ctx.rootScanId, "error", {{"where","quarantine_parent"},{"msg", qerr}});
      return Action::Error;
    }
  }

  return Action::Simulate;
}

} // namespace wntx
