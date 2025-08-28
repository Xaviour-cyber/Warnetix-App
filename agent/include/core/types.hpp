#pragma once
#include <string>
#include <filesystem>
#include <cstdint>

namespace wntx {

enum class Severity { Low=0, Medium=1, High=2, Critical=3 };
enum class Action   { Simulate, Rename, Quarantine, Delete, Skip, Error };

struct Limits {
  uint32_t maxDepth = 4;
  uint32_t maxChildrenPerNode = 20000;
  uint64_t maxArchiveSize = 1ull<<30;       // 1 GiB
  uint64_t maxTotalUnpacked = 4ull<<30;     // 4 GiB
  uint64_t maxSingleFile = 512ull<<20;      // 512 MiB
  double   maxExpansionRatio = 1000.0;
  uint32_t timeoutArchiveMs = 20000;
  uint32_t timeoutFileMs = 5000;
  bool     allowSymlink = false;
  bool     preventPathTraversal = true;
  bool     allowAbsolutePaths = false;
  bool     followJunctions = false;
};

struct PolicyContext {
  Severity policyMinGlobal = Severity::Medium;
  // TODO: load overrides per-ext dari config
};

struct ScanContext {
  Limits limits;
  PolicyContext policy;
  std::filesystem::path tempDir;
  std::filesystem::path quarantineDir;
  std::string rootScanId;
  uint32_t depth = 0;
  uint64_t totalUnpacked = 0;
};

} // namespace wntx
// types.hpp defines core types for the agent, including severity levels, actions, and scanning limits.