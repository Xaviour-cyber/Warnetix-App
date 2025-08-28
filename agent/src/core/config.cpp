#include "core/config.hpp"
#include <yaml-cpp/yaml.h>

using namespace wntx;

static Severity parseSeverity(const std::string& s) {
  if (s=="low") return Severity::Low;
  if (s=="medium") return Severity::Medium;
  if (s=="high") return Severity::High;
  if (s=="critical") return Severity::Critical;
  return Severity::Medium;
}

bool loadConfigYaml(const std::string& path, AppConfig& outCfg, std::string& err) {
  try {
    YAML::Node root = YAML::LoadFile(path);
    auto eng = root["engine"];
    if (eng) {
      outCfg.engine.tempDir = eng["temp_dir"].as<std::string>("");
      outCfg.engine.quarantineDir = eng["quarantine_dir"].as<std::string>("");
      outCfg.engine.logsDir = eng["logs_dir"].as<std::string>("");
      outCfg.engine.policyMin = parseSeverity(eng["policy_min"].as<std::string>("medium"));
      auto mat = eng["action_matrix"];
      if (mat) {
        outCfg.engine.actionLow      = mat["low"].as<std::string>("simulate");
        outCfg.engine.actionMedium   = mat["medium"].as<std::string>("rename");
        outCfg.engine.actionHigh     = mat["high"].as<std::string>("quarantine");
        outCfg.engine.actionCritical = mat["critical"].as<std::string>("delete");
      }
    }
    auto lim = root["limits"];
    if (lim) {
      if (auto r=lim["recursion"]) {
        outCfg.limits.maxDepth = r["max_depth"].as<uint32_t>(4);
        outCfg.limits.maxChildrenPerNode = r["max_children_per_node"].as<uint32_t>(20000);
      }
      if (auto s=lim["size"]) {
        outCfg.limits.maxArchiveSize = s["max_archive_size_bytes"].as<uint64_t>(1ull<<30);
        outCfg.limits.maxTotalUnpacked = s["max_total_unpacked_bytes"].as<uint64_t>(4ull<<30);
        outCfg.limits.maxSingleFile = s["max_single_file_bytes"].as<uint64_t>(512ull<<20);
      }
      if (auto zb=lim["zip_bomb"]) {
        outCfg.limits.maxExpansionRatio = zb["max_expansion_ratio"].as<double>(1000.0);
      }
      if (auto t=lim["timeouts"]) {
        outCfg.limits.timeoutArchiveMs = t["per_archive_ms"].as<uint32_t>(20000);
        outCfg.limits.timeoutFileMs = t["per_file_ms"].as<uint32_t>(5000);
      }
      if (auto fs=lim["fs_safety"]) {
        outCfg.limits.allowSymlink = fs["allow_symlink"].as<bool>(false);
        outCfg.limits.preventPathTraversal = fs["prevent_path_traversal"].as<bool>(true);
        outCfg.limits.allowAbsolutePaths = fs["allow_absolute_paths"].as<bool>(false);
        outCfg.limits.followJunctions = fs["follow_junctions"].as<bool>(false);
      }
    }
    return true;
  } catch (const std::exception& ex) {
    err = ex.what();
    return false;
  }
}
