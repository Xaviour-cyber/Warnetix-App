#pragma once
#include "types.hpp"
#include <string>

namespace wntx {

struct EngineConfig {
  std::string logsDir;
  std::string actionLow = "simulate";
  std::string actionMedium = "rename";
  std::string actionHigh = "quarantine";
  std::string actionCritical = "delete";
  Severity policyMin = Severity::Medium;
  std::string tempDir;
  std::string quarantineDir;
  // NOTE: mapping/routing & overrides bisa ditaruh di class lain jika perlu
};

struct AppConfig {
  EngineConfig engine;
  Limits limits;
  // routing/handlers/policy overrides: TODO
};

bool loadConfigYaml(const std::string& path, AppConfig& outCfg, std::string& err);

} // namespace wntx
