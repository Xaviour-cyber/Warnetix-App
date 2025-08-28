#pragma once
#include <string>
#include <filesystem>

namespace wntx {

struct RoutingDecision {
  std::string handler; // "zip", "seven_zip", "pdf", ...
  std::string reason;  // "magic" / "ext"
};

RoutingDecision routeToHandler(const std::filesystem::path& path);

} // namespace wntx
