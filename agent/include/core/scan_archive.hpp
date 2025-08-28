#pragma once
#include "core/types.hpp"
#include <filesystem>

namespace wntx {
Action scanArchive(const std::filesystem::path& absPath,
                   const std::string& parentNameInArchive,
                   ScanContext& ctx,
                   Severity& outSeverity);
} // namespace wntx
