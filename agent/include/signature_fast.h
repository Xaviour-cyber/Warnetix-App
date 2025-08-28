#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct FastSigOut {
  double score = 0.0;      // 0..1
  std::string severity;    // low|medium|high|critical
  std::string reason;      // ringkasan
};

FastSigOut fast_signature_scan(const std::wstring& path,
                               const std::vector<uint8_t>& head,
                               double entropy,
                               uint64_t sizeBytes);
#include "agent_config.h"