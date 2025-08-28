#pragma once
#include <string>
#include <vector>

struct AgentConfig {
  std::wstring apiUrl;
  std::wstring token;
  std::wstring quarantineDir;
  std::wstring policyMode;     // simulate | rename | quarantine
  std::wstring policyMin;      // low | medium | high | critical
  bool recursive = true;

  std::vector<std::wstring> watchPaths;

  // retry + spool
  std::wstring spoolDir = L"agent_spool";
  int minBackoffMs = 500;
  int maxBackoffMs = 15000;

  // heuristik
  double entropyHigh = 7.20;
};

AgentConfig loadConfigFromEnv();
void addDefaultUserDirs(AgentConfig& cfg);
#include "agent_config.h"