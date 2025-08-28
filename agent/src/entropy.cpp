// src/entropy.cpp
#include "entropy.h"
#include <cmath>

double entropy_8bit(const std::vector<uint8_t>& buf) {
  if (buf.empty()) return 0.0;
  double cnt[256] = {0};
  for (auto b : buf) cnt[b] += 1.0;
  double sum = (double)buf.size();
  double H = 0.0;
  for (int i = 0; i < 256; ++i) if (cnt[i] > 0) {
    double p = cnt[i] / sum; H -= p * std::log2(p);
  }
  return H;
}
// entropy_8bit calculates the Shannon entropy of a byte buffer.