// include/hash_sha256.h
#pragma once
#include <string>
#include <vector>

std::string sha256_bytes(const std::vector<unsigned char>& data);
std::string sha256_file(const std::wstring& path, size_t chunk = 1<<20); // 1MB chunk
std::string sha256_string(const std::string& str);