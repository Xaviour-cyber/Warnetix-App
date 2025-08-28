// include/json_min.h
#pragma once
#include <string>

std::string jsonEscape(const std::string& s);
std::string jsonEscapeW(const std::wstring& ws); // wide -> utf8 + escape
std::string utf8(const std::wstring& ws);
