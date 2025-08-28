// src/json_min.cpp
#include "json_min.h"
#include <windows.h>

static std::string to_utf8(const wchar_t* ws, int wlen) {
  if (wlen <= 0) return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, ws, wlen, nullptr, 0, nullptr, nullptr);
  std::string out(n, '\0');
  WideCharToMultiByte(CP_UTF8, 0, ws, wlen, out.data(), n, nullptr, nullptr);
  return out;
}

std::string utf8(const std::wstring& ws) { return to_utf8(ws.c_str(), (int)ws.size()); }

std::string jsonEscape(const std::string& s) {
  std::string out; out.reserve(s.size() + 16);
  for (char c : s) {
    switch (c) {
      case '\"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b";  break;
      case '\f': out += "\\f";  break;
      case '\n': out += "\\n";  break;
      case '\r': out += "\\r";  break;
      case '\t': out += "\\t";  break;
      default:
        if ((unsigned char)c < 0x20) {
          char buf[7]; sprintf_s(buf, "\\u%04x", (unsigned char)c);
          out += buf;
        } else out += c;
    }
  }
  return out;
}

std::string jsonEscapeW(const std::wstring& ws) { return jsonEscape(utf8(ws)); }
// jsonEscapeW converts wide string to UTF-8 and escapes it for JSON.