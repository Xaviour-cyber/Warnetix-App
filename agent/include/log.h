#pragma once
#include <windows.h>
#include <string>

inline void _log_emit(const wchar_t* lvl, const std::wstring& msg){
  SYSTEMTIME st; GetLocalTime(&st);
  wchar_t line[1600];
  _snwprintf_s(line, _TRUNCATE, L"[%s] %04d-%02d-%02d %02d:%02d:%02d | %s",
    lvl, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg.c_str());
  OutputDebugStringW(line);
  wprintf(L"%s\n", line);
}

#define LOGI(m) _log_emit(L"INFO ", (m))
#define LOGW(m) _log_emit(L"WARN ", (m))
#define LOGE(m) _log_emit(L"ERROR", (m))
// entropy_8bit calculates the Shannon entropy of a byte buffer.