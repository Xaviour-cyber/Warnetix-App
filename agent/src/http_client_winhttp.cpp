// src/http_client_winhttp.cpp
#include "http_client.h"
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

static bool crack(const std::wstring& url, URL_COMPONENTS& uc,
                  std::wstring& host, INTERNET_PORT& port,
                  std::wstring& path, bool& https)
{
  memset(&uc, 0, sizeof(uc));
  uc.dwStructSize = sizeof(uc);
  wchar_t hostBuf[1024]; wchar_t pathBuf[4096];
  uc.lpszHostName = hostBuf; uc.dwHostNameLength = 1024;
  uc.lpszUrlPath  = pathBuf; uc.dwUrlPathLength  = 4096;
  if (!WinHttpCrackUrl(url.c_str(), (DWORD)url.size(), 0, &uc)) return false;
  host.assign(uc.lpszHostName, uc.dwHostNameLength);
  path.assign(uc.lpszUrlPath,  uc.dwUrlPathLength);
  port  = uc.nPort;
  https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
  return true;
}

bool http_post_json(const std::wstring& url,
                    const std::string& body,
                    const std::wstring& token,
                    unsigned long* httpStatusOut,
                    std::string* responseBodyOut)
{
  std::wstring host, path; INTERNET_PORT port; URL_COMPONENTS uc; bool https=false;
  if (!crack(url, uc, host, port, path, https)) return false;

  HINTERNET hSes = WinHttpOpen(L"WarnetixAgent/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSes) return false;

  HINTERNET hCon = WinHttpConnect(hSes, host.c_str(), port, 0);
  if (!hCon) { WinHttpCloseHandle(hSes); return false; }

  HINTERNET hReq = WinHttpOpenRequest(hCon, L"POST", path.c_str(),
                                      nullptr, WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES,
                                      https ? WINHTTP_FLAG_SECURE : 0);
  if (!hReq) { WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return false; }

  std::wstring headers = L"Content-Type: application/json\r\n";
  if (!token.empty()) headers += L"X-Agent-Token: " + token + L"\r\n";

  BOOL ok = WinHttpSendRequest(hReq,
      headers.c_str(), (DWORD)headers.size(),
      (LPVOID)body.data(), (DWORD)body.size(),
      (DWORD)body.size(), 0);

  if (!ok) { WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return false; }

  ok = WinHttpReceiveResponse(hReq, nullptr);
  if (!ok) { WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return false; }

  DWORD status=0, len=sizeof(status);
  WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,
                      WINHTTP_HEADER_NAME_BY_INDEX, &status, &len, WINHTTP_NO_HEADER_INDEX);
  if (httpStatusOut) *httpStatusOut = status;

  if (responseBodyOut) {
    std::string resp;
    DWORD avail=0;
    do {
      if (!WinHttpQueryDataAvailable(hReq, &avail)) break;
      if (avail == 0) break;
      std::string chunk; chunk.resize(avail);
      DWORD read=0; if (!WinHttpReadData(hReq, chunk.data(), avail, &read)) break;
      chunk.resize(read); resp += chunk;
    } while (avail > 0);
    *responseBodyOut = resp;
  }

  WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
  return true;
}
