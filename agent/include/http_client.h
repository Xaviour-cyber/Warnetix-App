// include/http_client.h
#pragma once
#include <string>
#include <map>

bool http_post_json(const std::wstring& url,
                    const std::string& jsonUtf8,
                    const std::wstring& token, // empty -> no header
                    unsigned long* httpStatusOut = nullptr,
                    std::string* responseBodyOut = nullptr);
// http_post_json sends a JSON payload to the specified URL with optional token.