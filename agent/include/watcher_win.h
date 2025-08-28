// include/watcher_win.h
#pragma once
#include <string>
#include <functional>

using FileEventCallback = std::function<void(const std::wstring& fullPath, bool created, bool modified)>;

// spawn thread: watch one dir (recursively if recursive=true). returns false if fail.
bool watch_directory_thread(const std::wstring& dir, bool recursive, FileEventCallback cb);
// watch_directory_thread starts a thread to monitor a directory for file changes.