// src/watcher_win.cpp
#include "watcher_win.h"
#include <windows.h>
#include <vector>

struct ThreadCtx {
  std::wstring dir;
  bool recursive;
  FileEventCallback cb;
};

static DWORD WINAPI watcher_proc(LPVOID p) {
  auto* ctx = (ThreadCtx*)p;
  HANDLE hDir = CreateFileW(
      ctx->dir.c_str(),
      FILE_LIST_DIRECTORY,
      FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
      nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS,
      nullptr);
  if (hDir == INVALID_HANDLE_VALUE) return 1;

  std::vector<char> buf(64*1024);
  DWORD ret=0;
  while (true) {
    BOOL ok = ReadDirectoryChangesW(
      hDir, buf.data(), (DWORD)buf.size(), ctx->recursive,
      FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
      &ret, nullptr, nullptr);
    if (!ok) break;

    char* base = buf.data();
    for (;;) {
      FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)base;
      std::wstring name(fni->FileName, fni->FileNameLength/sizeof(WCHAR));
      std::wstring full = ctx->dir + L"\\" + name;
      bool created = (fni->Action == FILE_ACTION_ADDED || fni->Action == FILE_ACTION_RENAMED_NEW_NAME);
      bool modified = (fni->Action == FILE_ACTION_MODIFIED || fni->Action == FILE_ACTION_RENAMED_NEW_NAME);

      if (ctx->cb) ctx->cb(full, created, modified);
      if (fni->NextEntryOffset == 0) break;
      base += fni->NextEntryOffset;
    }
  }
  CloseHandle(hDir);
  delete ctx;
  return 0;
}

bool watch_directory_thread(const std::wstring& dir, bool recursive, FileEventCallback cb) {
  auto* ctx = new ThreadCtx{dir, recursive, cb};
  HANDLE th = CreateThread(nullptr, 0, watcher_proc, ctx, 0, nullptr);
  if (!th) { delete ctx; return false; }
  CloseHandle(th);
  return true;
}
