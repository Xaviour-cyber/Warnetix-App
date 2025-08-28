#pragma once
#include <string>
#include <filesystem>
#include <memory>

namespace wntx {

// Data satu entry dalam arsip (keluaran dari nextEntry)
struct EntryInfo {
  std::string name;
  uint64_t    size = 0;
  bool        isDir = false;
  bool        isSymlink = false;
  bool        isEncrypted = false;
};

class IArchiveReader {
public:
  virtual ~IArchiveReader() = default;

  // Buka arsip
  virtual bool open(const std::filesystem::path& path, std::string& err) = 0;

  // >>> PEMANGGILAN YANG KITA PAKAI <<< 
  // Ambil info entry saat ini ke 'out'. 
  // return false jika sudah habis / error ringan (cek 'err' kalau ada).
  virtual bool nextEntry(EntryInfo& out, std::string& err) = 0;

  // Ekstrak entry (yang barusan di-nextEntry) ke 'dst'.
  // Implementasi bebas, tapi bagusnya di sini juga sekalian majukan index internal.
  virtual bool extractToTemp(const EntryInfo& e, const std::filesystem::path& dst, std::string& err) = 0;

  // Tutup arsip
  virtual void close() = 0;
};

// Factory minimal untuk ZIP (biar simpel dulu)
std::unique_ptr<IArchiveReader> makeZipReader();

} // namespace wntx
