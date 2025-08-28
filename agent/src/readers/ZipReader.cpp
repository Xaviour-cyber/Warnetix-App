#include "readers/IArchiveReader.hpp"
#include <zip.h>
#include <vector>
#include <cstdio>
#include <filesystem>

namespace wntx {

class ZipReader : public IArchiveReader {
  zip_t* z_ = nullptr;
  zip_int64_t idx_ = 0;          // index entry saat ini
  zip_int64_t total_ = 0;        // jumlah entry

public:
  bool open(const std::filesystem::path& path, std::string& err) override {
    int ze = 0;
    z_ = zip_open(path.string().c_str(), ZIP_RDONLY, &ze);
    if (!z_) { err = "zip_open failed code=" + std::to_string(ze); return false; }
    total_ = zip_get_num_entries(z_, 0);
    idx_   = 0;
    return true;
  }

  bool nextEntry(EntryInfo& out, std::string& err) override {
    if (!z_) { err = "zip not open"; return false; }
    if (idx_ >= total_) return false; // sudah habis

    zip_stat_t st; zip_stat_init(&st);
    if (zip_stat_index(z_, idx_, 0, &st) != 0) { err = "zip_stat_index failed"; return false; }

    out.name      = st.name ? st.name : "";
    out.size      = static_cast<uint64_t>(st.size);
    out.isDir     = (!out.name.empty() && out.name.back() == '/');
    out.isSymlink = false;

    // Tandai terenkripsi (opsional, tergantung build libzip)
    out.isEncrypted = false;
#ifdef ZIP_STAT_ENCRYPTION_METHOD
    if ((st.valid & ZIP_STAT_ENCRYPTION_METHOD) && st.encryption_method != ZIP_EM_NONE) {
      out.isEncrypted = true;
    }
#endif
    return true; // NOTE: idx_ belum maju; majunya saat extractToTemp
  }

  bool extractToTemp(const EntryInfo& e, const std::filesystem::path& dst, std::string& err) override {
    if (!z_) { err = "zip not open"; return false; }

    if (e.isDir) {
      std::error_code ec; std::filesystem::create_directories(dst, ec);
      idx_++;                                // maju walau hanya folder
      return true;
    }

    std::filesystem::create_directories(dst.parent_path());

    zip_file_t* zf = zip_fopen_index(z_, idx_, 0);
    if (!zf) {
      err = "zip_fopen_index failed";
      idx_++;                                // ⚠️ maju saat gagal supaya tidak loop
      return false;
    }

    FILE* fo = fopen(dst.string().c_str(), "wb");
    if (!fo) {
      zip_fclose(zf);
      err = "fopen failed";
      idx_++;                                // ⚠️ maju saat gagal supaya tidak loop
      return false;
    }

    std::vector<char> buf(1<<16);
    zip_int64_t n;
    while ((n = zip_fread(zf, buf.data(), buf.size())) > 0) {
      fwrite(buf.data(), 1, (size_t)n, fo);
    }
    fclose(fo);
    zip_fclose(zf);

    // (opsional) kalau n<0 → error baca; boleh hapus dst agar bersih

    idx_++;                                   // maju setelah sukses
    return true;
  }

  void close() override {
    if (z_) { zip_close(z_); z_ = nullptr; }
  }
};

std::unique_ptr<IArchiveReader> makeZipReader() {
  return std::make_unique<ZipReader>();
}

} // namespace wntx
