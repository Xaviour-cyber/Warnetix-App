// src/hash_sha256.cpp
#include "hash_sha256.h"
#include <windows.h>
#include <fstream>
#include <sstream>
#ifdef HAVE_OPENSSL
  #include <openssl/sha.h>
#else
  #include <bcrypt.h>
  #pragma comment(lib, "bcrypt.lib")
#endif

static std::string hex(const unsigned char* d, size_t n) {
  static const char* he = "0123456789abcdef";
  std::string s; s.resize(n*2);
  for (size_t i=0;i<n;++i){ s[2*i]=he[d[i]>>4]; s[2*i+1]=he[d[i]&0xF]; }
  return s;
}

std::string sha256_bytes(const std::vector<unsigned char>& data) {
#ifdef HAVE_OPENSSL
  unsigned char md[SHA256_DIGEST_LENGTH];
  SHA256(data.data(), data.size(), md);
  return hex(md, sizeof(md));
#else
  BCRYPT_ALG_HANDLE hAlg = nullptr; BCRYPT_HASH_HANDLE hHash = nullptr;
  NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
  if (st < 0) return "";
  DWORD objLen=0,res=0; BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &res, 0);
  std::vector<UCHAR> obj(objLen);
  DWORD dlen=0; BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&dlen, sizeof(dlen), &res, 0);
  std::vector<UCHAR> hash(dlen);
  BCryptCreateHash(hAlg, &hHash, obj.data(), objLen, nullptr, 0, 0);
  BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
  BCryptFinishHash(hHash, hash.data(), dlen, 0);
  if (hHash) BCryptDestroyHash(hHash);
  if (hAlg) BCryptCloseAlgorithmProvider(hAlg,0);
  return hex(hash.data(), dlen);
#endif
}

std::string sha256_file(const std::wstring& path, size_t chunk) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return "";
#ifdef HAVE_OPENSSL
  SHA256_CTX ctx; SHA256_Init(&ctx);
  std::vector<unsigned char> buf; buf.resize(chunk);
  while (f) {
    f.read((char*)buf.data(), buf.size());
    std::streamsize got = f.gcount();
    if (got>0) SHA256_Update(&ctx, buf.data(), (size_t)got);
  }
  unsigned char md[SHA256_DIGEST_LENGTH]; SHA256_Final(md, &ctx);
  return hex(md, sizeof(md));
#else
  BCRYPT_ALG_HANDLE hAlg=nullptr; BCRYPT_HASH_HANDLE hHash=nullptr;
  NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
  if (st < 0) return "";
  DWORD objLen=0,res=0; BCryptGetProperty(hAlg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&objLen,sizeof(objLen),&res,0);
  std::vector<UCHAR> obj(objLen);
  DWORD dlen=0; BCryptGetProperty(hAlg,BCRYPT_HASH_LENGTH,(PUCHAR)&dlen,sizeof(dlen),&res,0);
  std::vector<UCHAR> hash(dlen);
  BCryptCreateHash(hAlg,&hHash,obj.data(),objLen,nullptr,0,0);

  std::vector<unsigned char> buf; buf.resize(chunk);
  while (f) {
    f.read((char*)buf.data(), buf.size());
    std::streamsize got = f.gcount();
    if (got>0) BCryptHashData(hHash,(PUCHAR)buf.data(),(ULONG)got,0);
  }
  BCryptFinishHash(hHash, hash.data(), dlen, 0);
  if (hHash) BCryptDestroyHash(hHash);
  if (hAlg) BCryptCloseAlgorithmProvider(hAlg,0);
  return hex(hash.data(), dlen);
#endif
}
