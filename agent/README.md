# Warnetix Agent (Windows, C++)

## Build (MSVC + CMake)
```powershell
# opsional: install OpenSSL (untuk SHA256 yang lebih cepat)
# jika tidak ada, otomatis fallback ke Windows CNG/BCrypt

agent\scripts\build.ps1  # -> build\Release\warnetix_agent.exe
