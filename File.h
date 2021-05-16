#ifndef CRYPTO_FILE_H_19741129
#define CRYPTO_FILE_H_19741129

#include "Common.h"

class AutoHandle
{
    HANDLE m_h;
public:
    bool valid() const
    {
        return m_h != INVALID_HANDLE_VALUE && m_h != nullptr;
    }
    explicit AutoHandle(HANDLE h = INVALID_HANDLE_VALUE) : m_h(h) {}
    ~AutoHandle()
    {
        if (valid()) {
            CloseHandle(m_h);
        }
    }

    HANDLE detach()
    {
        HANDLE h = m_h;
        m_h = INVALID_HANDLE_VALUE;
        return h;
    }

    operator HANDLE() { return m_h; }

    bool operator==(HANDLE h) const
    {
        return m_h == h;
    }
    bool operator!=(HANDLE h) const
    {
        return m_h != h;
    }
};

class MappingFileHandle
{
    enum {DEFAULT_FILE_SIZE = 1UL * 1024 * 1024 * 1024}; // 1GB
    HANDLE m_hFile;
    HANDLE m_hMapFile;
    void * m_pMapAddress;
    size_t m_size;
    bool m_readonly;
public:
    MappingFileHandle(const TCHAR * file, bool readonly, size_t default_size = DEFAULT_FILE_SIZE) :
        m_hFile(INVALID_HANDLE_VALUE),
        m_hMapFile(INVALID_HANDLE_VALUE),
        m_pMapAddress(nullptr),
        m_size(0),
        m_readonly(readonly)
    {
        DWORD dwDesiredAccess = GENERIC_READ;
        DWORD dwShareMode = FILE_SHARE_READ;
        DWORD dwCreationDisposition = OPEN_EXISTING;
        DWORD dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
        if (!readonly) {
            dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
            dwShareMode = 0;
            dwCreationDisposition = CREATE_ALWAYS;
        }
        TCHAR objName[] = _T("CryptoShared");

        AutoHandle hFile(
            CreateFile(
                file,
                dwDesiredAccess,
                dwShareMode,
                nullptr,
                dwCreationDisposition,
                dwFlagsAndAttributes,
                nullptr
            )
        );
        if (hFile.valid()) {
            DWORD dwProtect = PAGE_READONLY;
            DWORD dwNumberOfBytesToMap = 0;
            LARGE_INTEGER size = {0};
            if (readonly) {
                GetFileSizeEx(hFile, &size);
                m_size = static_cast<size_t>(size.QuadPart);
                dwNumberOfBytesToMap = size.LowPart;
                size.LowPart = size.HighPart = 0;
            } else {
                dwProtect = PAGE_READWRITE;
            /*
            #ifdef _WIN32
                size.LowPart = 1024 * 1024 * 1024;
            #else
                size.LowPart = UINT_MAX;
            #endif
            */
                size.LowPart = static_cast<DWORD>(default_size);
            }
            AutoHandle hMapFile(
                CreateFileMapping(
                    hFile,
                    nullptr,
                    dwProtect,
                    size.HighPart,
                    size.LowPart,
                    objName
                )
            );
            if (hMapFile.valid()) {
                dwDesiredAccess = FILE_MAP_READ;
                if (!readonly) {
                    dwDesiredAccess |= FILE_MAP_WRITE;
                }
                void * p = MapViewOfFile(
                    hMapFile,
                    dwDesiredAccess,
                    0,
                    0,
                    dwNumberOfBytesToMap
                );
                if (p != nullptr) {
                    m_hFile = hFile.detach();
                    m_hMapFile = hMapFile.detach();
                    m_pMapAddress = p;
                    return;
                }
            }
        }
        throw Exception(GetLastError());
    }

    size_t size() const { return m_size; }
    void set_size(size_t n) { m_size = n; }
    uint8_t * c_ptr() { return static_cast<uint8_t*>(m_pMapAddress); }

    void close(bool can_throw_exception = true)
    {
        std::vector<DWORD> errors;
        if (m_pMapAddress != nullptr) {
            if (!m_readonly) {
                if (!FlushViewOfFile(m_pMapAddress, m_size)) {
                    DWORD err = GetLastError();
                    errors.push_back(err);
                }
            }
            if (!UnmapViewOfFile(m_pMapAddress)) {
                DWORD err = GetLastError();
                errors.push_back(err);
            }
            m_pMapAddress = nullptr;
        }
        if (m_hMapFile != INVALID_HANDLE_VALUE) {
            if (!CloseHandle(m_hMapFile)) {
                DWORD err = GetLastError();
                errors.push_back(err);
            }
            m_hMapFile = INVALID_HANDLE_VALUE;
        }
        if (m_hFile != INVALID_HANDLE_VALUE) {
            if (!m_readonly) {
                LARGE_INTEGER newSize;
                newSize.QuadPart = static_cast<LONGLONG>(m_size);
                if (!SetFilePointerEx(m_hFile, newSize, nullptr, FILE_BEGIN)) {
                    DWORD err = GetLastError();
                    errors.push_back(err);
                }
                if (!SetEndOfFile(m_hFile)) {
                    DWORD err = GetLastError();
                    errors.push_back(err);
                }
            }
            if (!CloseHandle(m_hFile)) {
                DWORD err = GetLastError();
                errors.push_back(err);
            }
            m_hFile = INVALID_HANDLE_VALUE;
        }
        if (can_throw_exception && !errors.empty()) {
            std::basic_string<TCHAR> buf;
            for (DWORD err : errors) {
                auto msg = strerror(err);
                if (!buf.empty()) {
                    buf.append(_T("\r\n"));
                }
                buf.append(msg.c_str());
            }
            throw Exception(buf.c_str());
        }
    }

    ~MappingFileHandle()
    {
        close(false);
    }
};

class File
{
    FILE * m_pf;
public:
    File(const TCHAR * name, const TCHAR * mode)
    {
        _tfopen_s(&m_pf, name, mode);
        if (m_pf == nullptr) {
            throw Exception(ERROR_OPEN_FAILED);
        }
    }
    void write(const uint8_t * input, size_t n)
    {
        while (true) {
            size_t c = fwrite(input, sizeof(input[0]), n, m_pf);
            if (c == n) {
                break;
            } else {
                input += c;
                n -= c;
            }
        }
    }
    size_t read(uint8_t * output, size_t n)
    {
        size_t count = 0;
        while (true) {
            size_t r = fread(output, sizeof(output[0]), n, m_pf);
            count += r;
            if (r == n || feof(m_pf)) {
                break;
            } else {
                output += r;
                n -= r;
            }
        }
        return count;
    }
    ~File()
    {
        fclose(m_pf);
    }
};

size_t get_file_size(const TCHAR * file);
bool is_file(const TCHAR * name);
bool is_folder(const TCHAR * name);
std::basic_string<TCHAR> dirname(const TCHAR * path);
void move_file(const TCHAR * from, const TCHAR * to);
void remove_directory(const TCHAR * name, bool ignore_error = true);
void create_directory(const TCHAR * name);

#endif //CRYPTO_FILE_H_19741129
