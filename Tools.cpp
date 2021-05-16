#include "stdafx.h"
#include "Tools.h"
#include "File.h"
#include "Cipher.h"

/*
HKEY_CURRENT_USER
    |_Software
        |_Crypto
            |_me
                |_current
                    |_pbk -> value
                    |_pvk -> value
                |_archive
                    |_MD5(pbk)
                        |_pbk -> value
                        |_pvk -> value
            |_friends
                |_name -> pbk
            |_encryption
                |_dir -> value
            |_decryption
                |_dir -> value
*/
namespace
{
    const TCHAR * myself_subkey = _T("Software\\Crypto\\me\\current");
    const TCHAR * archive_subkey = _T("Software\\Crypto\\me\\archive");
    const TCHAR * friends_subkey = _T("Software\\Crypto\\friends");
    const TCHAR * public_key = _T("pbk");
    const TCHAR * private_key = _T("pvk");
    const TCHAR * pvk_password = _T("key");

    class BIOMem
    {
        BIO * m_bio;
    public:
        BIOMem() : m_bio(BIO_new(BIO_s_mem()))
        {
            if (m_bio == nullptr) {
                throw std::bad_alloc();
            }
        }
        operator BIO*() { return m_bio; }
        ~BIOMem()
        {
            BIO_free_all(m_bio);
        }
    };

    bool export_private_key(RSA * key_pair, char * password, std::string * output)
    {
        bool retval = false;
        try {
            BIOMem bio;
            EvpPkey key(key_pair);
            int len = static_cast<int>(strlen(password));
            int ret = PEM_write_bio_PKCS8PrivateKey(
                bio, key, EVP_aes_256_cbc(), password, len, nullptr, nullptr
            );
            len = BIO_pending(bio);
            if (ret != 0 && len > 0) {
                std::vector<char> buf(static_cast<size_t>(len) + 1, '\0');
                BIO_read(bio, &buf[0], len);
                *output = &buf[0];
                retval = true;
            }
        } catch (std::exception const&) {
        }
        return retval;
    }

    bool get_key(const TCHAR * subkey, const TCHAR * name, std::string * output)
    {
        bool retval = false;
        HKEY hkey;
        DWORD cbData = 0;
        LONG result = RegOpenKeyEx(
            HKEY_CURRENT_USER,
            subkey,
            0,
            KEY_READ,
            &hkey
        );
        if (result == ERROR_SUCCESS) {
            DWORD dwType = 0;
            result = RegQueryValueEx(
                hkey,
                name,
                nullptr,
                &dwType,
                nullptr,
                &cbData
            );
            if (result == ERROR_SUCCESS && cbData > 0) {
                std::vector<BYTE> buf(cbData + 1, 0);
                result = RegQueryValueEx(
                    hkey,
                    name,
                    nullptr,
                    &dwType,
                    &buf[0],
                    &cbData
                );
                if (result == ERROR_SUCCESS) {
                    *output = reinterpret_cast<char*>(&buf[0]);
                    retval = true;
                }
            }
            RegCloseKey(hkey);
        }
        return retval;
    }

    bool get_key(const TCHAR * name, std::string * output)
    {
        return get_key(myself_subkey, name, output);
    }

    std::string to_hex(const void * input, size_t bytes)
    {
        const BYTE * data = static_cast<const BYTE*>(input);
        std::vector<char> buf(bytes * 2 + 1, 0);
		for (size_t i = 0; i < bytes; ++i) {
			sprintf_s(&buf[i*2], 3, "%02x", data[i]);
        }
        return &buf[0];
    }

    uint8_t hex_char_to_oct(char c)
    {
        uint8_t retval = 0;
        if (isdigit(c)) {
            retval = static_cast<uint8_t>(c - '0');
        } else {
            if (c >= 'a' && c <= 'f') {
                retval = static_cast<uint8_t>(c - 'a') + 10;
            } else if (c >= 'A' && c <= 'F') {
                retval = static_cast<uint8_t>(c - 'A') + 10;
            }
        }
        return retval;
    }

    std::vector<uint8_t> to_bin(const char * hex_string)
    {
        size_t len = strlen(hex_string);
        std::vector<uint8_t> retval;
        retval.reserve(len);
        for (size_t i = 0, ie = len >> 1; i < ie; ++i, hex_string += 2) {
            retval.push_back(
                (hex_char_to_oct(hex_string[0]) << 4) |
                hex_char_to_oct(hex_string[1])
            );
        }
        return retval;
    }

    bool save_item(HKEY hkey, const TCHAR * name, const void * input, size_t size)
    {
        bool retval = true;
        if (input != nullptr && size > 0) {
            retval = RegSetValueEx(
                hkey,
                name,
                0,
                REG_BINARY,
                static_cast<const BYTE*>(input),
                static_cast<DWORD>(size)
            ) == ERROR_SUCCESS;
        };
        return retval;
    }

    bool save_key_pair(const TCHAR * subkey, const char * strPbk, size_t nPbk, const char * strPvk, size_t nPvk, const char * strKey, size_t nKey)
    {
        bool retval = false;

        HKEY hkey = nullptr;
        DWORD dwDisposition;
        LSTATUS status = RegCreateKeyEx(
            HKEY_CURRENT_USER,
            subkey,
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            nullptr,
            &hkey,
            &dwDisposition
        );
        if (status == ERROR_SUCCESS) {
            retval = save_item(hkey, public_key, strPbk, nPbk) && save_item(hkey, private_key, strPvk, nPvk) && save_item(hkey, pvk_password, strKey, nKey);
            RegCloseKey(hkey);
            if (!retval) {
                RegDeleteKey(HKEY_CURRENT_USER, subkey);
            }
        }
        return retval;
    }
}

bool md5(const char * input, std::string * output)
{
    bool retval = false;
    MD5_CTX c;
    if (MD5_Init(&c)) {
        unsigned char md[MD5_DIGEST_LENGTH];
        MD5_Update(&c, input, strlen(input));
        MD5_Final(md, &c);
        //output->swap(to_hex(md, sizeof(md)));
        *output = to_hex(md, sizeof(md));
        retval = true;
    }
    return retval;
}

static bool sha512(const void * input, size_t len, uint8_t * output)
{
    bool retval = false;
    SHA512_CTX c;
    if (SHA512_Init(&c)) {
        SHA512_Update(&c, input, len);
        SHA512_Final(output, &c);
        retval = true;
    }
    return retval;
}

/*
bool sha512(const char * input, std::string * output)
{
    unsigned char md[SHA512_DIGEST_LENGTH];
    bool retval = sha512(input, strlen(input), md);
    if (retval) {
        *output = to_hex(md, sizeof(md));
    }
    return retval;
}
*/

const size_t xor_key_length = 16;

static bool input_to_id(const void * input, size_t len, std::string * output)
{
    std::vector<uint8_t> random_bytes, key;
    generate_random_bytes_and_xor_key(xor_key_length, &random_bytes, &key);
    size_t header_size = random_bytes.size();
    size_t total_size = header_size + SHA512_DIGEST_LENGTH;
    size_t buffer_size = ((total_size + 127) >> 7) << 7;
    random_bytes.resize(buffer_size);
    bool retval = sha512(input, len, &random_bytes[header_size]);
    if (retval) {
        xor(&key[0], key.size(), &random_bytes[header_size], SHA512_DIGEST_LENGTH);
        *output = to_hex(&random_bytes[0], total_size);
    }
    return retval;
}

bool password_to_id(const char* input, std::string* output)
{
    return input_to_id(input, strlen(input), output);
}

bool ids_are_equal(const char * id1, const char * id2)
{
    std::vector<uint8_t> bin_id1 = to_bin(id1), bin_id2 = to_bin(id2);
    std::vector<uint8_t> key1, key2;
    int n1 = retrieve_key(&bin_id1[0], bin_id1.size(), xor_key_length, &key1);
    int n2 = retrieve_key(&bin_id2[0], bin_id2.size(), xor_key_length, &key2);
    bool retval = false;
    if (n1 > 0 && n2 > 0) {
        size_t n = bin_id1.size() - n1;
        if (n == (bin_id2.size() - n2)) {
            xor(&key1[0], key1.size(), &bin_id1[n1], n);
            xor(&key2[0], key2.size(), &bin_id2[n2], n);
            retval = memcmp(&bin_id1[n1], &bin_id2[n2], n) == 0;
        }
    }
    return retval;
}

bool file_to_id(const wchar_t* input, std::string* output)
{
#if ( defined( UNICODE ) || defined( _UNICODE ) )
    LPCTSTR file = input;
#else
    std::string tmp;
    unicode_to_ansi(input, tmp);
    LPCTSTR file = tmp.c_str();
#endif
    MappingFileHandle mfh(file, true);
    return input_to_id(mfh.c_ptr(), mfh.size(), output);
}

std::basic_string<TCHAR> strerror(DWORD dwError)
{
    HLOCAL hLocal = nullptr;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        nullptr,
        dwError,
        0, //LANG_USER_DEFAULT,
        (LPTSTR)&hLocal,
        0,
        nullptr
    );
    std::basic_string<TCHAR> error_message = (LPTSTR)hLocal;
    LocalFree(hLocal);
    return error_message;
}

Exception::Exception(DWORD dwError)
{
    m_strErrorMessage = strerror(dwError);
#if ( defined( UNICODE ) || defined( _UNICODE ) )
    unicode_to_ansi(m_strErrorMessage.c_str(), m_aem);
#endif
}

Exception::Exception(LPCTSTR msg) : m_strErrorMessage(msg)
{
#if ( defined( UNICODE ) || defined( _UNICODE ) )
    unicode_to_ansi(m_strErrorMessage.c_str(), m_aem);
#endif
}

bool export_public_key(RSA * key_pair, std::string * output)
{
    bool retval = false;
    try {
        BIOMem bio;
        PEM_write_bio_RSAPublicKey(bio, key_pair);
        int keylen = BIO_pending(bio);
        if (keylen > 0) {
            std::vector<char> buf(keylen + 1, '\0');
            BIO_read(bio, &buf[0], keylen);
            *output = &buf[0];
            retval = true;
        }
    } catch (std::exception const&) {
    }
    return retval;
}

std::string ntorn(const char * input)
{
    std::string retval;
    const char * h = input;
    for (const char * n = strchr(h, '\n'); n != nullptr; h = n + 1, n = strchr(h, '\n')) {
        retval.append(h, n);
        retval.append("\r\n");
    }
    retval.append(h);
    return retval;
}

bool key_pair_exists()
{
    HKEY hkey;
    DWORD cbData = 0;
    LONG result = RegOpenKeyEx(
        HKEY_CURRENT_USER,
        myself_subkey,
        0,
        KEY_READ,
        &hkey
    );
    if (result == ERROR_SUCCESS) {
        DWORD dwType = 0;
        result = RegQueryValueEx(
            hkey,
            private_key,
            nullptr,
            &dwType,
            nullptr,
            &cbData
        );
        RegCloseKey(hkey);
    }
    return result == ERROR_SUCCESS && cbData > 0;
}

bool save_key_pair(RSA * key_pair, char * password)
{
    std::string strPbk, strPvk;
    bool retval = export_public_key(key_pair, &strPbk) && export_private_key(key_pair, password, &strPvk);
    if (retval) {
        std::string strKey;
        password_to_id(password, &strKey);
        retval = save_key_pair(myself_subkey, strPbk.c_str(), strPbk.length(), strPvk.c_str(), strPvk.length(), strKey.c_str(), strKey.length());
    }
    return retval;
}

bool get_public_key(std::string * output)
{
    return get_key(public_key, output);
}

bool archive_key_pair()
{
    std::string strPbk, strPvk;
    bool retval = get_public_key(&strPbk) && get_key(private_key, &strPvk);
    if (retval) {
        std::string strKey;
        get_key(pvk_password, &strKey);
        CString strSubkey(archive_subkey);
        std::string fingerprint;
        if (md5(strPbk.c_str(), &fingerprint)) {
            strSubkey += _T("\\");
        #if ( defined( UNICODE ) || defined( _UNICODE ) )
            {
                USES_CONVERSION;
                strSubkey += A2W(fingerprint.c_str());
            }
        #else
            strSubkey += fingerprint.c_str();
        #endif
            retval = save_key_pair(strSubkey, strPbk.c_str(), strPbk.length(), strPvk.c_str(), strPvk.length(), strKey.c_str(), strKey.length());
        }
    }
    return retval;
}

bool get_all_my_key_pairs(std::unordered_map<std::string, KeyPairStrings> * output)
{
    std::string strPbk, strPvk, strKey;
    bool retval = get_public_key(&strPbk) && get_key(private_key, &strPvk);
    if (retval) {
        get_key(pvk_password, &strKey);

        std::string fingerprint;
        retval = md5(strPbk.c_str(), &fingerprint);
        (*output)[std::move(fingerprint)] = KeyPairStrings(std::move(strPbk), std::move(strPvk), std::move(strKey));

        HKEY hkey = nullptr;
        LSTATUS status = RegOpenKeyEx(HKEY_CURRENT_USER, archive_subkey, 0, KEY_READ, &hkey);
        if (status == ERROR_SUCCESS) {
            TCHAR buf[64];
            DWORD dwBuf, dwClass;
            for (DWORD i = 0; ; ++i) {
                dwBuf = _countof(buf);
                dwClass = 0;
                status = RegEnumKeyEx(
                    hkey,
                    i,
                    buf, &dwBuf,
                    nullptr,
                    nullptr, &dwClass,
                    nullptr
                );
                if (status == ERROR_SUCCESS) {
                    CString subkey(archive_subkey);
                    subkey.AppendChar(_T('\\'));
                    subkey.Append(buf);
                    if (
                        get_key(subkey, public_key, &strPbk) &&
                        get_key(subkey, private_key, &strPvk) &&
                        md5(strPbk.c_str(), &fingerprint)
                    ) {
                        get_key(subkey, pvk_password, &strKey);
                        (*output)[std::move(fingerprint)] = KeyPairStrings(std::move(strPbk), std::move(strPvk), std::move(strKey));
                    }
                } else {
                    break;
                }
            }
            RegCloseKey(hkey);
        }
    }
    return retval;
}

RSA * rebuild_public_key_from_text(const char * input)
{
    RSA * retval = nullptr;
    try {
        BIOMem bio;
        BIO_write(bio, input, static_cast<int>(strlen(input)));
        retval = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
    } catch (std::exception const&) {
    }
    return retval;
}

bool is_valid_public_key(const char * input)
{
    bool retval = false;
    RSA * rsa = rebuild_public_key_from_text(input);
    if (rsa != nullptr) {
        RSA_free(rsa);
        retval = true;
    }
    return retval;
}

RSA * rebuild_public_key_from_file(const TCHAR * file)
{
    RSA * retval = nullptr;
    FILE * pf = nullptr;
    _tfopen_s(&pf, file, _T("r"));
    if (pf != nullptr) {
        retval = PEM_read_RSAPublicKey(pf, nullptr, nullptr, nullptr);
        fclose(pf);
    }
    return retval;
}

bool get_file_content(const TCHAR * file_name, std::string * output)
{
    bool retval = false;
    FILE * pf = nullptr;
    _tfopen_s(&pf, file_name, _T("r"));
    if (pf != nullptr) {
        std::vector<char> buf(4096);
        while (!feof(pf)) {
            size_t n = fread(&buf[0], sizeof(buf[0]), buf.size(), pf);
            output->append(&buf[0], &buf[0] + n);
        }
        fclose(pf);
        retval = true;
    }
    return retval;
}

bool add_a_friend(const TCHAR * name, const char * strPbk, size_t nPbk)
{
    HKEY hkey = nullptr;
    DWORD dwDisposition;
    LSTATUS status = RegCreateKeyEx(
        HKEY_CURRENT_USER,
        friends_subkey,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        nullptr,
        &hkey,
        &dwDisposition
    );
    if (status == ERROR_SUCCESS) {
        status = RegSetValueEx(
            hkey,
            name,
            0,
            REG_BINARY,
            reinterpret_cast<const BYTE*>(strPbk),
            static_cast<DWORD>(nPbk)
        );
        RegCloseKey(hkey);
    }
    return (status == ERROR_SUCCESS);
}

bool get_friends(std::unordered_map<std::basic_string<TCHAR>, std::string> * friends)
{
    const DWORD dwBufferSize = 8192;
    bool retval = false;
    HKEY hkey = nullptr;
    LSTATUS status = RegOpenKeyEx(
        HKEY_CURRENT_USER,
        friends_subkey,
        0,
        KEY_READ,
        &hkey
    );
    if (status == ERROR_SUCCESS) {
        std::vector<TCHAR> name(dwBufferSize);
        std::vector<BYTE> data(dwBufferSize);
        for (
            DWORD index = 0, cbName = dwBufferSize, cbData = dwBufferSize;
            ;
            ++index, cbName = dwBufferSize, cbData = dwBufferSize
        ) {
            DWORD type = 0;
            status = RegEnumValue(
                hkey,
                index,
                &name[0],
                &cbName,
                nullptr,
                &type,
                &data[0],
                &cbData
            );

            if (status == ERROR_SUCCESS) {
                retval = true;
                (*friends)[&name[0]] = std::string(&data[0], &data[0] + cbData);
            } else {
                break;
            }
        }
        RegCloseKey(hkey);
    }
    return retval;
}

bool find_friend(std::string const & pbk_id, std::string * pbk, std::basic_string<TCHAR> * name)
{
    std::unordered_map<std::basic_string<TCHAR>, std::string> friends;
    bool successful = get_friends(&friends);
    if (successful) {
        successful = false;
        for (auto i = friends.begin(), e = friends.end(); i != e; ++i) {
            std::string id;
            md5(i->second.c_str(), &id);
            if (id == pbk_id) {
                *pbk = i->second;
                *name = i->first;
                successful = true;
                break;
            }
        }
    }
    return successful;
}

size_t get_file_size(const TCHAR * file)
{
    struct __stat64 stat = {0};
    _tstat64(file, &stat);
    return static_cast<size_t>(stat.st_size);
}

bool is_file(const TCHAR * name)
{
    bool retval = true;
    DWORD attr = GetFileAttributes(name);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        retval = false;
    }
    return retval;
}

bool is_folder(const TCHAR * name)
{
    DWORD dwAttrib = GetFileAttributes(name);
    return (
        dwAttrib != INVALID_FILE_ATTRIBUTES && 
        (dwAttrib & FILE_ATTRIBUTE_DIRECTORY)
    );
}

namespace
{
    int pass_cb(char* buf, int size, int, void* u)
    {
        const std::string pass = reinterpret_cast<char*>(u);
        int len = static_cast<int>(pass.size());
        // if too long, truncate
        if (len > size) {
            len = size;
        }
        //pass.copy(buf, len);
        memcpy(buf, pass.c_str(), len);
        return len;
    }

    char *LoseStringConst(const std::string& str)
    {
        return const_cast<char*>(str.c_str());
    }

    void* StringAsVoid(const std::string& str)
    {
        return reinterpret_cast<void*>(LoseStringConst(str));
    }
}

RSA * rebuild_private_key(const char * password)
{
    RSA * retval = nullptr;
    std::string strPvk;
    if (get_key(private_key, &strPvk)) {
        try {
            BIOMem bio;
            BIO_write(bio, strPvk.c_str(), static_cast<int>(strPvk.length()));
            retval = PEM_read_bio_RSAPrivateKey(
                bio, nullptr, pass_cb,  StringAsVoid(password)
            );
        } catch (std::exception const&) {
        }
    }
    return retval;
}

RSA * rebuild_private_key(const char * pem_string, const char * password)
{
    RSA * retval = nullptr;
    try {
        BIOMem bio;
        BIO_write(bio, pem_string, static_cast<int>(strlen(pem_string)));
        retval = PEM_read_bio_RSAPrivateKey(
            bio, nullptr, pass_cb,  StringAsVoid(password)
        );
    } catch (std::exception const&) {
    }
    return retval;
}

std::basic_string<TCHAR> dirname(const TCHAR * path)
{
    std::basic_string<TCHAR> retval;
    auto p = _tcsrchr(path, _T('\\'));
    if (p != nullptr) {
        retval.assign(path, p);
    }
    return retval;
}

void move_file(const TCHAR * from, const TCHAR * to)
{
    create_directory(dirname(to).c_str());
    if (_trename(from, to) != 0) {
        TCHAR msg[256];
        _tcserror_s(msg, errno);
        throw Exception(msg);
    }
}

void remove_directory(const TCHAR * name, bool ignore_error)
{
    size_t len = _tcslen(name) + 1;
    std::vector<TCHAR> buf(len + 2, 0);
    _tcscpy_s(&buf[0], len, name);
    SHFILEOPSTRUCTW shf = {0};
    shf.hwnd = nullptr;
    shf.wFunc = FO_DELETE;
    shf.pFrom = &buf[0];
    shf.pTo = &buf[0];
    shf.fFlags = FOF_NOCONFIRMATION;
    auto result = SHFileOperationW(&shf);
    if (!ignore_error && result != 0) {
        throw Exception(result);
    }
}

void create_directory(const TCHAR * name)
{
    auto result = SHCreateDirectoryEx(nullptr, name, nullptr);
    if (result != ERROR_SUCCESS && result != ERROR_ALREADY_EXISTS) {
        throw Exception(result);
    }
}

std::vector<std::basic_string<TCHAR>> split(const TCHAR * input, TCHAR tch)
{
    std::vector<std::basic_string<TCHAR>> result;
    const TCHAR * h = input, * n = _tcschr(h, tch);
    while (n != nullptr) {
        result.emplace_back(std::basic_string<TCHAR>(h, n));
        h = n + 1;
        n = _tcschr(h, tch);
    }
    if (h[0] != 0) {
        result.emplace_back(std::basic_string<TCHAR>(h));
    }
    return result;
}

std::basic_string<TCHAR> join(std::basic_string<TCHAR> const * from, int n, TCHAR tch)
{
    std::basic_string<TCHAR> retval;
    retval.reserve(32);
    for (int i = 0; i < n; ++i) {
        if (!retval.empty()) {
            retval.push_back(tch);
        }
        retval.append(from[i].c_str());
    }
    return retval;
}

void MetaInformation::destroy()
{
    sender.clear();
    files.clear();
    std::basic_string<TCHAR> tmp(std::move(local_folder));
    remove_directory(tmp.c_str(), false);
}

std::vector<int> get_index_of_set_bits(const void * input, size_t size, size_t n)
{
    std::vector<int> retval;
    retval.reserve(n);
    //ASSERT(size%sizeof(uint64_t) == 0);
    const uint64_t * pui = static_cast<const uint64_t*>(input);
    size_t loop = size/sizeof(uint64_t), i;
    for (i = 0; i < loop && n != 0; ++i, ++pui) {
        uint64_t ui = *pui;
        for (size_t j = 0, je = sizeof(uint64_t) * 8; j < je && n != 0; ++j) {
            if ((ui & 1) != 0) {
                retval.push_back(static_cast<int>(i * 64 + j));
                --n;
            }
            ui >>= 1;
        }
    }
    if (n != 0) {
        size_t remains = size%sizeof(uint64_t);
        if (remains != 0) {
            union {
                uint64_t ui;
                uint8_t ub[8];
            };
            ui = 0;
            memcpy(ub, pui, remains);
            for (size_t j = 0, je = sizeof(uint64_t) * 8; j < je && n != 0; ++j) {
                if ((ui & 1) != 0) {
                    retval.push_back(static_cast<int>(i * 64 + j));
                    --n;
                }
                ui >>= 1;
            }
        }
    }
    if (n != 0) {
        retval.clear();
    }
    return retval;
}

inline void fill_buffer(const uint8_t * input, std::vector<int> const & indices,  std::vector<uint8_t> * buffer)
{
    buffer->reserve(indices.size());
    for (auto i = indices.begin(), ie = indices.end(); i != ie; ++i) {
        buffer->push_back(input[*i]);
    }
}

void generate_random_bytes_and_xor_key(size_t key_length, std::vector<uint8_t> * random_bytes, std::vector<uint8_t> * key)
{
    int buffer_size = 1024;
    while (true) {
        std::vector<uint8_t> buf(buffer_size);
        RAND_bytes(&buf[0], buffer_size);
        auto indices = get_index_of_set_bits(&buf[0], buffer_size, key_length);
        if (!indices.empty() && indices.back() < buffer_size) {
            size_t size = ((static_cast<size_t>(indices.back()) + 16) >> 4) << 4;
            random_bytes->assign(&buf[0], &buf[0] + size);
            fill_buffer(&(*random_bytes)[0], indices, key);
            break;
        }
        buffer_size <<= 1;
    }
}

int retrieve_key(const void * input, size_t size, size_t key_length, std::vector<uint8_t> * key)
{
    int retval = -1;
    auto indices = get_index_of_set_bits(input, size, key_length);
    if (!indices.empty() && indices.back() < static_cast<int>(size)) {
        fill_buffer(static_cast<const uint8_t*>(input), indices, key);
        retval = ((indices.back() + 16) >> 4) << 4;
    }
    return retval;
}

bool get_public_key_id(std::string * output)
{
    std::string strPbk;
    bool retval = get_public_key(&strPbk);
    if (retval) {
        retval = md5(strPbk.c_str(), output);
    }
    return retval;
}

bool update_key(
    std::unordered_map<std::string, KeyPairStrings> & all_key_pairs,
    std::unordered_map<std::string, KeyPairStrings>::iterator used_one,
    const char * password
) {
    bool retval = true;
    if (used_one != all_key_pairs.end()) {
        std::string key_id;
        retval = password_to_id(password, &key_id);
        if (retval) {
            //if (key_id != used_one->second.m_key) {
            if (!ids_are_equal(key_id.c_str(), used_one->second.m_key.c_str())) {
                std::string pbk_id;
                retval = get_public_key_id(&pbk_id);
                if (retval) {
                    retval = false;
                    CString strSubkey(myself_subkey);
                    if (used_one->first != pbk_id) {
                        strSubkey = archive_subkey;
                        strSubkey += _T("\\");
                    #if ( defined( UNICODE ) || defined( _UNICODE ) )
                        {
                            USES_CONVERSION;
                            strSubkey += A2W(used_one->first.c_str());
                        }
                    #else
                        strSubkey += used_one->first.c_str();
                    #endif
                    }
                    {
                        HKEY hkey = nullptr;
                        DWORD dwDisposition;
                        LSTATUS status = RegCreateKeyEx(
                            HKEY_CURRENT_USER,
                            strSubkey,
                            0,
                            nullptr,
                            REG_OPTION_NON_VOLATILE,
                            KEY_ALL_ACCESS,
                            nullptr,
                            &hkey,
                            &dwDisposition
                        );
                        if (status == ERROR_SUCCESS) {
                            retval = save_item(hkey, pvk_password, key_id.c_str(), key_id.length());
                            RegCloseKey(hkey);
                        }
                    }
                }
            }
        }
    }
    return retval;
}
