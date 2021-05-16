#include "stdafx.h"
#include "resource.h"
#include "Tools.h"
#include "Cipher.h"
#include "File.h"

namespace
{
    const char * default_sign_hash_algorithm_name = "SHA256";
    const u_long default_version = 3;

    void set_value(const char * value, std::basic_string<TCHAR> * to)
    {
        USES_CONVERSION;
        to->assign(A2T(value));
    }

    std::unordered_map<std::basic_string<TCHAR>, std::basic_string<TCHAR>> simplify(std::unordered_set<std::basic_string<TCHAR>> const& filenames)
    {
        std::vector<std::vector<std::basic_string<TCHAR>>> segments;
        segments.reserve(filenames.size());
        for (auto i = filenames.begin(), e = filenames.end(); i != e; ++i) {
            segments.emplace_back(split(i->c_str(), _T('\\')));
        }

        std::unordered_map<std::basic_string<TCHAR>, std::basic_string<TCHAR>> retval;
        for (int i = 1; ; ++i) {
            retval.clear();
            std::unordered_set<std::basic_string<TCHAR>> unique_paths;
            for (int j = 0, je = static_cast<int>(segments.size()); j < je; ++j) {
                int k = static_cast<int>(segments[j].size());
                int from = k - i;
                int n = i;
                if (from < 0) {
                    from = 0;
                    n = k;
                }
                auto path = join(&segments[j][from], n, _T('\\'));
                auto result = unique_paths.insert(std::move(path));
                if (!result.second) {
                    unique_paths.clear();
                    break;
                }
                retval[join(&segments[j][0], k, _T('\\'))] = join(&segments[j][from], n, _T('\\'));
            }
            if (!unique_paths.empty()) {
                break;
            }
        }
        return retval;
    }

    bool create_decryption_home_folder(const TCHAR * encrypted_file, std::basic_string<TCHAR> * home_folder)
    {
        bool retval = false;
        const TCHAR * ptc = _tcsrchr(encrypted_file, _T('\\'));
        if (ptc != nullptr) {
            home_folder->assign(encrypted_file, ptc + 1);
            CTime date(CTime::GetCurrentTime());
            CString prefix;
            prefix.LoadString(IDS_STRING_FOLDER_NAME);
            TCHAR buf[64];
            _stprintf_s(
                buf, _T("%s_%d_%d_%d_%02d%02d%02d"),
                static_cast<LPCTSTR>(prefix), date.GetYear(), date.GetMonth(), date.GetDay(),
                date.GetHour(), date.GetMinute(), date.GetSecond()
            );
            home_folder->append(&buf[0]);
            retval = (CreateDirectory(home_folder->c_str(), nullptr) != FALSE);
            if (!retval) {
                retval = (GetLastError() == ERROR_ALREADY_EXISTS);
            }
        }
        return retval;
    }

    // Convert a wide Unicode string to an UTF8 string
    std::vector<char> utf8_encode(const wchar_t * input)
    {
        int len = static_cast<int>(wcslen(input));
        if (len == 0) return std::vector<char>();
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, input, len, nullptr, 0, nullptr, nullptr);
        std::vector<char> strTo(size_needed, '\0');
        WideCharToMultiByte(CP_UTF8, 0, input, len, &strTo[0], size_needed, nullptr, nullptr);
        return strTo;
    }

    // Convert an UTF8 string to a wide Unicode String
    std::wstring utf8_decode(const char * input, size_t nInput)
    {
        int len = static_cast<int>(nInput);
        if (len == 0) return std::wstring();
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, input, len, nullptr, 0);
        std::wstring wstrTo(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, input, len, &wstrTo[0], size_needed);
        return wstrTo;
    }

    void get_random_key(size_t n, void * output)
    {
        ASSERT(n > 0 && n <= 128);
        uint8_t buf[4096];
        RAND_bytes(buf, sizeof(buf));
        SHA512_CTX ctx = {0};
        SHA512_Init(&ctx);
        SHA512_Update(&ctx, buf, sizeof(buf));
        SHA512_Final(buf, &ctx);
        memcpy(output, &buf[0], n);
        uint8_t * pb = static_cast<uint8_t*>(output);
        for (size_t c = 1, ce = sizeof(buf)/n; c < ce; ++c) {
            size_t next = c * n;
            for (size_t i = 0; i < n; ++i) {
                pb[i] ^= buf[next+i];
            }
        }
    }

    std::vector<uint8_t> get_random_key(size_t n)
    {
    #if 0
        ASSERT(n >= 16 && n <= 128);
        uint8_t buf[4096];
        RAND_bytes(buf, sizeof(buf));
        SHA512_CTX ctx = {0};
        SHA512_Init(&ctx);
        SHA512_Update(&ctx, buf, sizeof(buf));
        SHA512_Final(buf, &ctx);
        std::vector<uint8_t> retval(buf, buf + n);
        for (size_t c = 1, ce = sizeof(buf)/n; c < ce; ++c) {
            size_t next = c * n;
            for (size_t i = 0; i < n; ++i) {
                retval[i] ^= buf[next+i];
            }
        }
        return retval;
    #else
        std::vector<uint8_t> retval(n);
        get_random_key(n, &retval[0]);
        return retval;
    #endif
    }

    struct Recipient
    {
        std::string id;
        std::string strPbk;

        Recipient() {}
        Recipient(std::string && i, std::string const & pbk) : id(std::move(i)), strPbk(pbk) {}
    };

    bool convert(const std::vector<std::string> & public_keys, std::vector<Recipient> & output)
    {
        bool retval = true;
        std::vector<Recipient> recipients;
        for (auto i = public_keys.begin(), e = public_keys.end(); i != e; ++i) {
            std::string id;
            retval = md5(i->c_str(), &id);
            if (retval) {
                recipients.emplace_back(Recipient(std::move(id), *i));
            } else {
                break;
            }
        }
        if (retval) {
            output.swap(recipients);
        }
        return retval;
    }

    struct RecipientSection
    {
        uint8_t id[MD5_DIGEST_LENGTH*2];
        u_long content_length;
        uint8_t content[1];
    };

    const u_long content_length_mask = 756810249;

    bool encrypt_key(
        const uint8_t * xor_key, size_t xor_key_length,
        std::vector<uint8_t> const & key,
        Recipient const & recipient,
        uint8_t ** output
    ) {
        bool retval = false;
        RSAKey rsa(rebuild_public_key_from_text(recipient.strPbk.c_str()));
        if (rsa != nullptr) {
            RecipientSection * prs = reinterpret_cast<RecipientSection*>(*output);
            memcpy(prs->id, recipient.id.c_str(), sizeof(prs->id));
            int result = RSA_public_encrypt(static_cast<int>(key.size()), &key[0], prs->content, rsa, RSA_PKCS1_PADDING);
            if (result > 0) {
                prs->content_length = htonl(result ^ content_length_mask);
                xor(xor_key, xor_key_length, prs, &prs->content[0] - reinterpret_cast<uint8_t*>(prs));
                *output += (result + sizeof(prs->id) + sizeof(prs->content_length));
                retval = true;
            }
        }
        return retval;
    }

    struct FileSection
    {
        u_long name_length;
        u_long content_length;
        uint8_t content[1];
    };

    const u_long name_length_mask = 391745028;

    bool encrypt_file_impl(
        const std::vector<uint8_t> & key,
        const TCHAR * file,
        uint8_t ** output,
        std::basic_string<TCHAR> * error_message
    ) {
        enum {BLOCK_SIZE = 4096 * 32};
        bool retval = false;
        try {
            File inf(file, _T("rb"));
            EncryptionCipherCtx enc(key);
            std::vector<uint8_t> buf(BLOCK_SIZE);
            uint8_t* next = *output;
            while (true) {
                size_t r1 = inf.read(&buf[0], buf.size());
                if (r1 > 0) {
                    size_t r2 = enc.update(&buf[0], r1, next);
                    next += r2;
                }
                if (r1 < buf.size()) {
                    break;
                }
            }
            size_t r = enc.close(next);
            *output = next + r;
            retval = true;
        } catch (std::exception const& e) {
            set_value(e.what(), error_message);
        }
        return retval;
    }

    bool encrypt_file(
        const uint8_t * xor_key, size_t xor_key_length,
        std::vector<uint8_t> const & key,
        const TCHAR * file_name,
        uint8_t ** output,
        std::basic_string<TCHAR> * error_message
    ) {
        auto utf8_name = utf8_encode(file_name);
        size_t ns = utf8_name.size();
        xor(xor_key, xor_key_length, &utf8_name[0], ns);
        FileSection * pfs = reinterpret_cast<FileSection*>(*output);
        pfs->name_length = htonl(static_cast<u_long>(ns) ^ name_length_mask);
        memcpy(pfs->content, &utf8_name[0], ns);
        uint8_t * current = pfs->content + ns, * next = current;
        bool successful = encrypt_file_impl(key, file_name, &next, error_message);
        if (successful) {
            u_long content_length = static_cast<u_long>(next - current);
            pfs->content_length = htonl(content_length ^ content_length_mask);
            xor(xor_key, xor_key_length, pfs, &pfs->content[0] - reinterpret_cast<uint8_t*>(pfs));
            *output = next;
        }
        return successful;
    }

    bool decrypt_impl(
        const std::vector<uint8_t> & key,
        const uint8_t * input, size_t input_length,
        const TCHAR * file,
        std::basic_string<TCHAR> * error_message
    ) {
        enum {BLOCK_SIZE = 4096};
        bool retval = false;
        try {
            File of(file, _T("wb"));
            DecryptionCipherCtx dec(key);
            std::vector<uint8_t> buf(BLOCK_SIZE + 512);

            for (
                size_t inl = BLOCK_SIZE <= input_length ? BLOCK_SIZE : input_length;
                input_length != 0;
                input_length -= inl, inl = BLOCK_SIZE <= input_length ? BLOCK_SIZE : input_length
            ) {
                size_t r = dec.update(input, inl, &buf[0]);
                input += inl;
                of.write(&buf[0], r);
            }
            size_t r = dec.close(&buf[0]);
            of.write(&buf[0], r);
            retval = true;
        } catch (std::exception const& e) {
            set_value(e.what(), error_message);
        }
        return retval;
    }

    bool decrypt_file(
        std::vector<uint8_t> const & key,
        const uint8_t * input, size_t input_len,
        const TCHAR * home_folder,
        const TCHAR *,
        unsigned index,
        std::basic_string<TCHAR> * tmp_name,
        std::basic_string<TCHAR> * error_message
    )  {
        CTime time(CTime::GetCurrentTime());
        TCHAR file_name[MAX_PATH];
        _stprintf_s(file_name, _T("%s\\%lld.tmp"), home_folder, (time.GetTime() + index));
        tmp_name->assign(file_name);
        bool successful = decrypt_impl(key, input, input_len, file_name, error_message);
        if (!successful) {
            DeleteFile(file_name);
        }
        return successful;
    }

    struct SignSection
    {
        uint8_t id[MD5_DIGEST_LENGTH*2];
        u_long content_length;
        uint8_t content[1];
    };

    bool sign(
        const uint8_t * xor_key, size_t xor_key_length,
        const uint8_t * input, size_t input_len,
        const char * hash, RSA * pvk,
        uint8_t ** output
    ) {
        std::string pbk_id;
        bool retval = get_public_key_id(&pbk_id);
        if (retval) {
            try {
                SignSection * pss = reinterpret_cast<SignSection*>(*output);
                memcpy(pss->id, pbk_id.c_str(), sizeof(pss->id));
                EvpMdCtx mdctx(hash);
                mdctx.update(input, input_len);
                auto md = mdctx.close();
                auto result = RSA_private_encrypt(static_cast<int>(md.size()), &md[0], pss->content, pvk, RSA_PKCS1_PADDING);
                if (result > 0) {
                    pss->content_length = htonl(result ^ content_length_mask);
                    uint8_t * begin = reinterpret_cast<uint8_t*>(pss);
                    xor(xor_key, xor_key_length, begin, &pss->content[0] - begin);
                    (*output) = pss->content + result;
                    retval = true;
                }
            } catch (std::exception const&) {
            }
        }
        return retval;
    }

    const size_t global_xor_key_length = 16;

    struct PackageHeader
    {
        u_long magic;
        u_long version;
        u_long length;
        u_long number_of_recipients;
        u_long number_of_files;
        u_long content_offset;
        char signHashName[8+global_xor_key_length];
        uint8_t xor_key[global_xor_key_length];
    };

    const u_long global_magic = 536249187;
    const u_long version_mask = 634523107;
    const u_long length_mask = 865364719;
    const u_long recipient_mask = 975782021;
    const u_long file_mask = 484367893;
    const u_long offset_mask = 597663235;

    bool pvk_decrypt(const uint8_t * input, size_t input_len, RSA * pvk, std::vector<uint8_t> * key)
    {
        std::vector<uint8_t> buf(input_len);
        bool retval = false;
        int result = RSA_private_decrypt(static_cast<int>(input_len), input, &buf[0], pvk, RSA_PKCS1_PADDING);
        if (result > 0) {
            key->assign(&buf[0], &buf[0] + result);
            retval = true;
        }
        return retval;
    }

    bool pvk_decrypt(const uint8_t * input, size_t input_len, const char * password, KeyPairStrings const & key_pair, std::vector<uint8_t> * key)
    {
        bool retval = false;
        RSAKey rsa(rebuild_private_key(key_pair.m_pvk.c_str(), password));
        if ((retval = rsa.valid())) {
            retval = pvk_decrypt(input, input_len, rsa, key);
        }
        return retval;
    }

    void move_file(const TCHAR * from, const TCHAR * to, const TCHAR * potential_parent_of_to)
    {
        if (_istalpha(to[0]) && to[1] == _T(':')) {
            ::move_file(from, to);
        } else {
            TCHAR buf[_MAX_PATH];
            _stprintf_s(buf, _T("%s\\%s"), potential_parent_of_to, to);
            ::move_file(from, buf);
        }
    }

    std::basic_string<TCHAR> v1_check_sign(
        const uint8_t * text,
        size_t text_size,
        size_t file_size,
        const char * sign_hash
    ) {
        try {
            if (text_size < file_size) {
                const SignSection * pss = reinterpret_cast<const SignSection*>(text + text_size);
                std::string pbk_id(pss->id, pss->id + sizeof(pss->id));
                std::string sender_pbk;
                std::basic_string<TCHAR> sender_name;
                if (find_friend(pbk_id, &sender_pbk, &sender_name)) {
                    RSAKey rsa(rebuild_public_key_from_text(sender_pbk.c_str()));
                    if  (rsa.valid()) {
                        u_long signature_size = ntohl(pss->content_length) ^ content_length_mask;
                        const uint8_t * signature = pss->content;
                        if ((text_size + signature_size) <= file_size) {
                            EvpMdCtx md_ctx(sign_hash);
                            md_ctx.update(text, text_size);
                            auto md = md_ctx.close();
                            std::vector<uint8_t> buf(signature_size);
                            RSA_public_decrypt(static_cast<int>(signature_size), signature, &buf[0], rsa, RSA_PKCS1_PADDING);
                            if (memcmp(&md[0], &buf[0], md.size()) == 0) {
                                return sender_name;
                            }
                        }
                    }
                }
            }
        } catch (std::exception const&) {
        }
        return std::basic_string<TCHAR>();
    }

    void get_error_message(UINT id, std::basic_string<TCHAR>* error_message)
    {
        CString tmp;
        tmp.LoadString(id);
        error_message->assign(static_cast<LPCTSTR>(tmp));
    }

    bool check_sign(
        const uint8_t * xor_key, size_t xor_key_length,
        const uint8_t * text,
        size_t text_size,
        size_t file_size,
        const char * sign_hash,
        std::basic_string<TCHAR>* sender_name,
        std::basic_string<TCHAR>* error_message
    ) {
        bool retval = true;
        if (text_size < file_size) {
            SignSection sign_section;
            memcpy(&sign_section, text + text_size, sizeof(sign_section));
            xor(xor_key, xor_key_length, &sign_section, &sign_section.content[0] - reinterpret_cast<uint8_t*>(&sign_section));
            std::string pbk_id(sign_section.id, sign_section.id + sizeof(sign_section.id));
            std::string sender_pbk;
            //std::basic_string<TCHAR> sender_name;

            retval = false;
            if (find_friend(pbk_id, &sender_pbk, sender_name)) {
                RSAKey rsa(rebuild_public_key_from_text(sender_pbk.c_str()));
                if (rsa.valid()) {
                    u_long signature_size = ntohl(sign_section.content_length) ^ content_length_mask;
                    const SignSection * pss = reinterpret_cast<const SignSection*>(text + text_size);
                    const uint8_t * signature = pss->content;
                    if ((text_size + signature_size) <= file_size) {
                        EvpMdCtx md_ctx(sign_hash);
                        md_ctx.update(text, text_size);
                        auto md = md_ctx.close();
                        std::vector<uint8_t> buf(signature_size);
                        RSA_public_decrypt(static_cast<int>(signature_size), signature, &buf[0], rsa, RSA_PKCS1_PADDING);
                        if (memcmp(&md[0], &buf[0], md.size()) == 0) {
                            retval = true;
                        } else {
                            get_error_message(IDS_STRING_FILE_TAMPERED, error_message);
                        }
                    } else {
                        get_error_message(IDS_STRING_FILE_TAMPERED, error_message);
                    }
                } else {
                    CString tmp;
                    tmp.Format(IDS_STRING_BAD_PBK_OF_SENDER, sender_name->c_str());
                    error_message->assign(static_cast<LPCTSTR>(tmp));
                }
            } else {
                get_error_message(IDS_STRING_UNKNOWN_SENDER, error_message);
            }
        }
        return retval;
    }

    std::string get_hash_name(PackageHeader const * pHeader)
    {
        enum {LIMIT = sizeof(pHeader->signHashName)};
        char buf[LIMIT] = "";
        int n = pHeader->signHashName[0];
        ASSERT(n < (LIMIT - 1));
        memcpy(buf, &pHeader->signHashName[1], n);
        return buf;
    }
}

void xor(
    const uint8_t * key, size_t key_len,
    void * inout, size_t input_len
) {
    uint8_t * pb = static_cast<uint8_t *>(inout);
    for (size_t curr = 0, next = curr + key_len; curr < input_len; curr = next, next += key_len) {
        for (size_t i = 0, j = curr, je = next <= input_len ? next : input_len; j < je; ++i, ++j) {
            pb[j] ^= key[i];
        }
    }
}

/*
 * 1. random header
 * 2. PackageHeader
 * 3. recipients
 * 4. content
 * 5. sign (optional)
 */
bool encrypt(
    const std::unordered_set<std::basic_string<TCHAR>> & files,
    const std::vector<std::string> & public_keys,
    const TCHAR * output_file,
    std::basic_string<TCHAR> * error_message,
    RSA * rsa,
    const char * hash
) {
    if (hash == nullptr || hash[0] == 0) {
        hash = default_sign_hash_algorithm_name;
    }
    bool retval = false;
    size_t key_len = 32 + 16; // key + iv
    try {
        MappingFileHandle mfh(output_file, false);
        std::vector<Recipient> recipients;
        retval = convert(public_keys, recipients);
        if (retval) {
            uint8_t * pNext = mfh.c_ptr(), * pNonrandom = nullptr;

            //the first section: a random header
            std::vector<uint8_t> random_bytes, global_xor_key;
            generate_random_bytes_and_xor_key(global_xor_key_length, &random_bytes, &global_xor_key);
            memcpy(pNext, &random_bytes[0], random_bytes.size());

            //the second section: PackageHeader
            pNext += random_bytes.size();
            pNonrandom = pNext;
            PackageHeader * pHeader = reinterpret_cast<PackageHeader *>(pNonrandom);
            size_t hash_name_len = strlen(hash);
            ASSERT(hash_name_len < (sizeof(pHeader->signHashName)-1));
            {
                pHeader->magic = htonl(global_magic);
                pHeader->version = htonl(default_version ^ version_mask);
                pHeader->number_of_recipients = htonl(static_cast<u_long>(public_keys.size()) ^ recipient_mask);
                pHeader->number_of_files = htonl(static_cast<u_long>(files.size()) ^ file_mask);
                get_random_key(sizeof(pHeader->signHashName), pHeader->signHashName);
                get_random_key(sizeof(pHeader->xor_key), pHeader->xor_key);
                for (size_t i = 0; i < global_xor_key_length; ++i) {
                    global_xor_key[i] ^= pHeader->xor_key[i];
                }
                memcpy(&pHeader->signHashName[1], hash, hash_name_len);
                pHeader->signHashName[0] = static_cast<char>(hash_name_len);
                pNext += sizeof(PackageHeader);
            }

            //the third section: the information about the recipients
            auto key = get_random_key(key_len);
            {
                for (auto i = recipients.begin(), e = recipients.end(); i != e; ++i) {
                    if (!encrypt_key(&global_xor_key[0], global_xor_key.size(), key, *i, &pNext)) {
                        retval = false;
                        goto out;
                    }
                }
            }

            //the fourth section: the encrypted files
            {
                pHeader->content_offset = htonl(static_cast<u_long>(pNext - mfh.c_ptr()) ^ offset_mask);
                for (auto i = files.begin(), e = files.end(); i != e; ++i) {
                    if (!encrypt_file(&global_xor_key[0], global_xor_key.size(), key, i->c_str(), &pNext, error_message)) {
                        retval = false;
                        goto out;
                    }
                }
            }
            u_long length_of_content_for_signing = static_cast<u_long>(pNext - mfh.c_ptr());
            {
                mfh.set_size(length_of_content_for_signing);
                pHeader->length = htonl(length_of_content_for_signing ^ length_mask);

                xor(&global_xor_key[0], global_xor_key.size(), pNonrandom, &pHeader->xor_key[0] - pNonrandom);
            }

            //the fifth section: the signature, it is optional
            {
                if (rsa != nullptr) {
                    if (sign(&global_xor_key[0], global_xor_key.size(), mfh.c_ptr(), length_of_content_for_signing, hash, rsa, &pNext)) {
                        mfh.set_size(pNext - mfh.c_ptr());
                    }
                }
            }
            mfh.close();
        }
    } catch (std::exception& e) {
        set_value(e.what(), error_message);
        retval = false;
    }
out:
    if (!retval) {
        DeleteFile(output_file);
    }
    return retval;
}

static bool v1_decrypt(
    const TCHAR * file,
    const char * password,
    MetaInformation * output,
    std::basic_string<TCHAR> * error_message
) {
    std::basic_string<TCHAR> decryption_home_folder;
    std::unordered_map<std::string, KeyPairStrings> all_my_key_pairs;
    bool retval = get_all_my_key_pairs(&all_my_key_pairs);
    if (retval) {
        try {
            MappingFileHandle mfh(file, true);
            PackageHeader header;
            memcpy(&header, mfh.c_ptr(), sizeof(PackageHeader));
            PackageHeader * pHeader = &header;
            xor(
                pHeader->xor_key, sizeof(pHeader->xor_key),
                &header, &pHeader->xor_key[0] - reinterpret_cast<uint8_t*>(&header)
            );
            u_long magic = ntohl(pHeader->magic);
            u_long version = ntohl(pHeader->version) ^ version_mask;
            if (magic == global_magic && version == default_version) {
                u_long number_of_recipients = ntohl(pHeader->number_of_recipients) ^ recipient_mask;
                u_long number_of_files = ntohl(pHeader->number_of_files) ^ file_mask;
                u_long content_offset = ntohl(pHeader->content_offset) ^ offset_mask;
                u_long length = ntohl(pHeader->length) ^ length_mask;

                output->sender = v1_check_sign(
                    mfh.c_ptr(),
                    length,
                    mfh.size(),
                    get_hash_name(pHeader).c_str()
                );

                uint8_t * pNext = mfh.c_ptr();
                pNext += sizeof(PackageHeader);
                std::vector<uint8_t> key;

                {
                    for (u_long i = 0; i < number_of_recipients; ++i) {
                        RecipientSection rs;
                        memcpy(&rs, pNext, sizeof(RecipientSection));
                        xor(pHeader->xor_key, sizeof(pHeader->xor_key), &rs, &rs.content[0] - reinterpret_cast<uint8_t*>(&rs));
                        u_long content_length = ntohl(rs.content_length) ^ content_length_mask;

                        std::string pbk_id(&rs.id[0], &rs.id[0] + sizeof(rs.id));
                        auto kp = all_my_key_pairs.find(pbk_id);
                        if (kp != all_my_key_pairs.end()) {
                            RecipientSection * prs = reinterpret_cast<RecipientSection*>(pNext);
                            if (pvk_decrypt(prs->content, content_length, password, kp->second, &key)) {
                                break;
                            }
                        }

                        pNext += (sizeof(rs.id) + sizeof(rs.content_length) + content_length);
                    }
                }

                if (!key.empty()) {
                    retval = create_decryption_home_folder(file, &decryption_home_folder);
                    if (retval) {
                        std::unordered_set<std::basic_string<TCHAR>> file_names;
                        std::unordered_map<std::basic_string<TCHAR>, std::basic_string<TCHAR>> tmp_files;
                        pNext = mfh.c_ptr() + content_offset;
                        for (u_long i = 0; i < number_of_files; ++i) {
                            FileSection fs;
                            memcpy(&fs, pNext, sizeof(FileSection));
                            xor(pHeader->xor_key, sizeof(pHeader->xor_key), &fs, &fs.content[0] - reinterpret_cast<uint8_t*>(&fs));
                            u_long name_length = ntohl(fs.name_length) ^ name_length_mask;
                            u_long content_length = ntohl(fs.content_length) ^ content_length_mask;

                            FileSection * pfs = reinterpret_cast<FileSection*>(pNext);
                            std::vector<char> filename_buf(pfs->content, pfs->content + name_length);
                            xor(pHeader->xor_key, sizeof(pHeader->xor_key), &filename_buf[0], name_length);
                            auto file_name = utf8_decode(&filename_buf[0], name_length);
                            file_names.insert(file_name);
                            uint8_t * content_ptr = pfs->content + name_length;
                            std::basic_string<TCHAR> tmp_file;
                            retval = decrypt_file(
                                key,
                                content_ptr, content_length,
                                decryption_home_folder.c_str(),
                                file_name.c_str(),
                                i,
                                &tmp_file,
                                error_message
                            );
                            if (retval) {
                                tmp_files[file_name] = std::move(tmp_file);
                                pNext += (sizeof(pfs->name_length) + sizeof(pfs->content_length) + name_length + content_length);
                            } else {
                                break;
                            }
                        }
                        if (retval) {
                            retval = (SetCurrentDirectory(decryption_home_folder.c_str()) != FALSE);
                            if (retval) {
                                auto simple_file_names = simplify(file_names);
                                for (auto i = tmp_files.begin(), e = tmp_files.end(); i != e; ++i) {
                                    auto simple_name = simple_file_names[i->first];
                                    move_file(i->second.c_str(), simple_name.c_str(), decryption_home_folder.c_str());
                                    output->files.insert(std::move(simple_name));
                                }
                                output->local_folder = decryption_home_folder;
                            }
                        }
                    }
                } else {
                    CString msg;
                    msg.LoadString(IDS_STRING_NOT_FOR_YOU);
                    error_message->assign(msg);
                    retval = false;
                }
            } else {
                CString msg;
                msg.LoadString(IDS_STRING_UNSUPPORTED_FILE_CONTENT);
                error_message->assign(msg);
                retval = false;
            }
        } catch (std::exception const& e) {
            set_value(e.what(), error_message);
            retval = false;
        }
    }
    if (!retval && !decryption_home_folder.empty()) {
        remove_directory(decryption_home_folder.c_str());
    }
    return retval;
}

static bool current_decrypt(
    const TCHAR * file,
    const char * password,
    MetaInformation * output,
    std::basic_string<TCHAR> * error_message,
    bool * needRetry
) {
    std::basic_string<TCHAR> decryption_home_folder;
    std::unordered_map<std::string, KeyPairStrings> all_my_key_pairs;
    std::unordered_map<std::string, KeyPairStrings>::iterator used_one;
    *needRetry = false;
    bool retval = get_all_my_key_pairs(&all_my_key_pairs);
    if (retval) {
        used_one = all_my_key_pairs.end();
        std::string strKey;
        retval = password_to_id(password, &strKey);
        if (retval) {
            try {
                MappingFileHandle mfh(file, true);
                std::vector<uint8_t> global_xor_key;
                uint8_t * pNonrandom = nullptr;
                {
                    uint8_t * pb = mfh.c_ptr();
                    int n = retrieve_key(pb, mfh.size(), global_xor_key_length, &global_xor_key);
                    if (n <= 0) {
                        CString msg;
                        msg.LoadString(IDS_STRING_UNSUPPORTED_FILE_CONTENT);
                        error_message->assign(msg);
                        *needRetry = true;
                        return false;
                    }
                    pNonrandom = pb + n;
                }

                PackageHeader header;
                memcpy(&header, pNonrandom, sizeof(PackageHeader));
                PackageHeader * pHeader = &header;
                for (size_t i = 0; i < global_xor_key_length; ++i) {
                    global_xor_key[i] ^= pHeader->xor_key[i];
                }
                xor(
                    &global_xor_key[0], global_xor_key.size(),
                    &header, &pHeader->xor_key[0] - reinterpret_cast<uint8_t*>(&header)
                );
                u_long magic = ntohl(pHeader->magic);
                u_long version = ntohl(pHeader->version) ^ version_mask;
                if (magic == global_magic && version == default_version) {
                    u_long number_of_recipients = ntohl(pHeader->number_of_recipients) ^ recipient_mask;
                    u_long number_of_files = ntohl(pHeader->number_of_files) ^ file_mask;
                    u_long content_offset = ntohl(pHeader->content_offset) ^ offset_mask;
                    u_long length = ntohl(pHeader->length) ^ length_mask;

                    uint8_t * pNext = pNonrandom;
                    pNext += sizeof(PackageHeader);
                    std::vector<uint8_t> key;

                    {
                        for (u_long i = 0; i < number_of_recipients; ++i) {
                            RecipientSection rs;
                            memcpy(&rs, pNext, sizeof(RecipientSection));
                            xor(&global_xor_key[0], global_xor_key.size(), &rs, &rs.content[0] - reinterpret_cast<uint8_t*>(&rs));
                            u_long content_length = ntohl(rs.content_length) ^ content_length_mask;

                            std::string pbk_id(&rs.id[0], &rs.id[0] + sizeof(rs.id));
                            auto kp = all_my_key_pairs.find(pbk_id);
                            if (kp != all_my_key_pairs.end()) {
                                //if (!kp->second.m_key.empty()) {
                                if (kp->second.m_key.length() > (SHA512_DIGEST_LENGTH * 2)) {
                                    //if (kp->second.m_key != strKey) {
                                    if (!ids_are_equal(strKey.c_str(), kp->second.m_key.c_str())) {
                                        continue;
                                    }
                                }
                                RecipientSection * prs = reinterpret_cast<RecipientSection*>(pNext);
                                if (pvk_decrypt(prs->content, content_length, password, kp->second, &key)) {
                                    used_one = kp;
                                    break;
                                }
                            }

                            pNext += (sizeof(rs.id) + sizeof(rs.content_length) + content_length);
                        }
                    }

                    if (!key.empty()) {
                        { // put here for userbility
                            if (output != nullptr) {
                                if (
                                    !check_sign(
                                        &global_xor_key[0], global_xor_key.size(),
                                        mfh.c_ptr(),
                                        length,
                                        mfh.size(),
                                        get_hash_name(pHeader).c_str(),
                                        &output->sender,
                                        error_message
                                    )
                                ) {
                                    return false;
                                }
                            } else {
                                return false;
                            }
                        }

                        retval = create_decryption_home_folder(file, &decryption_home_folder);
                        if (retval) {
                            std::unordered_set<std::basic_string<TCHAR>> file_names;
                            std::unordered_map<std::basic_string<TCHAR>, std::basic_string<TCHAR>> tmp_files;
                            pNext = mfh.c_ptr() + content_offset;
                            for (u_long i = 0; i < number_of_files; ++i) {
                                FileSection fs;
                                memcpy(&fs, pNext, sizeof(FileSection));
                                xor(&global_xor_key[0], global_xor_key.size(), &fs, &fs.content[0] - reinterpret_cast<uint8_t*>(&fs));
                                u_long name_length = ntohl(fs.name_length) ^ name_length_mask;
                                u_long content_length = ntohl(fs.content_length) ^ content_length_mask;

                                FileSection * pfs = reinterpret_cast<FileSection*>(pNext);
                                std::vector<char> filename_buf(pfs->content, pfs->content + name_length);
                                xor(&global_xor_key[0], global_xor_key.size(), &filename_buf[0], name_length);
                                auto file_name = utf8_decode(&filename_buf[0], name_length);
                                file_names.insert(file_name);
                                uint8_t * content_ptr = pfs->content + name_length;
                                std::basic_string<TCHAR> tmp_file;
                                retval = decrypt_file(
                                    key,
                                    content_ptr, content_length,
                                    decryption_home_folder.c_str(),
                                    file_name.c_str(),
                                    i,
                                    &tmp_file,
                                    error_message
                                );
                                if (retval) {
                                    tmp_files[file_name] = std::move(tmp_file);
                                    pNext += (sizeof(pfs->name_length) + sizeof(pfs->content_length) + name_length + content_length);
                                } else {
                                    break;
                                }
                            }
                            if (retval) {
                                update_key(all_my_key_pairs, used_one, password);
                                retval = (SetCurrentDirectory(decryption_home_folder.c_str()) != FALSE);
                                if (retval) {
                                    auto simple_file_names = simplify(file_names);
                                    for (auto i = tmp_files.begin(), e = tmp_files.end(); i != e; ++i) {
                                        auto simple_name = simple_file_names[i->first];
                                        move_file(i->second.c_str(), simple_name.c_str(), decryption_home_folder.c_str());
                                        output->files.insert(std::move(simple_name));
                                    }
                                    output->local_folder = decryption_home_folder;
                                }
                            }
                        }
                    } else {
                        CString msg;
                        msg.LoadString(IDS_STRING_NOT_FOR_YOU);
                        error_message->assign(msg);
                        retval = false;
                    }
                } else {
                    CString msg;
                    msg.LoadString(IDS_STRING_UNSUPPORTED_FILE_CONTENT);
                    error_message->assign(msg);
                    *needRetry = true;
                    retval = false;
                }
            } catch (std::exception const& e) {
                set_value(e.what(), error_message);
                retval = false;
            }
        } else {
            error_message->assign(Exception(ERROR_IPSEC_IKE_INVALID_HASH_ALG).getMessage());
        }
    } else {
        CString msg;
        msg.LoadString(IDS_STRING_NO_KEY_PAIR);
        error_message->assign(msg);
    }
    if (!retval && !decryption_home_folder.empty()) {
        remove_directory(decryption_home_folder.c_str());
    }
    return retval;
}

bool decrypt(
    const TCHAR * file,
    const char * password,
    MetaInformation * output,
    std::basic_string<TCHAR> * error_message
) {
    std::basic_string<TCHAR> msg;
    bool needRetry = false;
    bool retval = current_decrypt(file, password, output, &msg, &needRetry);
    if (!retval) {
        if (!needRetry) {
            error_message->swap(msg);
        }
        else {
            retval = v1_decrypt(file, password, output, error_message);
            if (!retval) {
                error_message->swap(msg);
            }
        }
    }
    return retval;
}