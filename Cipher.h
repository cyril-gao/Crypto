#ifndef CRYPTO_CIPHER_H_19741129
#define CRYPTO_CIPHER_H_19741129

#include "Common.h"
#include <openssl/ec.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

class EvpMdCtx
{
    EVP_MD_CTX * m_ctx;
    const EVP_MD * m_type;
public:
    EvpMdCtx(const char * name) : m_ctx(EVP_MD_CTX_new()), m_type(nullptr)
    {
        if (m_ctx == nullptr) {
            throw std::bad_alloc();
        }
        m_type = nullptr;
        if (_stricmp(name, "SHA256") == 0) {
            m_type = EVP_sha256();
        } else if (_stricmp(name, "SHA224") == 0) {
            m_type = EVP_sha224();
        } else if (_stricmp(name, "SHA384") == 0) {
            m_type = EVP_sha384();
        } else if (_stricmp(name, "SHA512") == 0) {
            m_type = EVP_sha512();
        } else if (_stricmp(name, "shake128") == 0) {
            m_type = EVP_shake128();
        } else if (_stricmp(name, "shake256") == 0) {
            m_type = EVP_shake256();
        } else {
            EVP_MD_CTX_free(m_ctx), m_ctx = nullptr;
            throw Exception(ERROR_IPSEC_IKE_INVALID_HASH_ALG);
        }
        if (!EVP_DigestInit_ex(m_ctx, m_type, nullptr)) {
            EVP_MD_CTX_free(m_ctx), m_ctx = nullptr;
            throw Exception(PEERDIST_ERROR_NOT_INITIALIZED);
        }
    }
    void update(const uint8_t * input, size_t input_len)
    {
        if (!EVP_DigestUpdate(m_ctx, input, input_len)) {
            throw Exception(ERROR_FUNCTION_NOT_CALLED);
        }
    }
    std::vector<uint8_t> close()
    {
        unsigned n = EVP_MD_size(m_type);
        std::vector<uint8_t> retval(n);
        if (!EVP_DigestFinal_ex(m_ctx, &retval[0], &n)) {
            throw Exception(SEC_E_ENCRYPT_FAILURE);
        }
        return retval;
    }
    ~EvpMdCtx()
    {
        EVP_MD_CTX_free(m_ctx);
    }
};

class CipherCtx
{
protected:
    EVP_CIPHER_CTX * m_ctx;
    enum { BLOCK_SIZE = 4096 };
    CipherCtx(
        const std::vector<uint8_t> & key,
        int (*init)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *, const unsigned char *, const unsigned char *)
    ) : m_ctx(EVP_CIPHER_CTX_new())
    {
        assert(key.size() == (32 + 16));
        if (m_ctx == nullptr) {
            throw std::bad_alloc();
        }
        if (!init(m_ctx, EVP_aes_256_cbc(), nullptr, &key[0], &key[32])) {
            EVP_CIPHER_CTX_free(m_ctx), m_ctx = nullptr;
            throw Exception(PEERDIST_ERROR_NOT_INITIALIZED);
        }
    }

    //suppose that output is big enough
    size_t update(
        const uint8_t * input, size_t input_length, uint8_t * output,
        int (*updater)(EVP_CIPHER_CTX*, unsigned char *, int *, const unsigned char *, int),
        DWORD error_code
    )  {
        int output_size = static_cast<int>(BLOCK_SIZE + EVP_CIPHER_CTX_block_size(m_ctx));
        size_t retval = 0;
        for (
            int outl = output_size, inl = BLOCK_SIZE <= input_length ? BLOCK_SIZE : static_cast<int>(input_length);
            input_length != 0;
            input_length -= inl, inl = BLOCK_SIZE <= input_length ? BLOCK_SIZE : static_cast<int>(input_length), outl = output_size
        ) {
            if (updater(m_ctx, output, &outl, input, inl)) {
                input += inl;
                output += outl;
                retval += outl;
            } else {
                throw Exception(error_code);
            }
        }
        return retval;
    }

    //suppose that output is big enough
    size_t close(
        uint8_t * output,
        int (*clean)(EVP_CIPHER_CTX *, unsigned char *, int *),
        DWORD error_code
    )  {
        int outlen = BLOCK_SIZE;
        if (!clean(m_ctx, output, &outlen)) {
            throw Exception(error_code);
        }
        return static_cast<size_t>(outlen);
    }
        
    ~CipherCtx()
    {
        EVP_CIPHER_CTX_free(m_ctx);
    }
};

class EncryptionCipherCtx : public CipherCtx
{
public:
    EncryptionCipherCtx(const std::vector<uint8_t> & key) : CipherCtx(key, EVP_EncryptInit_ex)
    {
    }

    //suppose that output is big enough
    size_t update(const uint8_t * input, size_t input_len, uint8_t * output)
    {
        return CipherCtx::update(input, input_len, output, EVP_EncryptUpdate, SEC_E_ENCRYPT_FAILURE);
    }

    //suppose that output is big enough
    size_t close(uint8_t * output)
    {
        return CipherCtx::close(output, EVP_EncryptFinal_ex, SEC_E_ENCRYPT_FAILURE);
    }
};

class DecryptionCipherCtx : public CipherCtx
{
public:
    DecryptionCipherCtx(const std::vector<uint8_t> & key) : CipherCtx(key, EVP_DecryptInit_ex)
    {
    }

    //suppose that output is big enough
    size_t update(const uint8_t * input, size_t input_len, uint8_t * output)
    {
        return CipherCtx::update(input, input_len, output, EVP_DecryptUpdate, SEC_E_DECRYPT_FAILURE);
    }

    //suppose that output is big enough
    size_t close(uint8_t * output)
    {
        return CipherCtx::close(output, EVP_DecryptFinal_ex, SEC_E_DECRYPT_FAILURE);
    }
};

class EvpPkey
{
    EVP_PKEY * m_key;
public:
    EvpPkey(RSA * rsa) : m_key(EVP_PKEY_new())
    {
        if (m_key == nullptr) {
            throw std::bad_alloc();
        }
        if (!EVP_PKEY_set1_RSA(m_key, rsa)) {
            EVP_PKEY_free(m_key);
            m_key = nullptr;
        }
    }
    ~EvpPkey()
    {
        EVP_PKEY_free(m_key);
    }
    operator EVP_PKEY*() { return m_key; }
};

class RSAKey
{
    RSA * m_rsa;
public:
    explicit RSAKey(RSA * rsa = nullptr) : m_rsa(rsa) {}
    ~RSAKey() { RSA_free(m_rsa); }
    operator RSA*() { return m_rsa; }
    bool valid() const
    {
        return m_rsa != nullptr;
    }
};

bool save_key_pair(RSA * key_pair, char * password);
bool export_public_key(RSA * key_pair, std::string * output);

RSA * rebuild_public_key_from_file(const TCHAR * file);
RSA * rebuild_public_key_from_text(const char * input);
RSA * rebuild_private_key(const char * pem_string, const char * password);
RSA * rebuild_private_key(const char * password);

bool encrypt(
    const std::unordered_set<std::basic_string<TCHAR>> & files,
    const std::vector<std::string> & public_keys,
    const TCHAR * output_file,
    std::basic_string<TCHAR> * error_message,
    RSA * rsa = nullptr,
    const char * hash = nullptr
);

struct MetaInformation
{
    std::basic_string<TCHAR> sender;
    std::unordered_set<std::basic_string<TCHAR>> files;
    std::basic_string<TCHAR> local_folder;

    bool is_clean() const
    {
        return files.empty() || local_folder.empty();
    }

    void destroy();

    void swap(MetaInformation && other)
    {
        sender.swap(other.sender);
        files.swap(other.files);
        local_folder.swap(other.local_folder);
    }
};

bool decrypt(
    const TCHAR * file,
    const char * password,
    MetaInformation * output,
    std::basic_string<TCHAR> * error_message
);

std::vector<int> get_index_of_set_bits(const void * input, size_t size, size_t n);

void generate_random_bytes_and_xor_key(size_t key_length, std::vector<uint8_t> * random_bytes, std::vector<uint8_t> * key);
int retrieve_key(const void * input, size_t size, size_t key_length, std::vector<uint8_t> * key);

#endif //CRYPTO_CIPHER_H_19741129
