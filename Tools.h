#ifndef CRYPTO_TOOLS_H_19741129
#define CRYPTO_TOOLS_H_19741129

#include "Common.h"

void xor(
    const uint8_t * key, size_t key_len,
    void * inout, size_t input_len
);
bool get_file_content(const TCHAR * file_name, std::string * output);
bool key_pair_exists();
bool archive_key_pair();

struct KeyPairStrings
{
    std::string m_pbk;
    std::string m_pvk;
    std::string m_key;

    KeyPairStrings() {}
    KeyPairStrings(std::string && pbk, std::string && pvk) :
        m_pbk(std::move(pbk)), m_pvk(std::move(pvk))
    {
    }
    KeyPairStrings(std::string && pbk, std::string && pvk, std::string && key) :
        m_pbk(std::move(pbk)), m_pvk(std::move(pvk)), m_key(std::move(key))
    {
    }
};

bool get_all_my_key_pairs(std::unordered_map<std::string, KeyPairStrings> * output);
bool get_public_key_id(std::string * output);
bool get_public_key(std::string * output);
bool is_valid_public_key(const char * input);
bool public_key_is_valid(const char * b64str);
bool update_key(
    std::unordered_map<std::string, KeyPairStrings> & all_key_pairs,
    std::unordered_map<std::string, KeyPairStrings>::iterator used_one,
    const char * password
);

std::string ntorn(const char * input);

//bool friend_exists(const TCHAR * name);
bool add_a_friend(const TCHAR * name, const char * strPbk, size_t nPbk);

bool get_friends(std::unordered_map<std::basic_string<TCHAR>, std::string> * friends);
bool find_friend(std::string const & pbk_id, std::string * pbk, std::basic_string<TCHAR> * name);

bool md5(const char * input, std::string * output);
//bool sha512(const char * input, std::string * output);
bool password_to_id(const char * input, std::string * output);
bool ids_are_equal(const char * id1, const char * id2);
bool file_to_id(const wchar_t * file, std::string* output);

std::vector<std::basic_string<TCHAR>> split(const TCHAR * input, TCHAR tch);
std::basic_string<TCHAR> join(std::basic_string<TCHAR> const * from, int n, TCHAR tch);

#endif //CRYPTO_TOOLS_H_19741129
