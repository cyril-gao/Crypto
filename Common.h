#ifndef CRYPTO_COMMON_H_19741129
#define CRYPTO_COMMON_H_19741129

#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <atlbase.h>
#include <stdexcept>
#include <memory>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <string>

#pragma comment(lib, "ws2_32.lib")

std::basic_string<TCHAR> strerror(DWORD err);

class Exception : public std::exception
{
    std::basic_string<TCHAR> m_strErrorMessage;
#if ( defined( UNICODE ) || defined( _UNICODE ) )
    std::string m_aem;
#endif
public:
    Exception( DWORD dwError );

    Exception( LPCTSTR msg );

    LPCTSTR getMessage() const { return m_strErrorMessage.c_str(); }

    const char * what() const
    {
    #if ( defined( UNICODE ) || defined( _UNICODE ) )
        return m_aem.c_str();
    #else
        return m_strErrorMessage.c_str();
    #endif
    }
};

inline void unicode_to_ansi(const wchar_t * from, std::string & to)
{
    USES_CONVERSION;
    to = W2A( from );
}

#endif //CRYPTO_COMMON_H_19741129
