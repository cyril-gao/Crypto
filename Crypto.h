
// Crypto.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols
#include "Tools.h"

// CCryptoApp:
// See Crypto.cpp for the implementation of this class
//
enum Answer { ANSWER_YES, ANSWER_NO };

class CCryptoApp : public CWinApp
{
public:
	CCryptoApp();

    CImageList  m_imgSelection;
// Overrides
public:
	virtual BOOL InitInstance();
    void CreateBoldFont(CFont * pout);

#if ( defined( UNICODE ) || defined( _UNICODE ) )
	#define ShowMessage ShowMessageW
#else
	#define ShowMessage ShowMessageA
#endif

	void ShowMessageA( LPCSTR msg, UINT nType, CWnd * pWnd = nullptr );
	void ShowMessageW( LPCWSTR msg, UINT nType, CWnd * pWnd = nullptr );
	Answer ShowQuestion( LPCTSTR msg, CWnd * pWnd = nullptr );

    void InitializeCListCtrl(
		CListCtrl  * pCtrlList,
		int          nColumn,
		TCHAR      * astrColumnLabel[],
		int          anColumnFormat[],
		int          anColumnWidth[],
		CImageList * pImageList
	);
// Implementation
	DECLARE_MESSAGE_MAP()
};

extern CCryptoApp theApp;