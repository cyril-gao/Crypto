// Dispatcher.h : main header file for the DISPATCHER application
//

#if !defined(AFX_DISPATCHER_H__26D33AD2_C5EC_4598_8692_09CB29229167__INCLUDED_)
#define AFX_DISPATCHER_H__26D33AD2_C5EC_4598_8692_09CB29229167__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

#include "Tools.h"
#include "Cipher.h"
#include "File.h"
#include "afxcmn.h"
#include "afxwin.h"

class TColorText : public CStatic
{
protected:
    DECLARE_MESSAGE_MAP( )

public:
    TColorText() :
        m_bTransparent(true),
        m_backgroundColor(RGB(255, 255, 255)),
        m_textColor(RGB(0, 0, 0))
    {
    }
    // make the background transparent (or if ATransparent == true, restore the previous background color)
    void setTransparent( bool ATransparent = true );
    // set background color and make the background opaque
    void SetBackgroundColor( COLORREF );
    void SetTextColor( COLORREF );
protected:
    HBRUSH CtlColor( CDC* pDC, UINT nCtlColor );

private:
    bool m_bTransparent;
    COLORREF m_backgroundColor;  // default is white (in case someone sets opaque without setting a color)
    COLORREF m_textColor;  // default is black. it would be more clean 
    // to not use the color before set with SetTextColor(..), but whatever...
};

// OperationsPropertyPage dialog

class OperationsPropertyPage : public CPropertyPage
{
	DECLARE_DYNAMIC(OperationsPropertyPage)
public:
	OperationsPropertyPage();
	virtual ~OperationsPropertyPage();
    enum Operation {
        CREATE_NEW_KEY_PAIR,
        EXPORT_PUBLIC_KEY,
        ADD_A_FRIEND,
        ENCRYPTION,
        DECRYPTION
    };

    Operation m_operation;
// Dialog Data
	enum { IDD = IDD_CRYPTO_OPERTIONS };
public:
	virtual BOOL OnSetActive();
	virtual LRESULT OnWizardNext();
protected:
    virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
};

// KeyPairPropertyPage dialog

class KeyPairPropertyPage : public CPropertyPage
{
	DECLARE_DYNAMIC(KeyPairPropertyPage)
    BIGNUM * m_bn;
    RSA * m_rsa;
    bool m_saved;
public:
	KeyPairPropertyPage();
	virtual ~KeyPairPropertyPage();

// Dialog Data
	enum { IDD = IDD_CRYPTO_NEW_KEY_PAIR };
    virtual BOOL OnSetActive();
	virtual LRESULT OnWizardNext();
protected:
    virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
    afx_msg void OnGenerateKeyPair();
};

// ExportPublicKeyPropertyPage dialog

class ExportPublicKeyPropertyPage : public CPropertyPage
{
	DECLARE_DYNAMIC(ExportPublicKeyPropertyPage)

public:
	ExportPublicKeyPropertyPage();
	virtual ~ExportPublicKeyPropertyPage();

// Dialog Data
	enum { IDD = IDD_CRYPTO_OPERTIONS_EXPORT_PUBLIC_KEY };
	virtual BOOL OnSetActive();
    virtual LRESULT OnWizardBack();
	virtual BOOL OnWizardFinish();
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
    afx_msg void OnBrowseFile();
};

// FriendPropertyPage dialog

class FriendPropertyPage : public CPropertyPage
{
	DECLARE_DYNAMIC(FriendPropertyPage)
    std::string m_strPbkFromFile;
    std::string m_strPbkFromText;
    std::vector<CString> m_friendNames;
    CComboBox m_comboBoxFriendNames;

    CString getFriendName();
public:
	FriendPropertyPage();
	virtual ~FriendPropertyPage();

// Dialog Data
	enum { IDD = IDD_CRYPTO_ADD_A_FRIEND };
	virtual BOOL OnSetActive();
    virtual LRESULT OnWizardBack();
	virtual BOOL OnWizardFinish();
protected:
    virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

    void toggle(BOOL enabled);
    void check_validity();
	DECLARE_MESSAGE_MAP()
public:
    afx_msg void OnClickedFromFile();
    afx_msg void OnClickedFromText();
    afx_msg void OnBrowseFileForImport();
    afx_msg void OnChangePublicKeyContent();
    afx_msg void OnChangeFriendName();
};

// RecipientsPropertyPage dialog

class RecipientsPropertyPage : public CPropertyPage
{
	DECLARE_DYNAMIC(RecipientsPropertyPage)
    std::unordered_map<std::basic_string<TCHAR>, std::string> m_friends;
    std::vector<std::basic_string<TCHAR>> m_recipients;
public:
	RecipientsPropertyPage();
	virtual ~RecipientsPropertyPage();

    std::vector<std::string> get_public_key_of_recipients() const;

// Dialog Data
	enum { IDD = IDD_CRYPTO_RECIPIENTS };
	virtual BOOL OnSetActive();
    virtual LRESULT OnWizardBack();
protected:
    virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

    void check_validity();
	DECLARE_MESSAGE_MAP()
public:
    CListCtrl m_listFriends;
    afx_msg void OnFindRecipients(NMHDR *pNMHDR, LRESULT *pResult);
};

// FilesToBeEncryptedPropertyPage dialog

class FilesToBeEncryptedPropertyPage : public CPropertyPage
{
    enum { FILE_SIZE_LIMITATION = 1024 * 1024 * 512 };
	DECLARE_DYNAMIC(FilesToBeEncryptedPropertyPage)
    void check_validity();
    void add_file(std::basic_string<TCHAR> && file_name);
    std::basic_string<TCHAR> m_dirname;
    size_t m_total_file_size;
    TColorText m_signature;
public:
	FilesToBeEncryptedPropertyPage();
	virtual ~FilesToBeEncryptedPropertyPage();

// Dialog Data
	enum { IDD = IDD_CRYPTO_FILES_TO_BE_ENCRYPTED };
	virtual BOOL OnSetActive();
    virtual LRESULT OnWizardBack();
    virtual BOOL OnWizardFinish();
protected:
    virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
    CListCtrl m_listFiles;
    std::unordered_set<std::basic_string<TCHAR>> m_files;
    afx_msg void OnBrowseFilesToEncrypt();
    afx_msg void OnBrowseFileForSaving();
    afx_msg void OnChangeFileForSaving();
    afx_msg void OnChangePvkPassword();
};

#if 0
// PasswordPropertyPage dialog
class PasswordPropertyPage : public CPropertyPage
{
	DECLARE_DYNAMIC(PasswordPropertyPage)

    void check_validity();
public:
	PasswordPropertyPage();
	virtual ~PasswordPropertyPage();

    RSA * m_rsa;
// Dialog Data
	enum { IDD = IDD_CRYPTO_PASSWORD };

	virtual BOOL OnSetActive();
    virtual LRESULT OnWizardBack();
    virtual LRESULT OnWizardNext();
protected:
    virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
    afx_msg void OnChangePvkPassword();
};
#endif

// DecryptionPropertyPage dialog

class DecryptionPropertyPage : public CPropertyPage
{
	DECLARE_DYNAMIC(DecryptionPropertyPage)
    void check_validity();
    MetaInformation m_info;
    void clean();
    void showDecryptionResult();
    void decrypt(bool showing_error_message);
public:
	DecryptionPropertyPage();
	virtual ~DecryptionPropertyPage();

// Dialog Data
	enum { IDD = IDD_CRYPTO_DECRYPTION };

	virtual BOOL OnSetActive();
    virtual LRESULT OnWizardBack();
	virtual void OnCancel();
	virtual BOOL OnWizardFinish();
protected:
    virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
    afx_msg void OnBrowseFileForDecryption();
    afx_msg void OnChangePvkPassword();
};

class CryptoPropertySheet : public CPropertySheetEx
{
	DECLARE_DYNAMIC(CryptoPropertySheet)
public:
	CryptoPropertySheet(
		HBITMAP hbmWatermark,
		HBITMAP hbmHeader,
		LPCTSTR pszCaption,
		CWnd* pParentWnd = nullptr,
        UINT iSelectPage = 0
	);
	virtual ~CryptoPropertySheet();

protected:
	//{{AFX_MSG(DispatcherPropertySheet)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
public:
	OperationsPropertyPage m_operations;
    KeyPairPropertyPage m_keyPair;
    ExportPublicKeyPropertyPage m_pubkey;
    FriendPropertyPage m_friend;
    //PasswordPropertyPage m_password;
    RecipientsPropertyPage m_recipients;
    FilesToBeEncryptedPropertyPage m_files_to_be_encrypted;
    DecryptionPropertyPage m_decryption;
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_DISPATCHER_H__26D33AD2_C5EC_4598_8692_09CB29229167__INCLUDED_)
