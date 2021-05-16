// Dispatcher.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "resource.h"
#include "Crypto.h"
#include "afxdialogex.h"
#include "Wizard.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

void TColorText::setTransparent( bool ATransparent )
{
    m_bTransparent = ATransparent;
    Invalidate( );
}

void TColorText::SetBackgroundColor( COLORREF AColor )
{
    m_backgroundColor = AColor;
    m_bTransparent = false;
    Invalidate( );
}

void TColorText::SetTextColor( COLORREF AColor )
{
    m_textColor = AColor;
    Invalidate( );
}

BEGIN_MESSAGE_MAP( TColorText, CStatic )
    ON_WM_CTLCOLOR_REFLECT( )
END_MESSAGE_MAP( )

HBRUSH TColorText::CtlColor(CDC* pDC, UINT)
{
    pDC->SetTextColor( m_textColor );
    pDC->SetBkMode( TRANSPARENT );  // we do not want to draw background when drawing text. 
    // background color comes from drawing the control background.

    if( m_bTransparent )
        return nullptr;  // return nullptr to indicate that the parent object 
    // should supply the brush. it has the appropriate background color.
    else
        return (HBRUSH) CreateSolidBrush( m_backgroundColor );  // color for the empty area of the control
}

///////////////////////////////////////////////////////////////////////////////
IMPLEMENT_DYNAMIC(CryptoPropertySheet, CPropertySheetEx)

CryptoPropertySheet::CryptoPropertySheet(
    HBITMAP hbmWatermark,
    HBITMAP hbmHeader,
    LPCTSTR pszCaption,
    CWnd *  pParentWnd,
    UINT    iSelectPage
) :
    CPropertySheetEx(
        pszCaption, pParentWnd, iSelectPage,
        hbmWatermark,
        nullptr,
        hbmHeader
    )
{
    m_psh.dwFlags |= PSP_USEICONID;
    m_psh.dwFlags |= PSH_WIZARD97;
    m_psh.dwFlags &= ~PSH_HASHELP;  // Lose the Help button

    AddPage( &m_operations );
    AddPage( &m_keyPair );
    AddPage( &m_pubkey );
    AddPage( &m_friend );
    //AddPage( &m_password );
    AddPage( &m_recipients );
    AddPage( &m_files_to_be_encrypted );
    AddPage( &m_decryption );
    SetWizardMode();
}

CryptoPropertySheet::~CryptoPropertySheet()
{
}

BEGIN_MESSAGE_MAP(CryptoPropertySheet, CPropertySheetEx)
    //{{AFX_MSG_MAP(CryptoPropertySheet)
        // NOTE - the ClassWizard will add and remove mapping macros here.
    //}}AFX_MSG_MAP
END_MESSAGE_MAP()


// OperationsPropertyPage dialog

IMPLEMENT_DYNAMIC(OperationsPropertyPage, CPropertyPage)

OperationsPropertyPage::OperationsPropertyPage() :
    CPropertyPage(
        OperationsPropertyPage::IDD,
        0,
        IDS_STRING_OPERATION,
        IDS_STRING_OPERATION_DETAIL
    )
{
    m_psp.dwFlags &= ~PSP_HASHELP;  // Lose the Help button
}

OperationsPropertyPage::~OperationsPropertyPage()
{
}

BOOL OperationsPropertyPage::OnInitDialog() 
{
	CPropertyPage::OnInitDialog();
    int id;
    if (key_pair_exists()) {
        m_operation = ENCRYPTION;
        id = IDC_RADIO_ENCRYPTION;
    } else {
        m_operation = CREATE_NEW_KEY_PAIR;
        id = IDC_RADIO_CREATE_NEW_KEYPAIR;
        GetDlgItem(IDC_RADIO_ADD_A_FRIEND)->EnableWindow(FALSE);
        GetDlgItem(IDC_RADIO_EXPORT_PUBLIC_KEY)->EnableWindow(FALSE);
        GetDlgItem(IDC_RADIO_ENCRYPTION)->EnableWindow(FALSE);
        GetDlgItem(IDC_RADIO_DECRYPTION)->EnableWindow(FALSE);
    }
    CheckDlgButton(id, BST_CHECKED);
	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}

void OperationsPropertyPage::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(OperationsPropertyPage, CPropertyPage)
END_MESSAGE_MAP()

// OperationsPropertyPage message handlers
BOOL OperationsPropertyPage::OnSetActive() 
{
    CPropertySheet * pps = (CPropertySheet *)GetParent();
    pps->SetWizardButtons(PSWIZB_NEXT);
    return CPropertyPage::OnSetActive();
}

LRESULT OperationsPropertyPage::OnWizardNext() 
{
    if (IsDlgButtonChecked(IDC_RADIO_CREATE_NEW_KEYPAIR)) {
        m_operation = CREATE_NEW_KEY_PAIR;
    } else if (IsDlgButtonChecked(IDC_RADIO_EXPORT_PUBLIC_KEY)) {
        m_operation = EXPORT_PUBLIC_KEY;
    } else if (IsDlgButtonChecked(IDC_RADIO_ADD_A_FRIEND)) {
        m_operation = ADD_A_FRIEND;
    } else if (IsDlgButtonChecked(IDC_RADIO_ENCRYPTION)) {
        m_operation = ENCRYPTION;
    } else if (IsDlgButtonChecked(IDC_RADIO_DECRYPTION)) {
        m_operation = DECRYPTION;
    } else {
        ASSERT(FALSE);
    }

    LRESULT next_page;

    switch (m_operation) {
    case CREATE_NEW_KEY_PAIR:
        next_page = IDD_CRYPTO_NEW_KEY_PAIR;
        break;
    case EXPORT_PUBLIC_KEY:
        next_page = IDD_CRYPTO_EXPORT_PUBLIC_KEY;
        break;
    case ADD_A_FRIEND:
        next_page = IDD_CRYPTO_ADD_A_FRIEND;
        break;
    case ENCRYPTION:
        next_page = IDD_CRYPTO_RECIPIENTS;
        break;
    case DECRYPTION:
        next_page = IDD_CRYPTO_DECRYPTION;
        break;
    default:
        ASSERT(FALSE);
    }
    return next_page;
}

// KeyPairPropertyPage dialog

IMPLEMENT_DYNAMIC(KeyPairPropertyPage, CPropertyPage)

KeyPairPropertyPage::KeyPairPropertyPage() :
	CPropertyPage(
        KeyPairPropertyPage::IDD,
        0,
        IDS_STRING_KEY_PAIR,
        IDS_STRING_KEY_PAIR_DETAIL
    ),
    m_bn(nullptr),
    m_rsa(nullptr),
    m_saved(false)
{
    m_psp.dwFlags &= ~PSP_HASHELP;  // Lose the Help button
}

KeyPairPropertyPage::~KeyPairPropertyPage()
{
    RSA_free(m_rsa);
    BN_free(m_bn);
}

void KeyPairPropertyPage::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
}

BOOL KeyPairPropertyPage::OnInitDialog()
{
    CPropertyPageEx::OnInitDialog();
    GetDlgItem(IDC_EDIT_BITS)->SetWindowText(_T("4096"));
    return TRUE;  // return TRUE unless you set the focus to a control
                  // EXCEPTION: OCX Property Pages should return FALSE
}

BEGIN_MESSAGE_MAP(KeyPairPropertyPage, CPropertyPage)
    ON_BN_CLICKED(IDC_BUTTON_GENERATE_KEY_PAIR, &KeyPairPropertyPage::OnGenerateKeyPair)
END_MESSAGE_MAP()


// KeyPairPropertyPage message handlers
BOOL KeyPairPropertyPage::OnSetActive()
{
    CPropertySheet * pps = ( CPropertySheet * )GetParent();
    DWORD flags = PSWIZB_BACK;
    if (m_rsa != nullptr) {
        flags |= PSWIZB_NEXT;
    }
    pps->SetWizardButtons(flags);
    return CPropertyPage::OnSetActive();
}

LRESULT KeyPairPropertyPage::OnWizardNext()
{
    LRESULT next_page = IDD_CRYPTO_OPERTIONS_EXPORT_PUBLIC_KEY;
    if (!m_saved) {
        char password[128] = "";
        ::GetWindowTextA(GetDlgItem(IDC_EDIT_PASSWORD)->m_hWnd, password, sizeof(password) - 1);
        if (key_pair_exists()) {
            CString msg;
            msg.LoadString(IDS_STRING_KEY_PAIR_EXISTS);
            if (theApp.ShowQuestion(msg, this) == ANSWER_YES) {
                if (!archive_key_pair()) {
                    msg.LoadString(IDS_STRING_CANNOT_ARCHIVE_KEY_PAIR);
                    theApp.ShowMessage(msg, MB_ICONERROR, this);
                    return -1;
                }
            } else {
                return -1;
            }
        }

        if (save_key_pair(m_rsa, password)) {
            m_saved = true;
        } else {
            CString msg;
            msg.LoadString(IDS_STRING_CANNOT_SAVE_KEY_PAIR);
            theApp.ShowMessage(msg, MB_ICONERROR, this);
            next_page = -1;
        }
    }
    return next_page;
}

void KeyPairPropertyPage::OnGenerateKeyPair()
{
    if (m_rsa != nullptr) {
        RSA_free(m_rsa), m_rsa = nullptr;
        BN_free(m_bn);
    }

    m_saved = false;
    CString strPassword, strPassword2;
    GetDlgItem(IDC_EDIT_PASSWORD)->GetWindowText(strPassword);
    GetDlgItem(IDC_EDIT_PASSWORD2)->GetWindowText(strPassword2);
    if (strPassword.IsEmpty() || strPassword2.IsEmpty()) {
        strPassword.LoadString(IDS_STRING_PASSWORD_EMPTY);
        theApp.ShowMessage(strPassword, MB_ICONWARNING, this);
    } else if (strPassword != strPassword2) {
        strPassword.LoadString(IDS_STRING_PASSWORD_DO_NOT_MATCH);
        theApp.ShowMessage(strPassword, MB_ICONWARNING, this);
    } else {
        CString strBits;
        GetDlgItem(IDC_EDIT_BITS)->GetWindowText(strBits);
        int bits = _ttoi(strBits);
        m_bn = BN_new();
        m_rsa = RSA_new();
        if (m_rsa == nullptr || m_bn == nullptr) {
            strPassword2.LoadString(IDS_STRING_CANNOT_CREATE_KEY_PAIR);
            theApp.ShowMessage(strPassword, MB_ICONERROR, this);
            BN_free(m_bn);
            RSA_free(m_rsa), m_rsa = nullptr;
        } else {
            BN_set_word(m_bn, RSA_F4);
            theApp.BeginWaitCursor();
            int result = RSA_generate_key_ex(m_rsa, bits, m_bn, nullptr);
            theApp.EndWaitCursor();
            if (result == 0) {
                strPassword2.LoadString(IDS_STRING_CANNOT_CREATE_KEY_PAIR);
                theApp.ShowMessage(strPassword, MB_ICONERROR, this);
                BN_free(m_bn);
                RSA_free(m_rsa), m_rsa = nullptr;
            } else {
                std::string strPbk;
                if (export_public_key(m_rsa, &strPbk)) {
                    std::string strPbk2(ntorn(strPbk.c_str()));
                    ::SetWindowTextA(::GetDlgItem(m_hWnd, IDC_EDIT_PUBLIC_KEY), strPbk2.c_str());
                    CPropertySheet * pps = ( CPropertySheet * )GetParent();
                    pps->SetWizardButtons(PSWIZB_BACK|PSWIZB_NEXT);
                } else {
                    strPassword.LoadString(IDS_STRING_CANNOT_EXPORT_PUBLIC_KEY);
                    theApp.ShowMessage(strPassword, MB_ICONERROR, this);
                }
            }
        }
    }
}

// ExportPublicKeyPropertyPage dialog

IMPLEMENT_DYNAMIC(ExportPublicKeyPropertyPage, CPropertyPage)

ExportPublicKeyPropertyPage::ExportPublicKeyPropertyPage() :
    CPropertyPage(
        ExportPublicKeyPropertyPage::IDD,
        0,
        IDS_STRING_EXPORT_PUBKEY,
        IDS_STRING_EXPORT_PUBKEY_DETAIL
    )
{
    m_psp.dwFlags &= ~PSP_HASHELP;  // Lose the Help button
}

ExportPublicKeyPropertyPage::~ExportPublicKeyPropertyPage()
{
}

void ExportPublicKeyPropertyPage::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
}

BOOL ExportPublicKeyPropertyPage::OnSetActive()
{
    CString strFile;
    GetDlgItem(IDC_EDIT_FILE_NAME)->GetWindowText(strFile);
    DWORD dwFlags = PSWIZB_BACK | PSWIZB_DISABLEDFINISH;
    if (!strFile.IsEmpty()) {
        dwFlags = PSWIZB_BACK | PSWIZB_FINISH;
    }
    CryptoPropertySheet * pps = ( CryptoPropertySheet * )GetParent();
    ASSERT(
        pps->m_operations.m_operation == OperationsPropertyPage::CREATE_NEW_KEY_PAIR ||
        pps->m_operations.m_operation == OperationsPropertyPage::EXPORT_PUBLIC_KEY
    );
    pps->SetWizardButtons(dwFlags);
    return CPropertyPage::OnSetActive();
}

LRESULT ExportPublicKeyPropertyPage::OnWizardBack()
{
    LRESULT previous_page = IDD_CRYPTO_OPERTIONS;
    CryptoPropertySheet * pps = ( CryptoPropertySheet * )GetParent();
    ASSERT(
        pps->m_operations.m_operation == OperationsPropertyPage::CREATE_NEW_KEY_PAIR ||
        pps->m_operations.m_operation == OperationsPropertyPage::EXPORT_PUBLIC_KEY
    );
    if (pps->m_operations.m_operation == OperationsPropertyPage::CREATE_NEW_KEY_PAIR) {
        previous_page = IDD_CRYPTO_NEW_KEY_PAIR;
    }
    return previous_page;
}

BOOL ExportPublicKeyPropertyPage::OnWizardFinish() 
{
	// TODO: Add your specialized code here and/or call the base class
    CString strFile;
    GetDlgItem(IDC_EDIT_FILE_NAME)->GetWindowText(strFile);
    ASSERT(!strFile.IsEmpty());
    FILE * pf = nullptr;
    std::string strPbk;
    if (get_public_key(&strPbk)) {
        //ASSERT(is_valid_public_key(strPbk.c_str()));
        _tfopen_s(&pf, strFile, _T("w"));
        if (pf != nullptr) {
            fwrite(strPbk.c_str(), sizeof(char), strPbk.length(), pf);
            fclose(pf);
            return CPropertyPageEx::OnWizardFinish();
        }
    }
    strFile.LoadString(IDS_STRING_CANNOT_EXPORT_PUBLIC_KEY);
    theApp.ShowMessage(strFile, MB_ICONERROR, this);
	return FALSE;
}

BEGIN_MESSAGE_MAP(ExportPublicKeyPropertyPage, CPropertyPage)
    ON_BN_CLICKED(IDC_BUTTON_BROWSE_FILE, &ExportPublicKeyPropertyPage::OnBrowseFile)
END_MESSAGE_MAP()

// ExportPublicKeyPropertyPage message handlers
void ExportPublicKeyPropertyPage::OnBrowseFile()
{
    // TODO: Add your control notification handler code here
    CString filter;
    filter.LoadString(IDS_STRING_PEM_SUFFIX_FILTER);
    TCHAR userName[UNLEN + 1] = _T("");
    DWORD len = sizeof(userName)/sizeof(userName[0]);
    GetUserName(userName, &len);
    CFileDialog file(
        FALSE,
        _T("*.pem"),
        userName,
        OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT,
        filter,
        this
    );
    INT_PTR result = file.DoModal();
    if (result == IDOK) {
        GetDlgItem(IDC_EDIT_FILE_NAME)->SetWindowText(file.GetPathName());
        CryptoPropertySheet * pps = ( CryptoPropertySheet * )GetParent();
        pps->SetWizardButtons(PSWIZB_BACK | PSWIZB_FINISH);
    }
}

// FriendPropertyPage dialog

IMPLEMENT_DYNAMIC(FriendPropertyPage, CPropertyPage)

FriendPropertyPage::FriendPropertyPage() :
	CPropertyPage(
        FriendPropertyPage::IDD,
        0,
        IDS_STRING_FRIEND,
        IDS_STRING_FRIEND_DETAIL
    )
{
    m_psp.dwFlags &= ~PSP_HASHELP;  // Lose the Help button
}

FriendPropertyPage::~FriendPropertyPage()
{
}

void FriendPropertyPage::DoDataExchange(CDataExchange* pDX)
{
    CPropertyPage::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_COMBO_FRIEND_NAME, m_comboBoxFriendNames);
}

BOOL FriendPropertyPage::OnInitDialog()
{
    CPropertyPageEx::OnInitDialog();
    CheckDlgButton(IDC_RADIO_FROM_FILE, BST_CHECKED);
    GetDlgItem(IDC_EDIT_PUBLIC_KEY_CONTENT)->EnableWindow(FALSE);
    std::unordered_map<std::basic_string<TCHAR>, std::string> friends;
    if (get_friends(&friends)) {
        for (auto i = friends.begin(), ie = friends.end(); i != ie; ++i) {
            m_friendNames.emplace_back(i->first.c_str());
            m_comboBoxFriendNames.AddString(i->first.c_str());
        }
    }
    return TRUE;  // return TRUE unless you set the focus to a control
                  // EXCEPTION: OCX Property Pages should return FALSE
}

CString FriendPropertyPage::getFriendName()
{
    CString strName;
    int index = m_comboBoxFriendNames.GetCurSel();
    if (index >= 0) {
        strName = m_friendNames[index];
    } else {
        m_comboBoxFriendNames.GetWindow(GW_CHILD)->GetWindowText(strName);
    }
    return strName;
}

void FriendPropertyPage::check_validity()
{
    CString strName = getFriendName();
    DWORD dwFlags = PSWIZB_BACK | PSWIZB_DISABLEDFINISH;
    if (
        !strName.IsEmpty() &&
        (
            (IsDlgButtonChecked(IDC_RADIO_FROM_FILE) && !m_strPbkFromFile.empty()) ||
            (IsDlgButtonChecked(IDC_RADIO_FROM_TEXT) && !m_strPbkFromText.empty())
        )
    ) {
        dwFlags = PSWIZB_BACK | PSWIZB_FINISH;
    }
    CPropertySheet * pps = (CPropertySheet *)GetParent();
    pps->SetWizardButtons(dwFlags);
}

BOOL FriendPropertyPage::OnSetActive()
{
    check_validity();
    return CPropertyPage::OnSetActive();
}

LRESULT FriendPropertyPage::OnWizardBack()
{
    return IDD_CRYPTO_OPERTIONS;
}

BOOL FriendPropertyPage::OnWizardFinish()
{
    CString strName = getFriendName();
    if (strName.GetLength() > 2048) {
        strName.LoadString(IDS_STRING_NAME_IS_TOO_LONG);
        theApp.ShowMessage(strName, MB_ICONERROR, this);
        return FALSE;
    }

    const char * strPbk = nullptr;
    size_t nPbk = 0;
    if (IsDlgButtonChecked(IDC_RADIO_FROM_FILE)) {
        strPbk = m_strPbkFromFile.c_str();
        nPbk = m_strPbkFromFile.length();
    } else {
        strPbk = m_strPbkFromText.c_str();
        nPbk = m_strPbkFromText.length();
    }
    if (add_a_friend(strName, strPbk, nPbk)) {
        return CPropertyPageEx::OnWizardFinish();
    } else {
        strName.LoadString(IDS_STRING_CANNOT_ADD_A_FRIEND);
        theApp.ShowMessage(strName, MB_ICONERROR, this);
        return FALSE;
    }
}

BEGIN_MESSAGE_MAP(FriendPropertyPage, CPropertyPage)
    ON_BN_CLICKED(IDC_RADIO_FROM_FILE, &FriendPropertyPage::OnClickedFromFile)
    ON_BN_CLICKED(IDC_RADIO_FROM_TEXT, &FriendPropertyPage::OnClickedFromText)
    ON_BN_CLICKED(IDC_BUTTON_BROWSE_FILE_FOR_IMPORT, &FriendPropertyPage::OnBrowseFileForImport)
    ON_EN_CHANGE(IDC_EDIT_PUBLIC_KEY_CONTENT, &FriendPropertyPage::OnChangePublicKeyContent)
    ON_CBN_EDITCHANGE(IDC_COMBO_FRIEND_NAME, &FriendPropertyPage::OnChangeFriendName)
END_MESSAGE_MAP()

// FriendPropertyPage message handlers
void FriendPropertyPage::toggle(BOOL enabled)
{
    GetDlgItem(IDC_EDIT_PUBLIC_KEY_CONTENT)->EnableWindow(enabled);
    GetDlgItem(IDC_EDIT_PUBLIC_KEY_FILE_FOR_IMPORT)->EnableWindow(!enabled);
    GetDlgItem(IDC_BUTTON_BROWSE_FILE_FOR_IMPORT)->EnableWindow(!enabled);
    check_validity();
}

void FriendPropertyPage::OnClickedFromFile()
{
    // TODO: Add your control notification handler code here
    toggle(FALSE);
}

void FriendPropertyPage::OnClickedFromText()
{
    // TODO: Add your control notification handler code here
    toggle(TRUE);
}

void FriendPropertyPage::OnBrowseFileForImport()
{
    CString filter;
    filter.LoadString(IDS_STRING_PEM_SUFFIX_FILTER);
    CFileDialog file(
        TRUE,
        _T("*.pem"),
        nullptr,
        OFN_READONLY|OFN_PATHMUSTEXIST|OFN_FILEMUSTEXIST,
        filter,
        this
    );
    INT_PTR result = file.DoModal();
    if (result == IDOK) {
        CString strFile = file.GetPathName();
        std::string content;
        if (get_file_content(strFile, &content) && is_valid_public_key(content.c_str())) {
            m_strPbkFromFile.swap(content);
        } else {
            m_strPbkFromFile.clear();
            CString msg;
            msg.LoadString(IDS_STRING_CANNOT_IMPORT_PUBLIC_KEY);
            theApp.ShowMessage(msg, MB_ICONWARNING, this);
        }
        GetDlgItem(IDC_EDIT_PUBLIC_KEY_FILE_FOR_IMPORT)->SetWindowText(strFile);
    }
    check_validity();
}

void FriendPropertyPage::OnChangeFriendName()
{
    check_validity();
}

void FriendPropertyPage::OnChangePublicKeyContent()
{
    CString strPbk;
    GetDlgItem(IDC_EDIT_PUBLIC_KEY_CONTENT)->GetWindowText(strPbk);
    USES_CONVERSION;
    const TCHAR * ptcPbk = strPbk;
    std::string content(T2A(ptcPbk));
    if (is_valid_public_key(content.c_str())) {
        m_strPbkFromText.swap(content);
    } else {
        m_strPbkFromText.clear();
    }
    check_validity();
}

// RecipientsPropertyPage dialog

IMPLEMENT_DYNAMIC(RecipientsPropertyPage, CPropertyPage)

RecipientsPropertyPage::RecipientsPropertyPage() :
    CPropertyPage(
        RecipientsPropertyPage::IDD,
        0,
        IDS_STRING_RECIPIENTS,
        IDS_STRING_RECIPIENTS_DETAIL
    )
{
    m_psp.dwFlags &= ~PSP_HASHELP;  // Lose the Help button
}

RecipientsPropertyPage::~RecipientsPropertyPage()
{
}

void RecipientsPropertyPage::DoDataExchange(CDataExchange* pDX)
{
    CPropertyPage::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_LIST_RECIPIENTS, m_listFriends);
}

BEGIN_MESSAGE_MAP(RecipientsPropertyPage, CPropertyPage)
    ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST_RECIPIENTS, &RecipientsPropertyPage::OnFindRecipients)
END_MESSAGE_MAP()

BOOL RecipientsPropertyPage::OnInitDialog()
{
    CPropertyPageEx::OnInitDialog();
    {
        const int c_nColumn = 1;
        CString strFriends;
        strFriends.LoadString(IDS_STRING_FRIENDS);

        static TCHAR * s_strColumnLabel[c_nColumn] =
        {
            const_cast<TCHAR*>(static_cast<LPCTSTR>(strFriends))
        };

        static int s_anColumnFormat[c_nColumn] =
        {
            LVCFMT_LEFT
        };

        static int s_anColumnWidth[c_nColumn] =
        {
            484
        };

        theApp.InitializeCListCtrl(
            &m_listFriends,
            c_nColumn,
            s_strColumnLabel,
            s_anColumnFormat,
            s_anColumnWidth,
            &theApp.m_imgSelection
        );
    }
    {
        get_friends(&m_friends);

        LVITEM lvi = {0};
        int iIndex = 0;
        for (auto i = m_friends.begin(), e = m_friends.end(); i != e; ++i) {
            lvi.mask = LVIF_TEXT | LVIF_STATE | LVIF_IMAGE;
            lvi.iItem = iIndex;
            lvi.iSubItem = 0;

            lvi.pszText = const_cast<LPTSTR>(i->first.c_str());

            lvi.iImage = 0;
            lvi.stateMask = LVIS_STATEIMAGEMASK;
            lvi.state = INDEXTOSTATEIMAGEMASK(1);

            m_listFriends.InsertItem( &lvi );
            ++iIndex;
        }
    }

    return TRUE;
}

void RecipientsPropertyPage::check_validity()
{
    CPropertySheet * pps = ( CPropertySheet * )GetParent();
    DWORD flags = PSWIZB_BACK;
    if (!m_recipients.empty()) {
        flags |= PSWIZB_NEXT;
    }
    pps->SetWizardButtons(flags);
}

BOOL RecipientsPropertyPage::OnSetActive()
{
    check_validity();
    return CPropertyPage::OnSetActive();
}

LRESULT RecipientsPropertyPage::OnWizardBack()
{
    return IDD_CRYPTO_OPERTIONS;
}

std::vector<std::string> RecipientsPropertyPage::get_public_key_of_recipients() const
{
    std::vector<std::string> retval;
    for (auto i = m_recipients.begin(), e = m_recipients.end(); i != e; ++i) {
        auto j = m_friends.find(*i);
        if (j != m_friends.end()) {
            retval.push_back(j->second);
        }
    }
    return retval;
}

// RecipientsPropertyPage message handlers

void RecipientsPropertyPage::OnFindRecipients(NMHDR *, LRESULT * pResult)
{
    // LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
    // TODO: Add your control notification handler code here
    *pResult = 0;

    m_recipients.clear();
    POSITION pos = m_listFriends.GetFirstSelectedItemPosition();
    while (pos != nullptr) {
        int row = m_listFriends.GetNextSelectedItem(pos);
        m_recipients.emplace_back(m_listFriends.GetItemText(row, 0));
    }
    check_validity();
}

// FilesToBeEncryptedPropertyPage dialog

IMPLEMENT_DYNAMIC(FilesToBeEncryptedPropertyPage, CPropertyPage)

FilesToBeEncryptedPropertyPage::FilesToBeEncryptedPropertyPage() :
    CPropertyPage(
        FilesToBeEncryptedPropertyPage::IDD,
        0,
        IDS_STRING_FILES_TO_BE_ENCRYPTED,
        IDS_STRING_FILES_TO_BE_ENCRYPTED_DETAIL
    ),
    m_total_file_size(0)
{
    m_psp.dwFlags &= ~PSP_HASHELP;  // Lose the Help button
}

FilesToBeEncryptedPropertyPage::~FilesToBeEncryptedPropertyPage()
{
}

void FilesToBeEncryptedPropertyPage::DoDataExchange(CDataExchange* pDX)
{
    CPropertyPage::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_LIST_FILES_TO_BE_ENCRYPTED, m_listFiles);
    DDX_Control(pDX, IDC_STATIC_SIGNATURE, m_signature);
}

BOOL FilesToBeEncryptedPropertyPage::OnInitDialog()
{
    CPropertyPageEx::OnInitDialog();
    {
        const int c_nColumn = 2;
        CString strName, strSize;
        strName.LoadString(IDS_STRING_FILE_NAME);
        strSize.LoadString(IDS_STRING_FILE_SIZE);

        static TCHAR * s_strColumnLabel[c_nColumn] =
        {
            const_cast<TCHAR*>(static_cast<LPCTSTR>(strName)),
            const_cast<TCHAR*>(static_cast<LPCTSTR>(strSize))
        };

        static int s_anColumnFormat[c_nColumn] =
        {
            LVCFMT_LEFT,
            LVCFMT_LEFT
        };

        static int s_anColumnWidth[c_nColumn] =
        {
            394, 90
        };

        theApp.InitializeCListCtrl(
            &m_listFiles,
            c_nColumn,
            s_strColumnLabel,
            s_anColumnFormat,
            s_anColumnWidth,
            nullptr
        );
    }

    CTime date(CTime::GetCurrentTime());
    TCHAR buf[64];
    _stprintf_s(
        buf, _T("%d_%d_%d_%02d%02d%02d.dat"),
        date.GetYear(), date.GetMonth(), date.GetDay(),
        date.GetHour(), date.GetMinute(), date.GetSecond()
    );
    GetDlgItem(IDC_EDIT_FILE_FOR_SAVING)->SetWindowText(buf);

    return TRUE;
}

void FilesToBeEncryptedPropertyPage::check_validity()
{
    bool output_file_is_ready = false;
    CString file_name;
    GetDlgItem(IDC_EDIT_FILE_FOR_SAVING)->GetWindowText(file_name);
    if (!file_name.IsEmpty()) {
        auto dir = dirname(file_name);
        if (dir.empty() || is_folder(dir.c_str())) {
            output_file_is_ready = true;
        }
    }
    DWORD dwFlags = PSWIZB_BACK | PSWIZB_DISABLEDFINISH;
    if (!m_files.empty() && m_total_file_size < FILE_SIZE_LIMITATION && output_file_is_ready) {
        dwFlags = PSWIZB_BACK | PSWIZB_FINISH;
    }
    CPropertySheet * pps = ( CPropertySheet * )GetParent();
    pps->SetWizardButtons(dwFlags);
}

BOOL FilesToBeEncryptedPropertyPage::OnSetActive()
{
    check_validity();
    return CPropertyPage::OnSetActive();
}

LRESULT FilesToBeEncryptedPropertyPage::OnWizardBack()
{
    return IDD_CRYPTO_RECIPIENTS;
}

BEGIN_MESSAGE_MAP(FilesToBeEncryptedPropertyPage, CPropertyPage)
    ON_BN_CLICKED(IDC_BUTTON_BROWSE_FILES_TO_ENCRYPT, &FilesToBeEncryptedPropertyPage::OnBrowseFilesToEncrypt)
    ON_BN_CLICKED(IDC_BUTTON_BROWSE_FILE_FOR_SAVEING, &FilesToBeEncryptedPropertyPage::OnBrowseFileForSaving)
    ON_EN_CHANGE(IDC_EDIT_FILE_FOR_SAVING, &FilesToBeEncryptedPropertyPage::OnChangeFileForSaving)
    ON_EN_CHANGE(IDC_EDIT_PVK_PASSWORD, &FilesToBeEncryptedPropertyPage::OnChangePvkPassword)
END_MESSAGE_MAP()

// FilesToBeEncryptedPropertyPage message handlers
void FilesToBeEncryptedPropertyPage::add_file(std::basic_string<TCHAR> && file_name)
{
    const TCHAR * ptcFileName = file_name.c_str();
    size_t bytes = get_file_size(ptcFileName);
    m_total_file_size += bytes;
    TCHAR buf[16] = _T("");
    _stprintf_s(buf, _T("%u"), static_cast<unsigned int>(bytes));
    {
        LVITEM lvi = {0};
        int iIndex = static_cast<int>(m_files.size());
        lvi.mask = LVIF_TEXT | LVIF_STATE;
        lvi.iItem = iIndex;
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPTSTR>(ptcFileName);
        lvi.stateMask = LVIS_STATEIMAGEMASK;
        lvi.state = INDEXTOSTATEIMAGEMASK(1);
        m_listFiles.InsertItem(&lvi);
        m_listFiles.SetItemText(iIndex, 1, buf);
    }
    m_files.insert(std::move(file_name));
}

void FilesToBeEncryptedPropertyPage::OnBrowseFilesToEncrypt()
{
    CString anyFileFilter;
    anyFileFilter.LoadString(IDS_STRING_ANY_FILE_SUFFIX_FILTER);

    CFileDialog FileDlg(
        TRUE,
        _T("*.*"), nullptr,
        OFN_READONLY|OFN_ALLOWMULTISELECT|OFN_PATHMUSTEXIST|OFN_FILEMUSTEXIST,
        anyFileFilter
    );

    std::vector<TCHAR> buf(131072);
    FileDlg.GetOFN().lpstrFile = &buf[0];
    FileDlg.GetOFN().nMaxFile = static_cast<DWORD>(buf.size());
    if( FileDlg.DoModal() == IDOK ) {
        TCHAR fullpath[_MAX_PATH * 2];
        const TCHAR * folder = &buf[0];
        if (!is_file(folder)) {
            if (m_dirname.empty()) {
                m_dirname = folder;
            }
            for (
                const TCHAR * h = folder + lstrlen(folder) + 1;
                *h != 0;
                h += lstrlen(h) + 1
            ) {
                _stprintf_s(fullpath, _T("%s\\%s"), folder, h);
                std::basic_string<TCHAR> tmp(fullpath);
                if (m_files.find(tmp) == m_files.end()) {
                    add_file(std::move(tmp));
                }
            }
            if (m_total_file_size >= FILE_SIZE_LIMITATION) {
                anyFileFilter.LoadString(IDS_STRING_TOTAL_FILE_SIZE_TOO_BIG);
                theApp.ShowMessage(anyFileFilter, MB_ICONERROR, this);
            }
        } else {
            std::basic_string<TCHAR> tmp(folder);
            if (m_dirname.empty()) {
                m_dirname = dirname(folder);
            }
            if (m_files.find(tmp) == m_files.end()) {
                add_file(std::move(tmp));
            }
        }
    }
    check_validity();
}

void FilesToBeEncryptedPropertyPage::OnBrowseFileForSaving()
{
    CString filter, strDefaultName;
    filter.LoadString(IDS_STRING_ANY_FILE_SUFFIX_FILTER);
    strDefaultName.LoadString(IDS_STRING_DEFAULT_FILE_NAME_FOR_ENCRYPTION);
    CFileDialog file(
        FALSE,
        _T("*.*"),
        nullptr, //strDefaultName,
        OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT,
        filter,
        this
    );
    INT_PTR result = file.DoModal();
    if (result == IDOK) {
        GetDlgItem(IDC_EDIT_FILE_FOR_SAVING)->SetWindowText(file.GetPathName());
    }
    check_validity();
}

void FilesToBeEncryptedPropertyPage::OnChangeFileForSaving()
{
    check_validity();
}

void FilesToBeEncryptedPropertyPage::OnChangePvkPassword()
{
    // TODO: how to show signature is enabled
    char password[128] = "";
    ::GetWindowTextA(::GetDlgItem(m_hWnd, IDC_EDIT_PVK_PASSWORD), password, sizeof(password)-1);
    RSAKey rsa(rebuild_private_key(password));

    CString msg;
    if (rsa.valid()) {
        m_signature.SetBackgroundColor(RGB(0, 255, 0));
        msg.LoadString(IDS_STRING_SIGNATURE_ENABLED);
    } else {
        m_signature.SetBackgroundColor(RGB(220, 220, 220));
        msg.LoadString(IDS_STRING_SIGNATURE_PROMPT);
    }
    m_signature.SetWindowText(msg);
}

BOOL FilesToBeEncryptedPropertyPage::OnWizardFinish()
{
    char password[128] = "";
    ::GetWindowTextA(::GetDlgItem(m_hWnd, IDC_EDIT_PVK_PASSWORD), password, sizeof(password)-1);
    RSAKey rsa(rebuild_private_key(password));

    CryptoPropertySheet * pps = (CryptoPropertySheet *)GetParent();
    CString file_name;
    std::basic_string<TCHAR> errorMessage;
    GetDlgItem(IDC_EDIT_FILE_FOR_SAVING)->GetWindowText(file_name);
    if (file_name.Find(_T('\\')) < 0) {
        if (!m_dirname.empty()) {
            CString tmp = file_name;
            file_name = m_dirname.c_str();
            file_name.AppendChar(_T('\\'));
            file_name.Append(tmp);
        }
    }

    theApp.BeginWaitCursor();
    auto successful = encrypt(m_files, pps->m_recipients.get_public_key_of_recipients(), file_name, &errorMessage, rsa);
    theApp.EndWaitCursor();
    if (successful) {
    #if defined(DEBUG) || defined(_DBG) || defined(_DEBUG)
        errorMessage.clear();
        decrypt(file_name, password, nullptr, &errorMessage);
        if (!errorMessage.empty()) {
            DeleteFile(file_name);
            file_name.Format(IDS_STRING_CORRUPTED_FILE, errorMessage.c_str());
            theApp.ShowMessage(file_name, MB_ICONERROR, this);
        }
        else {
            LPCTSTR output_folder = _T("C:\\Users\\Cyril Gao\\Downloads");
            MetaInformation mi;
            mi.local_folder = std::basic_string<TCHAR>(output_folder);
            for (size_t count = 0; ; ++count) {
                DeleteFile(file_name);
                bool retval = encrypt(m_files, pps->m_recipients.get_public_key_of_recipients(), file_name, &errorMessage, rsa);
                ASSERT(retval);
                if (retval) {
                    retval = decrypt(file_name, password, &mi, &errorMessage);
                    mi.destroy();
                    mi.local_folder = std::basic_string<TCHAR>(output_folder);
                    ASSERT(retval);
                }
            }
        }
    #endif
        return CPropertyPageEx::OnWizardFinish();
    } else {
        theApp.ShowMessage(errorMessage.c_str(), MB_ICONERROR, this);
        return FALSE;
    }
}

#if 0
// PasswordPropertyPage dialog

IMPLEMENT_DYNAMIC(PasswordPropertyPage, CPropertyPage)

PasswordPropertyPage::PasswordPropertyPage() :
    CPropertyPage(
        PasswordPropertyPage::IDD,
        0,
        IDS_STRING_PVK_PASSWORD,
        IDS_STRING_PVK_PASSWORD_DETAIL
    ),
    m_rsa(nullptr)
{
    m_psp.dwFlags &= ~PSP_HASHELP;  // Lose the Help button
}

PasswordPropertyPage::~PasswordPropertyPage()
{
    RSA_free(m_rsa);
}

void PasswordPropertyPage::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(PasswordPropertyPage, CPropertyPage)
    ON_EN_CHANGE(IDC_EDIT_PVK_PASSWORD, &PasswordPropertyPage::OnChangePvkPassword)
END_MESSAGE_MAP()

BOOL PasswordPropertyPage::OnInitDialog()
{
    CPropertyPage::OnInitDialog();
    CryptoPropertySheet * pps = (CryptoPropertySheet *)GetParent();
    if (pps->m_operations.m_operation != OperationsPropertyPage::ENCRYPTION) {
        GetDlgItem(IDC_STATIC_PASSWORD)->ShowWindow(SW_HIDE);
    }

    return TRUE;
}

void PasswordPropertyPage::check_validity()
{
    DWORD flags = PSWIZB_BACK;
    CryptoPropertySheet * pps = (CryptoPropertySheet *)GetParent();
    if (pps->m_operations.m_operation == OperationsPropertyPage::ENCRYPTION) {
        flags |= PSWIZB_NEXT;
    } else {
        if (m_rsa != nullptr) {
            flags |= PSWIZB_NEXT;
        }
    }
    pps->SetWizardButtons(flags);
}

BOOL PasswordPropertyPage::OnSetActive()
{
    check_validity();
    return CPropertyPage::OnSetActive();
}

LRESULT PasswordPropertyPage::OnWizardBack()
{
    return IDD_CRYPTO_OPERTIONS;
}

LRESULT PasswordPropertyPage::OnWizardNext()
{
    CryptoPropertySheet * pps = (CryptoPropertySheet *)GetParent();
    if (pps->m_operations.m_operation == OperationsPropertyPage::ENCRYPTION) {
        return IDD_CRYPTO_RECIPIENTS;
    } else {
        return IDD_CRYPTO_DECRYPTION;
    }
}

// PasswordPropertyPage message handlers

void PasswordPropertyPage::OnChangePvkPassword()
{
    char buf[128] = "";
    ::GetWindowTextA(::GetDlgItem(m_hWnd, IDC_EDIT_PVK_PASSWORD), buf, sizeof(buf)-1);
    RSA_free(m_rsa);
    m_rsa = rebuild_private_key(buf);
    check_validity();
}
#endif

// DecryptionPropertyPage dialog

IMPLEMENT_DYNAMIC(DecryptionPropertyPage, CPropertyPage)

DecryptionPropertyPage::DecryptionPropertyPage() :
    CPropertyPage(
        DecryptionPropertyPage::IDD,
        0,
        IDS_STRING_DECRYPTION,
        IDS_STRING_DECRYPTION_DETAIL
    )
{
    m_psp.dwFlags &= ~PSP_HASHELP;  // Lose the Help button
}

DecryptionPropertyPage::~DecryptionPropertyPage()
{
}

void DecryptionPropertyPage::DoDataExchange(CDataExchange* pDX)
{
    CPropertyPage::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(DecryptionPropertyPage, CPropertyPage)
    ON_BN_CLICKED(IDC_BUTTON_BROWSE_FILE_FOR_DECRYPTION, &DecryptionPropertyPage::OnBrowseFileForDecryption)
    ON_EN_CHANGE(IDC_EDIT_PVK_PASSWORD, &DecryptionPropertyPage::OnChangePvkPassword)
END_MESSAGE_MAP()

BOOL DecryptionPropertyPage::OnInitDialog()
{
    CPropertyPageEx::OnInitDialog();
    CheckDlgButton(IDC_CHECK_AUTO_DELETE_DECRYPTED_FILES, BST_CHECKED);
    return TRUE;
}

void DecryptionPropertyPage::check_validity()
{
    DWORD dwFlags = PSWIZB_BACK | PSWIZB_DISABLEDFINISH;
    if (!m_info.is_clean()) {
        dwFlags = PSWIZB_BACK | PSWIZB_FINISH;
    }
    CryptoPropertySheet * pps = ( CryptoPropertySheet * )GetParent();
    pps->SetWizardButtons(dwFlags);
}

BOOL DecryptionPropertyPage::OnSetActive()
{
    check_validity();
    return CPropertyPage::OnSetActive();
}

LRESULT DecryptionPropertyPage::OnWizardBack()
{
    return IDD_CRYPTO_OPERTIONS;
}

void DecryptionPropertyPage::OnCancel()
{
    clean();
    CPropertyPage::OnCancel();
}

BOOL DecryptionPropertyPage::OnWizardFinish()
{
    clean();
    return CPropertyPage::OnWizardFinish();
}

// DecryptionPropertyPage message handlers
void DecryptionPropertyPage::clean()
{
    if (IsDlgButtonChecked(IDC_CHECK_AUTO_DELETE_DECRYPTED_FILES)) {
        GetDlgItem(IDC_EDIT_DECRYPTION_RESULT)->SetWindowText(_T(""));
        std::basic_string<TCHAR> local_folder(m_info.local_folder);
        try {
            m_info.destroy();
        } catch (std::exception const&) {
            CString msg;
            msg.Format(IDS_STRING_REMOVE_FOLDER_MANUALLY, local_folder.c_str());
            theApp.ShowMessage(msg, MB_ICONWARNING, this);
        }
    }
}

void DecryptionPropertyPage::showDecryptionResult()
{
    CString format;
    format.LoadString(IDS_STRING_SENDER_FORMAT);
    TCHAR buf[_MAX_PATH + 64];
    CString information_string;
    if (!m_info.sender.empty()) {
        _stprintf_s(buf, format, m_info.sender.c_str());
        information_string += buf;
    }
    if (m_info.files.size() == 1) {
        format.LoadString(IDS_STRING_FILE_FORMAT);
    } else {
        format.LoadString(IDS_STRING_FILES_FORMAT);
    }
    information_string += format;
    for (auto i = m_info.files.begin(), e = m_info.files.end(); i != e; ++i) {
        information_string.Append(_T("    "));
        information_string += i->c_str();
        information_string.Append(_T("\r\n"));
    }
    format.LoadString(IDS_STRING_LOCAL_FOLDER_FORMAT);
    _stprintf_s(buf, format, m_info.local_folder.c_str());
    information_string += buf;
    GetDlgItem(IDC_EDIT_DECRYPTION_RESULT)->SetWindowText(information_string);
}

void DecryptionPropertyPage::OnBrowseFileForDecryption()
{
    char password[128] = "";
    ::GetWindowTextA(::GetDlgItem(m_hWnd, IDC_EDIT_PVK_PASSWORD), password, sizeof(password)-1);

    CString filter;
    filter.LoadString(IDS_STRING_ANY_FILE_SUFFIX_FILTER);
    CFileDialog file(
        TRUE,
        _T("*.*"),
        nullptr,
        OFN_READONLY|OFN_PATHMUSTEXIST|OFN_FILEMUSTEXIST,
        filter,
        this
    );
    INT_PTR result = file.DoModal();
    if (result == IDOK) {
        GetDlgItem(IDC_EDIT_FILE_FOR_DECRYPTION)->SetWindowText(file.GetPathName());
        GetDlgItem(IDC_EDIT_PVK_PASSWORD)->SetFocus();
        decrypt(true);
        check_validity();
    }
}

void DecryptionPropertyPage::OnChangePvkPassword()
{
    decrypt(false);
    check_validity();
}

void DecryptionPropertyPage::decrypt(bool showing_error_message)
{
    CString strFile;
    GetDlgItem(IDC_EDIT_FILE_FOR_DECRYPTION)->GetWindowText(strFile);
    if (is_file(strFile)) {
        char password[128] = "";
        ::GetWindowTextA(::GetDlgItem(m_hWnd, IDC_EDIT_PVK_PASSWORD), password, sizeof(password)-1);
        if (password[0] != '\0') {
            std::basic_string<TCHAR> errorMessage;
            MetaInformation newInfo;
            theApp.BeginWaitCursor();
            bool successful = ::decrypt(strFile, password, &newInfo, &errorMessage);
            theApp.EndWaitCursor();
            if (successful) {
                clean();
                m_info.swap(std::move(newInfo));
                showDecryptionResult();
            } else {
                if (showing_error_message) {
                    theApp.ShowMessage(errorMessage.c_str(), MB_ICONERROR, this);
                }
                GetDlgItem(IDC_EDIT_DECRYPTION_RESULT)->SetWindowText(errorMessage.c_str());
            }
        }
    }
}
