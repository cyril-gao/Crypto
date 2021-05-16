
// Crypto.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "Crypto.h"
#include "Wizard.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CCryptoApp

BEGIN_MESSAGE_MAP(CCryptoApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CCryptoApp construction

CCryptoApp::CCryptoApp()
{
	// support Restart Manager
	m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;

	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}


// The one and only CCryptoApp object

CCryptoApp theApp;


// CCryptoApp initialization
void CCryptoApp::CreateBoldFont( CFont * pout )
{
    pout->CreateFont(
        14, 0, 0, 0, FW_SEMIBOLD,
        FALSE, FALSE, 0, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, 
        CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, 
        DEFAULT_PITCH|FF_SWISS,
        _T("MS Shell Dlg")
    );
}

namespace
{
    class ArgList
    {
        LPWSTR* m_list;
        int m_args;
    public:
        ArgList(): m_list(nullptr), m_args(0)
        {
            m_list = CommandLineToArgvW(GetCommandLineW(), &m_args);
        }
        ArgList(const ArgList&) = delete;
        ArgList& operator=(const ArgList&) = delete;
        bool is_valid() const { return m_list != nullptr; }
        int length() const { return m_args; }
        LPCWSTR operator[](int i) const
        {
            ASSERT(m_list != nullptr && i < m_args);
            return m_list[i];
        }
        ~ArgList()
        {
            if (m_list != nullptr) {
                LocalFree(m_list);
            }
        }
    };
}

BOOL CCryptoApp::InitInstance()
{
#if defined(DEBUG) || defined(_DBG) || defined(_DEBUG)
    {
        std::vector<uint8_t> random_bytes, key, new_key;
        generate_random_bytes_and_xor_key(16, &random_bytes, &key);

        int n = retrieve_key(&random_bytes[0], random_bytes.size(), 16, &new_key);
        ASSERT(n > 0 && n <= static_cast<int>(random_bytes.size()));
        ASSERT(key == new_key);
    }
#endif
	// InitCommonControlsEx() is required on Windows XP if an application
	// manifest specifies use of ComCtl32.dll version 6 or later to enable
	// visual styles.  Otherwise, any window creation will fail.
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// Set this to include all the common control classes you want to use
	// in your application.
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);
    OpenSSL_add_all_algorithms();
    OPENSSL_init_crypto(0, nullptr);
    EVP_add_cipher(EVP_aes_256_cbc());

	CWinApp::InitInstance();
	AfxEnableControlContainer();

	// Create the shell manager, in case the dialog contains
	// any shell tree view or shell list view controls.
	//CShellManager *pShellManager = new CShellManager;

	// Standard initialization
	// If you are not using these features and wish to reduce the size
	// of your final executable, you should remove from the following
	// the specific initialization routines you do not need
	// Change the registry key under which our settings are stored
	// TODO: You should modify this string to be something appropriate
	// such as the name of your company or organization
	//SetRegistryKey(_T("Local AppWizard-Generated Applications"));

    CString title;
    CBitmap bmpWatermark;
    CBitmap bmpHeader;

    VERIFY( bmpWatermark.LoadBitmap( IDB_BITMAP_WATERMARK ) );
    VERIFY( bmpHeader.LoadBitmap( IDB_BITMAP_KEY ) );
    title.LoadString( IDS_STRING_PROGRAM_TITLE );
    try {
        if (!m_imgSelection.Create(16, 16, ILC_COLOR24 | ILC_MASK, 7, 1)) {
            throw Exception(GetLastError());
        }
        CBitmap bm;
        bm.LoadBitmap(IDB_BITMAP_ITEM);
        m_imgSelection.Add(&bm, RGB(0, 0, 0));

#if 0
        ArgList arg_list;
        int len = arg_list.length();
        if (len <= 1) {
#endif
            CryptoPropertySheet wizard(bmpWatermark, bmpHeader, title);
            m_pMainWnd = &wizard;
            INT_PTR nResponse = wizard.DoModal();
            if (nResponse == IDOK)
            {
                // TODO: Place code here to handle when the dialog is
                //  dismissed with OK
            }
            else if (nResponse == IDCANCEL)
            {
                // TODO: Place code here to handle when the dialog is
                //  dismissed with Cancel
            }
#if 0
        }
        else {
            switch (len)
            {
            /*
            case 2:
                if (is_file(arg_list[1])) {
                    std::string id;
                    CString msg;
                    if (file_to_id(arg_list[1], &id)) {
                        CString fingerprint(id.c_str());
                        msg.Format(IDS_STRING_FINGERPRINT_MSG, fingerprint);
                        theApp.ShowMessage(msg, MB_ICONINFORMATION);
                    }
                    else {
                        msg.LoadString(IDS_STRING_FAILED_TO_GEN_FINGERPRINT);
                        theApp.ShowMessage(msg, MB_ICONERROR);
                    }
                }
                break;
            */
            case 3:
            {
                std::string id, fid;
                if (is_file(arg_list[1])) {
                    unicode_to_ansi(arg_list[2], id);
                    file_to_id(arg_list[1], &fid);
                }
                else if (is_file(arg_list[2])) {
                    unicode_to_ansi(arg_list[1], id);
                    file_to_id(arg_list[2], &fid);
                }
                if (!id.empty() || !fid.empty()) {
                    bool equal = ids_are_equal(id.c_str(), fid.c_str());
                    CString msg;
                    if (equal) {
                        msg.LoadString(IDS_STRING_FINGERPRINT_MATCH);
                    }
                    else {
                        msg.LoadString(IDS_STRING_FINGERPRINT_DOES_NOT_MATCH);
                    }
                    theApp.ShowMessage(msg, equal ? MB_ICONINFORMATION : MB_ICONERROR);
                }
            }
            default:
                break;
            }
        }
#endif
    } catch (std::exception const& e) {
        ShowMessageA(e.what(), MB_ICONERROR);
    }

	// Delete the shell manager created above.
	//if (pShellManager != nullptr)
	//{
		//delete pShellManager;
	//}

	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.
	return FALSE;
}

namespace
{
    class CMessageDialog : public CDialog
    {
        LPCTSTR    m_ptcMsg;
        UINT       m_nType;
        HBITMAP    m_bitmap;

        CFont      m_boldFont;

        CMessageDialog( CWnd * = nullptr );
    public:
        ~CMessageDialog()
        {
            if ( m_bitmap != nullptr ) {
                DeleteObject( m_bitmap );
            }
            if ( static_cast<HFONT>( m_boldFont ) != nullptr ) {
                m_boldFont.DeleteObject();
            }
        }
        static void ShowMessageA( LPCSTR msg, UINT nType, CWnd * pWnd );
        static void ShowMessageW( LPCWSTR msg, UINT nType, CWnd * pWnd );
        static Answer ShowQuestion( LPCTSTR msg, CWnd * pWnd );

    // Dialog Data
        //{{AFX_DATA(CMessageDialog)
        enum { IDD = IDD_CRYPTO_MESSAGEBOX };
        CStatic     m_flag;
        CStatic     m_msg;

        //}}AFX_DATA

        // ClassWizard generated virtual function overrides
        //{{AFX_VIRTUAL(CMessageDialog)
    protected:
        virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
        //}}AFX_VIRTUAL

    // Implementation
    protected:
        //{{AFX_MSG(CMessageDialog)
        virtual BOOL OnInitDialog();
        //}}AFX_MSG
        DECLARE_MESSAGE_MAP()
    };

    CMessageDialog::CMessageDialog( CWnd * parent ) :
        CDialog(CMessageDialog::IDD, parent), m_bitmap( nullptr )
    {
        //{{AFX_DATA_INIT(CMessageDialog)
        //}}AFX_DATA_INIT
    }

    void CMessageDialog::DoDataExchange(CDataExchange* pDX)
    {
        CDialog::DoDataExchange(pDX);
        //{{AFX_DATA_MAP(CMessageDialog)
        DDX_Control(pDX, IDC_STATIC_BMP, m_flag);
        DDX_Control(pDX, IDC_STATIC_MESSAGE, m_msg);
        //}}AFX_DATA_MAP
    }

    BEGIN_MESSAGE_MAP(CMessageDialog, CDialog)
        //{{AFX_MSG_MAP(CMessageDialog)
        //}}AFX_MSG_MAP
    END_MESSAGE_MAP()

    BOOL CMessageDialog::OnInitDialog() 
    {
        CDialog::OnInitDialog();
        // TODO: Add extra initialization here
        theApp.CreateBoldFont( &m_boldFont );

        CString title;
        title.LoadString( IDS_STRING_PROGRAM_TITLE );
        SetWindowText( title );

        int id = IDB_BITMAP_WARNING;
        switch ( m_nType ) {
        case MB_ICONERROR:
            id = IDB_BITMAP_ERROR;
            break;
        case MB_YESNO:
            id = IDB_BITMAP_QUESTION;
            break;
        default:
            id = IDB_BITMAP_WARNING;
            break;
        }
        m_bitmap = reinterpret_cast<HBITMAP>(
            ::LoadImage( AfxGetResourceHandle(), MAKEINTRESOURCE(id), IMAGE_BITMAP, 0, 0, 0 )
        );
        m_flag.SetBitmap( m_bitmap );

        m_msg.SetFont( &m_boldFont );
        m_msg.SetWindowText( m_ptcMsg );

        if ( m_nType != MB_YESNO ) {
            GetDlgItem( IDOK )->ShowWindow( SW_HIDE );
            CString strOK;
            strOK.LoadString( IDS_STRING_OK );
            GetDlgItem( IDCANCEL )->SetWindowText( strOK );
        }
        return TRUE;  // return TRUE unless you set the focus to a control
                      // EXCEPTION: OCX Property Pages should return FALSE
    }

    void CMessageDialog::ShowMessageA( LPCSTR msg, UINT nType, CWnd * pWnd )
    {
        CMessageDialog ad( pWnd );
    #if ( defined( UNICODE ) || defined( _UNICODE ) )
        USES_CONVERSION;
        ad.m_ptcMsg = A2W( msg );
    #else
        ad.m_ptcMsg = msg;
    #endif
        ad.m_nType  = nType;
        ad.DoModal();
    }

    void CMessageDialog::ShowMessageW( LPCWSTR msg, UINT nType, CWnd * pWnd )
    {
        CMessageDialog ad( pWnd );
    #if ( defined( UNICODE ) || defined( _UNICODE ) )
        ad.m_ptcMsg = msg;
    #else
        USES_CONVERSION;
        ad.m_ptcMsg = W2A( msg );
    #endif
        ad.m_nType  = nType;
        ad.DoModal();
    }
    
    Answer CMessageDialog::ShowQuestion( LPCTSTR msg, CWnd * pWnd )
    {
        CMessageDialog ad( pWnd );
        ad.m_ptcMsg = msg;
        ad.m_nType  = MB_YESNO;

        Answer a = ANSWER_NO;
        if ( ad.DoModal() == IDOK ) {
            a = ANSWER_YES;
        }
        return a;
    }
}

void CCryptoApp::ShowMessageA( LPCSTR msg, UINT nType, CWnd * pWnd )
{
    CMessageDialog::ShowMessageA( msg, nType, pWnd );
}
void CCryptoApp::ShowMessageW( LPCWSTR msg, UINT nType, CWnd * pWnd )
{
    CMessageDialog::ShowMessageW( msg, nType, pWnd );
}

Answer CCryptoApp::ShowQuestion( LPCTSTR msg, CWnd * pWnd )
{
    return CMessageDialog::ShowQuestion( msg, pWnd );
}

void CCryptoApp::InitializeCListCtrl(
    CListCtrl  * pCtrlList,
    int          nColumn,
    TCHAR      * astrColumnLabel[],
    int          anColumnFormat[],
    int          anColumnWidth[],
    CImageList * pImageList
) {
    int i;
    LV_COLUMN lvc;

    for ( i = 0; i < nColumn; i++ ) {
        pCtrlList->DeleteColumn( 0 );
    }

    // insert columns
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;

    for ( i = 0; i < nColumn; i++ ) {
        lvc.iSubItem = i;
        lvc.pszText = astrColumnLabel[i];
        lvc.cx = anColumnWidth[i];
        lvc.fmt = anColumnFormat[i];
        pCtrlList->InsertColumn( i, &lvc );
    }
    if ( pImageList != nullptr ) {
        pCtrlList->SetImageList( pImageList, LVSIL_SMALL );
    }
}
