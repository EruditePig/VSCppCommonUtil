#include "StdAfx.h"
#include "CommonUtil.h"
#include <io.h>
#include <memory>
#include <functional>
#include <sys/stat.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// 统计字符串的字符个数，中文算1个，英文算1个，数字算1个
size_t sjx::CountCString(CString cs)
{
#ifdef _UNICODE
    return cs.GetLength();
#else
    USES_CONVERSION;
    CStringW csW;
    csW = A2T(cs.GetBuffer());
    cs.ReleaseBuffer();
    return csW.GetLength();
#endif
}

BOOL sjx::GenFileMD5(CString filepath, CString& md5)
{
    USES_CONVERSION;
    if (!sjx::IsFileExist(filepath)) return FALSE;

    crypto::md5_helper_t hhelper;
#ifdef _UNICODE
    std::string sHash = hhelper.hexdigestfile(T2A(filepath));
#else
    std::string sHash = hhelper.hexdigestfile(filepath.GetBuffer());
    filepath.ReleaseBuffer();
#endif
    md5 = sHash.c_str();
    return TRUE;
}


// 比较两个文件的MD5值是否相同。返回值 0-相同，-1-file1生成MD5失败 -2-file2生成MD5失败 -3-MD5不同
int sjx::CompareFileByMD5(CString file1, CString file2)
{
    CString csMD5_1, csMD5_2;
    BOOL bRet1 = sjx::GenFileMD5(file1, csMD5_1);
    if (!bRet1)
    {
        return -1;
    }
    BOOL bRet2 = sjx::GenFileMD5(file2, csMD5_2);
    if (!bRet2)
    {
        return -2;
    }
    if (csMD5_1 == csMD5_2)
    {
        return 0;
    }
    else
    {
        return -3;
    }
}

// 检测MD5值的正确性
BOOL sjx::IsValidMD5(CString csMD5)
{
    if (csMD5.GetLength() != 32) return FALSE;

    csMD5 = csMD5.MakeLower();
    CString csTemp = csMD5.SpanIncluding(_T("1234567890abcedf"));
    return csTemp == csMD5;
}

// 比较两个文件的时间。返回值 0-相同，-1-file1生成MD5失败 -2-file2生成MD5失败 -3 -file1比file2早 -4 file1比file2晚
int sjx::CompareFileByModTime(CString file1, CString file2)
{
    WIN32_FILE_ATTRIBUTE_DATA lpinf1;
    BOOL bRet1 = ::GetFileAttributesEx(file1, GetFileExInfoStandard, &lpinf1);
    if (!bRet1)
    {
        return -1;
    }
    WIN32_FILE_ATTRIBUTE_DATA lpinf2;
    BOOL bRet2 = ::GetFileAttributesEx(file2, GetFileExInfoStandard, &lpinf2);
    if (!bRet2)
    {
        return -2;
    }
    LONG lRet = ::CompareFileTime(&lpinf1.ftLastWriteTime, &lpinf2.ftLastWriteTime);
    if (lRet == 0)
    {
        return 0;
    }
    else if (lRet == -1)
    {
        return -3;
    }
    else if (lRet == 1)
    {
        return -4;
    }
    else
    {
        ASSERT(0);
        return -5;
    }
}

// 比较文件的修改时间和给定的时间。返回值 0-相同 -1-file生成时间失败 -2-file要早 -3-file要晚
int sjx::CompareFileModTimeWithGivenTime(CString file, SYSTEMTIME time)
{
    WIN32_FILE_ATTRIBUTE_DATA lpinf;
    BOOL bRet = ::GetFileAttributesEx(file, GetFileExInfoStandard, &lpinf);
    if (!bRet)
    {
        return -1;
    }
#ifdef _DEBUG
    SYSTEMTIME stFile1;
    ::FileTimeToSystemTime(&lpinf.ftLastWriteTime, &stFile1);
#endif
    FILETIME ft;
    ::SystemTimeToFileTime(&time, &ft);

    LONG lRet = ::CompareFileTime(&lpinf.ftLastWriteTime, &ft);
    if (lRet == 0)
    {
        return 0;
    }
    else if (lRet == -1)
    {
        return -2;
    }
    else if (lRet == 1)
    {
        return -3;
    }
    else
    {
        ASSERT(0);
        return -4;
    }

}

BOOL sjx::ExplorerFile(CString filepath)
{
    if (!sjx::IsFileExist(filepath))
    {
        TRACE(_T("error : 文件不存在!\r\n"));
        return FALSE;
    }
    else
    {
        CString CmdLine;
        CmdLine.Format(_T("explorer.exe /select, %s"), filepath);
#ifdef _UNICODE
        USES_CONVERSION;
        DWORD wReturn = WinExec(T2A(CmdLine), SW_SHOW);
#else
        DWORD wReturn = WinExec(CmdLine.GetBuffer(), SW_SHOW);
        CmdLine.ReleaseBuffer();
#endif
        return TRUE;
    }
}


BOOL sjx::ExecBatFileInVS2010CmdPrompt(CString filepath)
{
    // 获取VS2010安装地址
    CString csVS2010CommonTool;
    BOOL bRet = csVS2010CommonTool.GetEnvironmentVariable(_T("VS100COMNTOOLS"));
    if (!bRet)
    {
        TRACE(_T("error : 找不到VS2010的安装路径，自动签出失败，请自行使用生成的签出批处理文件checkout.bat\r\n"));
        return false;
    }
    CString csVS2010Path = csVS2010CommonTool.Left(csVS2010CommonTool.ReverseFind(_T('C')));  // 删除掉路径后面的Common7\Tools\ 字段
    csVS2010Path += _T("\\VC\\");

    // 自动执行签出
    CString csPara = _T("/k \"\"") + csVS2010Path + _T("vcvarsall.bat\"\" x86 & ") + filepath;
    SHELLEXECUTEINFO ShExecInfo = { 0 };
    ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
    ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_DOENVSUBST;
    ShExecInfo.hwnd = NULL;
    ShExecInfo.lpVerb = NULL;
    ShExecInfo.lpFile = _T("%ComSpec%");
    ShExecInfo.lpParameters = csPara;
    ShExecInfo.lpDirectory = csVS2010Path;
    ShExecInfo.nShow = SW_SHOW;
    ShExecInfo.hInstApp = NULL;
    ShellExecuteEx(&ShExecInfo);
    return true;
}

BOOL sjx::GetFileLastWriteTimeStamp(CString filepath, CString& timeStamp)
{
    CFileFind finder;
    BOOL bRet = finder.FindFile(filepath);
    if (!bRet) return FALSE;
    finder.FindNextFile();

    CTime time;
    finder.GetLastWriteTime(time);
    timeStamp.Format(_T("%d-%d-%d %d:%d"),
        time.GetYear(),
        time.GetMonth(),
        time.GetDay(),
        time.GetHour(),
        time.GetMinute());
    return TRUE;
}

BOOL sjx::CopyFileWithCreateFolder(CString csSrcFilePath, CString csDestFilePath, BOOL flag)
{
    int index = csDestFilePath.ReverseFind(_T('\\'));
    if (index == -1) return FALSE;		// 路径中总得有\\存在
    CString csDestFolder = csDestFilePath.Left(index + 1);
    CString csDestFileName = csDestFilePath.Right(csDestFilePath.GetLength() - index - 1);
    return CopyFileWithCreateFolder(csSrcFilePath, csDestFolder, csDestFileName, flag);
}

// 拷贝文件，并且如果目录不存在则创建目录再拷贝
BOOL sjx::CopyFileWithCreateFolder(CString csSrcFilePath, CString csDestFolder, CString csDestRelativeFilePath, BOOL flag)
{
    // csDestRelativeFilePath分解为多个文件夹名和一个文件名
    CStringArray csFolders;
    CString csTmpFilePath = csDestRelativeFilePath;
    CString csTmpFolderPath = csDestFolder;
    do
    {
        int index = csTmpFilePath.Find(_T("\\"));
        if (index == -1 || index == 0) break;
        CString folder = csTmpFilePath.Left(index);
        csTmpFilePath = csTmpFilePath.Right(csTmpFilePath.GetLength() - index - 1);
        csTmpFolderPath = csTmpFolderPath + _T("\\") + folder;
        if (!IsFolderExist(csTmpFolderPath))
        {
            BOOL bRet = ::CreateDirectory(csTmpFolderPath, NULL);
            if (!bRet) return false;
        }
    } while (1);
    return ::CopyFile(csSrcFilePath, csDestFolder + csDestRelativeFilePath, flag);
}

BOOL sjx::IsFolderExist(CString csFolderPath)
{
    struct _stat64i32 s;
    if (_tstat(csFolderPath, &s) == 0)
    {
        if (s.st_mode & S_IFDIR)
        {
            return TRUE;
        }
        else
        {
            return false;
        }
    }
    else
    {
        return false;
    }
}

BOOL sjx::IsFileExist(CString csFilePath)
{
    struct _stat64i32 s;
    if (_tstat(csFilePath, &s) == 0)
    {
        if (s.st_mode & S_IFREG)
        {
            return TRUE;
        }
        else
        {
            return false;
        }
    }
    else
    {
        return false;
    }
}

CString sjx::GetFileExt(CString csFilePathOrName)
{
    return csFilePathOrName.Right(csFilePathOrName.GetLength() - csFilePathOrName.ReverseFind(_T('.')) - 1);
}

CString sjx::DelFileExt(CString csFilePathOrName)
{
    return csFilePathOrName.Left(csFilePathOrName.ReverseFind(_T('.')));
}

// 获取文件或文件夹的名字
CString sjx::GetFileOrFolderNameFromPath(CString csFilePath)
{
    sjx::EnsurePathEndWithoutSlash(csFilePath);
    return csFilePath.Right(csFilePath.GetLength() - csFilePath.ReverseFind(_T('\\')) - 1);
}

void sjx::GetFilesInFolder(CString csFolderPath, CStringArray& csaFiles, CString csPattern/* = _T("*.*")*/, BOOL bIncludeSubFolder/* = FALSE*/)
{
    csaFiles.RemoveAll();
    sjx::EnsurePathEndWithSlash(csFolderPath);

    std::function<void(CString, CStringArray&, CString, BOOL)> TransverseDir = [&TransverseDir](CString csFolderPath, CStringArray& csaFiles, CString csPattern, BOOL bIncludeSubFolder)
    {
        {   // 先搜索当前文件夹下
            CString searchPath = csFolderPath + csPattern;
            // 将当前目录文件枚举并树状显示
            CFileFind finder;
            BOOL bRet = finder.FindFile(searchPath);
            while (bRet)
            {
                bRet = finder.FindNextFile();
                if (finder.IsDots() || finder.IsDirectory())
                {
                    continue;
                }
                else        // 文件
                {
                    csaFiles.Add(finder.GetFilePath());
                }
            }
        }
        if (bIncludeSubFolder)  // 再搜索子文件夹下
        {
            CString searchPath = csFolderPath + _T("*.*");
            // 将当前目录文件枚举并树状显示
            CFileFind finder;
            BOOL bRet = finder.FindFile(searchPath);
            while (bRet)
            {
                bRet = finder.FindNextFile();
                if (finder.IsDots())
                {
                    continue;
                }
                else if (finder.IsDirectory())
                {
                    TransverseDir(csFolderPath + finder.GetFileName() + _T("\\"), csaFiles, csPattern, bIncludeSubFolder);
                }
            }

        }
    };
    TransverseDir(csFolderPath, csaFiles, csPattern, bIncludeSubFolder);
}

BOOL sjx::SelFile(CStringArray& csaFilePaths,
    SEL_FILE_MODE mode/* = FILE_OPEN*/,
    LPCTSTR lpszDefExt/* = NULL*/,
    LPCTSTR lpszFileName/* = NULL*/,
    DWORD dwFlags/* = OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT*/,
    LPCTSTR lpszFilter/* = NULL*/)
{
    dwFlags |= OFN_ALLOWMULTISELECT;
    CFileDialog dlg(mode == FILE_OPEN ? TRUE : FALSE, lpszDefExt, lpszFileName, dwFlags, lpszFilter);
    const int SEL_FILE_NUM = 100;   // 允许选择的文件数目
    dlg.m_ofn.lpstrFile = new TCHAR[_MAX_PATH*SEL_FILE_NUM];    // 重新定义缓冲区大小
    memset(dlg.m_ofn.lpstrFile, 0, _MAX_PATH*SEL_FILE_NUM);     // 初始化缓冲区
    dlg.m_ofn.nMaxFile = _MAX_PATH*SEL_FILE_NUM;

    if (dlg.DoModal() != IDOK) return FALSE;

    csaFilePaths.RemoveAll();
    POSITION pos = dlg.GetStartPosition();
    while (NULL != pos)
    {
        csaFilePaths.Add(dlg.GetNextPathName(pos));
    }
    delete[] dlg.m_ofn.lpstrFile;
    return TRUE;
}


BOOL sjx::SelFolder(CString& csFolderPath, CString InitialDir /*= _T("")*/, CString csTitle/* = _T("选择文件夹")*/, HWND hParent/* = NULL*/)
{
    if (IsOSVistaOrGreater())	//vista及以上版本	
    {
        CFolderPickerDialog PathDlg;
        PathDlg.m_ofn.lpstrTitle = csTitle;							//标题
        PathDlg.m_ofn.lpstrInitialDir = InitialDir;								//初始路径
        if (PathDlg.DoModal() == IDOK)
        {
            csFolderPath = PathDlg.GetPathName();
            return TRUE;
        }
        else
        {
            return FALSE;
        }
    }
    else
    {
        BROWSEINFO bi;
        TCHAR path[MAX_PATH] = { 0 };
        ZeroMemory(&bi, sizeof(bi));
        bi.hwndOwner = hParent;
        bi.pszDisplayName = path;
        bi.lpszTitle = csTitle;
        bi.ulFlags = BIF_USENEWUI | BIF_NONEWFOLDERBUTTON;
        LPITEMIDLIST list = SHBrowseForFolder(&bi);
        if (list != NULL)
        {
            SHGetPathFromIDList(list, path);
            csFolderPath = path;
            return TRUE;
        }
        else
        {
            return FALSE;
        }
    }
}


int sjx::IsInCStringArray(CString cs, const CStringArray& csa)
{
    for (int i = 0; i < csa.GetCount(); ++i)
    {
        if (csa[i] == cs) return i;
    }
    return -1;
}

void sjx::AddToCStringArray(BOOL bCheckDuplicate, const CStringArray& csaFrom, CStringArray& csaTo)
{
    for (int i = 0; i < csaFrom.GetCount(); ++i)
    {
        bool bAdd = true;
        if (bCheckDuplicate)
        {
            int index = IsInCStringArray(csaFrom[i], csaTo);
            if (index >= 0) bAdd = false;
        }
        if (bAdd)
        {
            csaTo.Add(csaFrom[i]);
        }
    }
}

// 确保路径字符串以\\结尾
void sjx::EnsurePathEndWithSlash(CString& path)
{
    int iPos = path.ReverseFind(_T('\\'));
    int len = path.GetLength();

    if (iPos != len - 1)
    {
        path.AppendChar(_T('\\'));
    }

}

// 确保路径字符串不以\\结尾
void sjx::EnsurePathEndWithoutSlash(CString& path)
{
    int iPos = path.ReverseFind(_T('\\'));
    int len = path.GetLength();

    if (iPos == len - 1)
    {
        path.Truncate(len - 1);
    }
}

BOOL sjx::CopyCStringToClipboard(CString data)
{
    if (::OpenClipboard(NULL) && ::EmptyClipboard())
    {
        HGLOBAL hResult = GlobalAlloc(GMEM_MOVEABLE, (data.GetLength() + 1) * sizeof(TCHAR));
        if (hResult == NULL)
        {
            ::CloseClipboard();
            return FALSE;
        }

        LPTSTR lptstrCopy = (LPTSTR)GlobalLock(hResult);
        memcpy(lptstrCopy, data.GetBuffer(), data.GetLength() * sizeof(TCHAR));
        lptstrCopy[data.GetLength()] = (TCHAR)0;
        GlobalUnlock(hResult);
        data.ReleaseBuffer();

        if (::SetClipboardData(CF_UNICODETEXT, hResult) == NULL)
        {
            TRACE("Unable to set Clipboard data");
            ::CloseClipboard();
            return FALSE;
        }

        ::CloseClipboard();
        return TRUE;
    }

    return FALSE;
}

// 展开树上一个节点的所有子节点，指定TVI_ROOT的话，那就是展开整个树
void sjx::ExpandTree(CTreeCtrl& tree, HTREEITEM hItem)
{
    if (!tree.ItemHasChildren(hItem))
    {
        return;
    }
    HTREEITEM hChildItem = tree.GetChildItem(hItem);
    while (hChildItem != NULL)
    {
        ExpandTree(tree, hChildItem);
        hChildItem = tree.GetNextItem(hChildItem, TVGN_NEXT);
    }
    tree.Expand(hItem, TVE_EXPAND);
};

BOOL sjx::IsOSVistaOrGreater()
{
    OSVERSIONINFO   osver;
    osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    ::GetVersionEx(&osver);

    if (osver.dwPlatformId == VER_PLATFORM_WIN32s)						//旧平台
    {
        //AfxMessageBox("dwPlatformId == 0");
        return FALSE;
    }
    else if (osver.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)			//旧平台
    {
        //AfxMessageBox("dwPlatformId == 1");
        return FALSE;
    }
    else if (osver.dwPlatformId >= VER_PLATFORM_WIN32_NT)				//最新平台
    {
        if (osver.dwMajorVersion <= 5 && osver.dwMinorVersion <= 2)		//Windows Vista以前版本 
        {
            //AfxMessageBox("xp及以前版本");
            return FALSE;
        }
        else															//Windows Vista及以后的版本（包括win7 win 8 win10）
        {
            //AfxMessageBox("Vista以后版本");
            return TRUE;
        }
    }
    //AfxMessageBox("失败");
    return FALSE;
}

// 获得exe所在的文件夹，以\结尾
CString sjx::GetModuleFolder()
{
    TCHAR FilePath[MAX_PATH + 1] = { 0 };
    GetModuleFileName(NULL, FilePath, sizeof(FilePath)); //获取程序当前执行文件名
    CString csFilePath(FilePath);

    int index = csFilePath.ReverseFind(_T('\\'));
    return csFilePath.Left(index + 1);
}

void sjx::RemoveFileReadOnlyAttr(CString filepath)
{
    DWORD dwAttr = ::GetFileAttributes(filepath);
    if (dwAttr & FILE_ATTRIBUTE_READONLY)
    {
        dwAttr &= ~FILE_ATTRIBUTE_READONLY;
        SetFileAttributes(filepath, dwAttr);
    }
}


BOOL sjx::DelFile(CString filepath)
{
    sjx::RemoveFileReadOnlyAttr(filepath);
    return ::DeleteFile(filepath);
}


BOOL sjx::DelFolder(CString folderPath)
{
    sjx::EnsurePathEndWithSlash(folderPath);
    CString searchPath = folderPath + _T("*.*");
    // 将当前目录文件枚举并树状显示
    CFileFind finder;
    BOOL bRet = finder.FindFile(searchPath);
    while (bRet)
    {
        bRet = finder.FindNextFile();
        if (finder.IsDots())
        {
            continue;
        }
        else if (finder.IsDirectory())  // 文件夹
        {
            sjx::DelFolder(folderPath + finder.GetFileName() + _T("\\"));
        }
        else        // 文件
        {
            sjx::DelFile(folderPath + finder.GetFileName());
        }
    }

    return ::RemoveDirectory(folderPath);
}


bool sjx::IsUTF8(const void* pBuffer, long size)
{
    bool IsUTF8 = true;
    unsigned char* start = (unsigned char*)pBuffer;
    unsigned char* end = (unsigned char*)pBuffer + size;
    while (start < end)
    {
        if (*start < 0x80) // (10000000): 值小于0x80的为ASCII字符  
        {
            start++;
        }
        else if (*start < (0xC0)) // (11000000): 值介于0x80与0xC0之间的为无效UTF-8字符  
        {
            IsUTF8 = false;
            break;
        }
        else if (*start < (0xE0)) // (11100000): 此范围内为2字节UTF-8字符  
        {
            if (start >= end - 1)
            {
                break;
            }

            if ((start[1] & (0xC0)) != 0x80)
            {
                IsUTF8 = false;
                break;
            }

            start += 2;
        }
        else if (*start < (0xF0)) // (11110000): 此范围内为3字节UTF-8字符  
        {
            if (start >= end - 2)
            {
                break;
            }

            if ((start[1] & (0xC0)) != 0x80 || (start[2] & (0xC0)) != 0x80)
            {
                IsUTF8 = false;
                break;
            }

            start += 3;
        }
        else
        {
            IsUTF8 = false;
            break;
        }
    }

    return IsUTF8;
}

void sjx::UnicodeToUTF8(CStringW uni, std::vector<char>& utf8)
{
    if (uni.IsEmpty())
    {
        utf8.clear();
        return;
    }

    int len;
    len = ::WideCharToMultiByte(CP_UTF8, 0, uni, -1, NULL, 0, NULL, NULL);
    utf8.resize(len);

    ::WideCharToMultiByte(CP_UTF8, 0, uni, -1, utf8.data(), len, NULL, NULL);
}

// 运行exe
void sjx::RunExeAndWait(CString csExePath)
{
    SHELLEXECUTEINFO  ShExecInfo = { 0 };
    ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
    ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    ShExecInfo.hwnd = NULL;
    ShExecInfo.lpVerb = NULL;
    ShExecInfo.lpFile = csExePath;
    ShExecInfo.lpParameters = NULL;
    ShExecInfo.lpDirectory = NULL;
    ShExecInfo.nShow = SW_SHOW;
    ShExecInfo.hInstApp = NULL;
    ShellExecuteEx(&ShExecInfo);
    WaitForSingleObject(ShExecInfo.hProcess, INFINITE);
}


// 调用命令提示符执行命令，并获得输出
BOOL sjx::ExecCmd(CString cmd, CString& csRet)
{
    USES_CONVERSION;
#ifdef _UNICODE
    char* pCmd = T2A(cmd);
#else
    char* pCmd = cmd.GetBuffer();
    cmd.ReleaseBuffer();
#endif
    std::shared_ptr<FILE> pipe(_popen(pCmd, "r"), _pclose);
    if (!pipe)
    {
        csRet = _T("创建管道失败，无法执行命令");
        return FALSE;
    }
    char buffer[128];
    while (!feof(pipe.get()))
    {
        if (fgets(buffer, 128, pipe.get()) != NULL)
            csRet += buffer;
    }
    return TRUE;
}


// Execute a command and get the results in a CString.
// Synchronously launches a child process and waits up to 2 seconds for completion.
// Uses a pipe to get the output of the child process.
// Does not pipe to stdin of child process.
// Example usage:
//   CString str;
//   str = ExecCmd( "ping 127.0.0.1 -n 99 " );  // This ping command will be terminated early before the -n 99 completes.
//   str.Replace( "\x0d\x0d\x0a", "\x0d\x0a" ); // fixes some ugly non-standard line terminators created by ping.
//
//   str = ExecCmd( "java -version" ); // A more practical usage.
//
CString sjx::ExecCmd2(CString cmd)
{
    // Handle Inheritance - to pipe child's stdout via pipes to parent, handles must be inherited.
    //   SECURITY_ATTRIBUTES.bInheritHandle must be TRUE
    //   CreateProcess parameter bInheritHandles must be TRUE;
    //   STARTUPINFO.dwFlags must have STARTF_USESTDHANDLES set.

    CString strResult; // Contains result of cmdArg.

    HANDLE hChildStdoutRd; // Read-side, used in calls to ReadFile() to get child's stdout output.
    HANDLE hChildStdoutWr; // Write-side, given to child process using si struct.

    BOOL fSuccess;

    // Create security attributes to create pipe.
    SECURITY_ATTRIBUTES saAttr = { sizeof(SECURITY_ATTRIBUTES) };
    saAttr.bInheritHandle = TRUE; // Set the bInheritHandle flag so pipe handles are inherited by child process. Required.
    saAttr.lpSecurityDescriptor = NULL;

    // Create a pipe to get results from child's stdout.
    // I'll create only 1 because I don't need to pipe to the child's stdin.
    if (!CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0))
    {
        return strResult;
    }

    STARTUPINFO si = { sizeof(STARTUPINFO) }; // specifies startup parameters for child process.

    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES; // STARTF_USESTDHANDLES is Required.
    si.hStdOutput = hChildStdoutWr; // Requires STARTF_USESTDHANDLES in dwFlags.
    si.hStdError = hChildStdoutWr; // Requires STARTF_USESTDHANDLES in dwFlags.
                                   // si.hStdInput remains null.
    si.wShowWindow = SW_HIDE; // Prevents cmd window from flashing. Requires STARTF_USESHOWWINDOW in dwFlags.

    PROCESS_INFORMATION pi = { 0 };

    // Create the child process.
    fSuccess = CreateProcess(
        NULL,
        cmd.GetBuffer(),            // command line
        NULL,               // process security attributes
        NULL,               // primary thread security attributes
        TRUE,               // TRUE=handles are inherited. Required.
        CREATE_NEW_CONSOLE, // creation flags
        NULL,               // use parent's environment
        NULL,               // use parent's current directory
        &si,                // __in, STARTUPINFO pointer
        &pi);               // __out, receives PROCESS_INFORMATION
    cmd.ReleaseBuffer();

    if (!fSuccess)
    {
        return strResult;
    }

    // Wait until child processes exit. Don't wait forever.
    WaitForSingleObject(pi.hProcess, INFINITE);
    TerminateProcess(pi.hProcess, 0); // Kill process if it is still running. Tested using cmd "ping blah -n 99"

                                      // Close the write end of the pipe before reading from the read end of the pipe.
    if (!CloseHandle(hChildStdoutWr))
    {
        return strResult;
    }

    // Read output from the child process.
    for (;;)
    {
        DWORD dwRead;
        CHAR chBuf[4096];

        // Read from pipe that is the standard output for child process.
        bool done = !ReadFile(hChildStdoutRd, chBuf, 4096, &dwRead, NULL) || dwRead == 0;
        if (done)
        {
            break;
        }

        // Append result to string.
        strResult += CString(chBuf, dwRead);
    }

    // Close process and thread handles.
    CloseHandle(hChildStdoutRd);

    // CreateProcess docs specify that these must be closed. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return strResult;
}


// 分割CString
void sjx::SplitCString(CString str, CString split, CStringArray& strGet)
{
    //str为待分割的CString，split为分割符如：， |或空格 strGet为输出参数，你得到的字符串存放在strGet中
    int pos = -1;
    pos = str.Find(split);
    while (pos != -1)
    {
        strGet.Add(str.Left(pos));
        str.Delete(0, pos + split.GetLength());
        pos = str.Find(split);
    }
    if (str != "")
    {//最后剩下的字符串可能没有split这个标示，看你需要怎么处理了
     //这里也把他加入到strGet中
        strGet.Add(str);
    }
}

// 打开文件，为读写扩展ini 0读1写
CStdioFile* sjx::OpenExIniFile(CString csPath, int readOrWrite)
{
    if (readOrWrite == 0)
    {
        CStdioFile* pFile = new CStdioFile();
        if (pFile)
        {
            BOOL bRet = pFile->Open(csPath, CFile::modeRead);
            if (!bRet)
            {
                delete pFile;
                return nullptr;
            }
            else
            {
                return pFile;
            }
        }
        else
        {
            return nullptr;
        }
    }
    else if (readOrWrite == 1)
    {
        CStdioFile* pFile = new CStdioFile();
        if (pFile)
        {
            CFileException error;
            BOOL bRet = pFile->Open(csPath, CFile::modeWrite | CFile::modeCreate, &error);
            if (!bRet)
            {
                delete pFile;
                return nullptr;
            }
            else
            {
                return pFile;
            }
        }
        else
        {
            return nullptr;
        }
    }
    else
    {
        return nullptr;
    }
}

// 读某个字段的结果
void sjx::ReadExIniSection(CStdioFile* pFile, CString csSecName, CString& csSecValue)
{
    auto IsAttrLine = [](CString csLine) -> BOOL
    {
        csLine = csLine.TrimLeft();
        csLine = csLine.TrimRight();
        return csLine.Left(1) == _T("[") && csLine.Right(1) == _T("]");
    };
    auto IsCommentLine = [](CString csLine)	-> BOOL
    {
        return csLine.Find(_T("//")) == 0;
    };
    auto IsBlankLine = [](CString csLine) -> BOOL
    {
        for (int i = 0; i < csLine.GetLength(); ++i)
        {
            if (csLine[i] != _T(' ') && csLine[i] != _T('\t'))
            {
                return FALSE;
            }
        }
        return TRUE;
    };

    auto SeekAttr = [](CStdioFile& file, CString csAttrName) -> BOOL
    {
        file.Seek(0, CFile::begin);
        CString csLine;
        while (file.ReadString(csLine))
        {
            csLine = csLine.TrimLeft();
            csLine = csLine.TrimRight();
            if (csLine == _T("[") + csAttrName + _T("]"))
            {
                return TRUE;
            }
        }
        return FALSE;
    };

    csSecValue.Empty();
    if (!pFile) return;

    if (SeekAttr(*pFile, csSecName))
    {
        CString csLine;
        while (pFile->ReadString(csLine))
        {
            if (IsCommentLine(csLine) || IsBlankLine(csLine))
            {
                continue;
            }
            if (IsAttrLine(csLine))		// 直到读到下一个属性为止
            {
                break;
            }
            csSecValue += csLine;
            csSecValue += _T("\r\n");
        }
    }
}

// 写某个字段的结果
void sjx::WriteExIniSection(CStdioFile* pFile, CString csSecName, CString csSecValue)
{
    if (!pFile) return;

    pFile->Seek(0, CFile::end);		// 到文件结尾
    pFile->WriteString(_T("\n"));
    CString csLine;
    csLine = _T("[") + csSecName + _T("]\n");
    pFile->WriteString(csLine);
    pFile->WriteString(_T("\n"));
    pFile->WriteString(csSecValue);
}

// 在记事本中显示字符串
void sjx::ShowTextInNotepad(CString csText)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    CString csPath("Notepad.exe");

    if (!CreateProcess(NULL, //for NT/2000/xp
        (LPTSTR)(LPCTSTR)csPath,   // command line string
        NULL,	// Process handle not inheritable
        NULL,	// Thread handle not inheritable.
        FALSE,  // Set handle inheritance to FALSE.
        0,		// No creation flags.
        NULL,	// Use parent's environment block.
        NULL,	// Use parent's starting directory.
        &si,	// startup information
        &pi		// Pointer to PROCESS_INFORMATION structure.
    ))
    {
        DWORD dwERror = GetLastError();
        TRACE(_T("ERROR launching Notepad\r\n"));
    }

    WaitForSingleObject(pi.hThread, WAIT_TIMEOUT);
    HWND hwnd = ::FindWindowEx(NULL, NULL, NULL, _T("无标题 - 记事本"));
    if (hwnd)
    {
        HWND hwndEdit = ::FindWindowEx(hwnd, NULL, _T("edit"), NULL);
        ::SendMessage(hwndEdit, WM_SETTEXT, 0, (LPARAM)(LPTSTR)(LPCTSTR)csText);
        ::SendMessage(hwndEdit, EM_SETMODIFY, (WPARAM)TRUE, 0);
    }

}

// 读取注册表某个字符串键值
BOOL sjx::GetRegString(HKEY hKeyArg, CString keyNameArg, CString valNameArg, ULONG len, CString& csRegValue)
{
    CRegKey k;
    k.Open(hKeyArg, keyNameArg);
    BOOL bRet = (k.QueryStringValue(valNameArg, csRegValue.GetBufferSetLength(len), &len) == ERROR_SUCCESS);
    csRegValue.ReleaseBuffer();
    return bRet;
}

// 写注册表某个字符串
BOOL sjx::SetRegString(HKEY hKeyArg, CString keyNameArg, CString csKey, CString csKeyVal)
{
    CRegKey key;
    BOOL bRet = TRUE;
    bRet = key.Open(hKeyArg, keyNameArg) == ERROR_SUCCESS;
    bRet = bRet ? TRUE : key.Create(hKeyArg, keyNameArg) == ERROR_SUCCESS;
    bRet = bRet ? key.SetStringValue(csKey, csKeyVal) == ERROR_SUCCESS : FALSE;
    return bRet;
}

// 获得某个目录下所有某个后缀的文件名
void sjx::GetAllExtFiles(CString csPath, CString csExt, FILE_VALUE value, CStringArray& csaFiles)
{
    csaFiles.RemoveAll();
    sjx::EnsurePathEndWithSlash(csPath);
    CString searchPath;
    searchPath.Format(_T("%s*."), csPath);
    searchPath += csExt;
    CFileFind finder;
    BOOL bRet = finder.FindFile(searchPath);
    while (bRet)
    {
        bRet = finder.FindNextFile();
        if (finder.IsDots() || finder.IsDirectory())
        {
            continue;
        }
        else
        {
            if (value == FILEPATH)
            {
                csaFiles.Add(finder.GetFilePath());
            }
            else
            {
                csaFiles.Add(finder.GetFileName());
            }
        }
    }
}

// 设置某个CComboBox的下拉框宽度匹配下拉选项中最长的那个，拷贝自MSDN CComboBox::SetDroppedWidth
void sjx::AutoSetComboBoxDropDownWidth(CComboBox* m_pComboBox)
{
    if (!m_pComboBox) return;
    if (m_pComboBox->GetCount() == 0) return;

    // Find the longest string in the combo box.
    CString    str;
    CSize      sz;
    int        dx = 0;
    TEXTMETRIC tm;
    CDC*       pDC = m_pComboBox->GetDC();
    CFont*     pFont = m_pComboBox->GetFont();

    // Select the listbox font, save the old font
    CFont* pOldFont = pDC->SelectObject(pFont);
    // Get the text metrics for avg char width
    pDC->GetTextMetrics(&tm);

    for (int i = 0; i < m_pComboBox->GetCount(); i++)
    {
        m_pComboBox->GetLBText(i, str);
        sz = pDC->GetTextExtent(str);

        // Add the avg width to prevent clipping
        sz.cx += tm.tmAveCharWidth;

        if (sz.cx > dx)
            dx = sz.cx;
    }
    // Select the old font back into the DC
    pDC->SelectObject(pOldFont);
    m_pComboBox->ReleaseDC(pDC);

    // Adjust the width for the vertical scroll bar and the left and right border.
    dx += ::GetSystemMetrics(SM_CXVSCROLL) + 2 * ::GetSystemMetrics(SM_CXEDGE);

    // Set the width of the list box so that every item is completely visible.
    m_pComboBox->SetDroppedWidth(dx);
}

// 获得当前Error的字符串
CString sjx::GetErrorString()
{
    CString Error;
    LPTSTR s;
    if (::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        ::GetLastError(),
        0,
        (LPTSTR)&s,
        0,
        NULL) == 0)
    { /* failed */
      // Unknown error code %08x (%d)
        Error = _T("Unknown error");
    } /* failed */
    else
    { /* success */
        LPTSTR p = _tcsrchr(s, _T('\r'));
        if (p != NULL)
        { /* lose CRLF */
            *p = _T('\0');
        } /* lose CRLF */
        Error = s;
        ::LocalFree(s);
    } /* success */
    return Error;
}
