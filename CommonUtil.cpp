#include "StdAfx.h"
#include "CommonUtil.h"
#include <io.h>

BOOL sjx::GenFileMD5(CString filepath, CString& md5)
{
	USES_CONVERSION;
	CFileFind finder;
	BOOL bRet = finder.FindFile(filepath);
	if (!bRet) return FALSE;
	finder.FindNextFile();

	BOOL bDir = finder.IsDirectory();
	BOOL bDots = finder.IsDots();
	if (bDir || bDots) return FALSE;

	crypto::md5_helper_t hhelper;
	std::string sHash = hhelper.hexdigestfile(T2A(filepath));
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
	USES_CONVERSION;
	CFileFind finder;
	BOOL bWorking = finder.FindFile(filepath);
	if (bWorking)
	{
		bWorking = finder.FindNextFile();
		CString FilePath = finder.GetFilePath();
		CString CmdLine;
		CmdLine.Format(_T("explorer.exe /select, %s"), FilePath);
		DWORD wReturn = WinExec(T2A(CmdLine), SW_SHOW);
	}
	else
	{
		TRACE(_T("error : 文件不存在!\r\n"));
	}
	return bWorking;
}


BOOL sjx::ExecBatFileInVSCmdPrompt(CString filepath)
{
	// 获取VS2010安装地址
	CString csVS2010CommonTool;
	BOOL bRet = csVS2010CommonTool.GetEnvironmentVariable(_T("VS100COMNTOOLS"));
	if (!bRet)
	{
		TRACE(_T("error : 找不到VS2010的安装路径，自动签出失败，请自行使用生成的签出批处理文件checkout.bat\r\n"));
		return false;
	}
	CString csVS2010Path = csVS2010CommonTool.Left(csVS2010CommonTool.ReverseFind('C'));  // 删除掉路径后面的Common7\Tools\ 字段
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

BOOL sjx::GetFileTimeStamp(CString filepath, CString& timeStamp)
{
	USES_CONVERSION;
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
	USES_CONVERSION;
	if (_access(T2A(csFolderPath), 0) == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

BOOL sjx::IsFileExist(CString csFilePath)
{
	USES_CONVERSION;
	if (_access(T2A(csFilePath), 0) == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

BOOL sjx::SelFile(BOOL bOpenFileDialog, // TRUE for FileOpen, FALSE for FileSaveAs
	CStringArray& csaFilePaths,
	LPCTSTR lpszDefExt/* = NULL*/,
	LPCTSTR lpszFileName/* = NULL*/,
	DWORD dwFlags/* = OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT*/,
	LPCTSTR lpszFilter/* = NULL*/)
{
	dwFlags |= OFN_ALLOWMULTISELECT;
	CFileDialog dlg(TRUE, lpszDefExt, lpszFileName, dwFlags, lpszFilter);
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
	return TRUE;
}


BOOL sjx::SelFolder(CString& csFolderPath, CString csTitle/* = _T("选择文件夹")*/, HWND hParent/* = NULL*/)
{
	if (IsOSVistaOrGreater())	//vista及以上版本	
	{
		CFolderPickerDialog PathDlg;
		PathDlg.m_ofn.lpstrTitle = csTitle;							//标题
		//PathDlg.m_ofn.lpstrInitialDir = DefaultPath;								//初始路径
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


void sjx::EnsurePathEndWithSlash(CString& path)
{
	if (path.Right(1) != _T("\\")) path += _T("\\");
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
