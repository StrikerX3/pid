// pid.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "process.h"

// case insensitive search functions courtesy of http://stackoverflow.com/questions/3152241/case-insensitive-stdstring-find

// templated version of my_equal so it could work with both char and wchar_t
template<typename charT>
struct my_equal {
	my_equal(const std::locale& loc) : loc_(loc) {}
	bool operator()(charT ch1, charT ch2) {
		return std::tolower(ch1, loc_) == std::tolower(ch2, loc_);
	}
private:
	const std::locale& loc_;
};

// find substring (case insensitive)
template<typename T>
int ci_find_substr(const T& str1, const T& str2, const std::locale& loc = std::locale())
{
	typename T::const_iterator it = std::search(str1.begin(), str1.end(),
		str2.begin(), str2.end(), my_equal<typename T::value_type>(loc));
	if (it != str1.end()) return it - str1.begin();
	else return -1; // not found
}

std::string ws2s(const std::wstring& wstr)
{
	typedef std::codecvt_utf8<wchar_t> convert_type;
	std::wstring_convert<convert_type, wchar_t> converter;

	return converter.to_bytes(wstr);
}

int _tmain(int argc, _TCHAR* argv[])
{
	cProcInfo i_Proc;
	DWORD u32_Error = i_Proc.Capture();
	if (u32_Error)
	{
		printf("Error 0x%X capturing processes.\n", u32_Error);
		return -1;
	}

	SYSTEM_PROCESS* pk_Proc = i_Proc.GetProcessList();
	while (pk_Proc->NextEntryOffset)
	{
		std::wstring procNameU(pk_Proc->ImageName.Buffer, pk_Proc->ImageName.Length / 2);
		std::string procName = ws2s(procNameU);
		if (argc == 1)
		{
			std::cout << pk_Proc->UniqueProcessId << ": " << procName << std::endl;
		}
		else
		{
			for (int i = 1; i < argc; i++)
			{
				// probably horribly inefficient, but I doubt anyone would run over 1000 processes...
				std::wstring nameToFindU(argv[i]);
				std::string nameToFind = ws2s(nameToFindU);
				std::string procPid = std::to_string((ULONG) pk_Proc->UniqueProcessId);
				int fName = ci_find_substr(procName, nameToFind);
				int fPid = ci_find_substr(procPid, nameToFind);
				//std::cout << nameToFind << " -- " << procName << " = " << f << std::endl;
				if (fName >= 0 || fPid >= 0)
				{
					std::cout << (LONG)pk_Proc->UniqueProcessId << ": " << procName << std::endl;
				}
			}
		}
		pk_Proc = (SYSTEM_PROCESS*)((BYTE*)pk_Proc + pk_Proc->NextEntryOffset);
	}
	return 0;
}
