#include "IniApi.h"

std::vector<std::string> IniLoadSectionNames(const std::string File) 
{
	std::string Buf;
	std::vector<std::string> Sections;
	DWORD Ret = 0;

	while (((DWORD)Buf.size() - Ret) < 3) 
	{
		Buf.resize(Buf.size() + MAX_PATH);
		Ret = GetPrivateProfileSectionNamesA(&Buf[0], (DWORD)Buf.size(), File.c_str());
	}

	const char* Data = Buf.c_str();
	for (; Data[0]; Data += lstrlenA(Data) + 1) 
		Sections.push_back(Data);

	return Sections;
}

std::string IniLoadString(const std::string File, const std::string Section, const std::string Key, const std::string DefaultValue) 
{
	std::string Buf;
	DWORD Ret = 0;

	while (((DWORD)Buf.size() - Ret) < 3) {
		Buf.resize(Buf.size() + MAX_PATH);
		Ret = GetPrivateProfileStringA(Section.c_str(), Key.c_str(), DefaultValue.c_str(), &Buf[0], (DWORD)Buf.size(), File.c_str());
	}
	Buf.resize(Ret);

	return Buf;
}

BOOL IniSaveString(const std::string File, const std::string Section, const std::string Key, const std::string Value)
{
	return WritePrivateProfileStringA(Section.c_str(), Key.c_str(), Value.c_str(), File.c_str()) == TRUE;
}