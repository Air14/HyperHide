#pragma once
#include <Windows.h>
#include <codecvt>
#include <locale>
#include <sstream>
#include <string>
#include <vector>
#include <cstdio>

std::vector<std::string> IniLoadSectionNames(const std::string File);

std::string IniLoadString(const std::string File, const std::string Section, const std::string Key, const std::string DefaultValue);

BOOL IniSaveString(const std::string File, const std::string Section, const std::string Key, const std::string Value);

template<typename ValueType>
ValueType IniLoadValue(const std::string File, const std::string Section, const std::string Key, ValueType DefaultValue)
{
	DWORD Ret = 0;
	ValueType Value;
	std::string DefaultValueStr = std::to_string(DefaultValue);
	std::string Buf;

	Buf = IniLoadString(File, Section, Key, DefaultValueStr);

	std::istringstream ss(Buf);

	ss >> Value;

	return Value;
}

template<typename ValueType>
BOOL IniSaveValue(const std::string File, const std::string Section, const std::string Key, ValueType Value)
{
	return IniSaveString(File, Section, Key, std::to_string(Value));
}