#pragma once
#include <Windows.h>
#include <Windows.h>
#include <codecvt>
#include <locale>
#include <sstream>
#include <string>
#include <vector>
#include <cstdio>

class Settings
{
public:
    struct Profile
    {
        BOOLEAN HookNtQueryInformationProcess;
        BOOLEAN HookNtQuerySystemInformation;
        BOOLEAN HookNtQueryInformationThread;
        BOOLEAN HookNtQueryInformationJobObject;
        BOOLEAN HookNtQueryObject;
        BOOLEAN HookNtQuerySystemTime;
        BOOLEAN HookNtQueryPerformanceCounter;
        BOOLEAN HookNtCreateUserProcess;
        BOOLEAN HookNtCreateProcessEx;
        BOOLEAN HookNtCreateThreadEx;
        BOOLEAN HookNtSetContextThread;
        BOOLEAN HookNtGetContextThread;
        BOOLEAN HookNtOpenProcess;
        BOOLEAN HookNtOpenThread;
        BOOLEAN HookNtSetInformationThread;
        BOOLEAN HookNtSystemDebugControl;
        BOOLEAN HookNtGetNextProcess;
        BOOLEAN HookNtYieldExecution;
        BOOLEAN HookNtCreateFile;
        BOOLEAN HookNtContinue;
        BOOLEAN HookNtClose;
        BOOLEAN HookNtUserBuildHwndList;
        BOOLEAN HookNtUserFindWindowEx;
        BOOLEAN HookNtUserQueryWindow;
        BOOLEAN HookNtUserGetForegroundWindow;
        BOOLEAN HookKuserSharedData;
        BOOLEAN HookKiExceptionDispatch;
        BOOLEAN HookNtSetInformationProcess;
        BOOLEAN ClearPebBeingDebugged;
        BOOLEAN ClearPebNtGlobalFlag;
        BOOLEAN ClearHeapFlags;
        BOOLEAN ClearKuserSharedData;
        BOOLEAN ClearHideFromDebuggerFlag;
        BOOLEAN ClearBypassProcessFreeze;
        BOOLEAN ClearProcessBreakOnTerminationFlag;
        BOOLEAN ClearThreadBreakOnTerminationFlag;
        BOOLEAN SaveProcessDebugFlags;
        BOOLEAN SaveProcessHandleTracing;
    };

    VOID LoadProfile(std::string ProfileName);

    BOOL SaveProfile();

    BOOL AddProfile(std::string ProfileName);

    VOID SetProfile(std::string ProfileName);

    VOID Load(std::string IniPath);

    std::vector<std::string>& GetProfileNames();

    Profile& GetCurrentProfile();

    std::string GetCurrentProfileName();

private:
    std::string IniFile;
    CONST std::string IniFileName = "HyperHide.ini";
    CONST std::string SettingsSectionName = "SETTINGS";
    CONST std::string DefaultProfile = "Default";
    CONST std::string CurrentProfileKey = "CurrentProfile";
    std::vector<std::string> ProfileNames;
    std::string CurrentProfileName;
    Profile CurrentProfile;
};