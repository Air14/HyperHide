#include "Settings.h"
#include "IniApi.h"

VOID Settings::LoadProfile(std::string ProfileName)
{
    // Nt hooks
    CurrentProfile.HookNtQueryInformationProcess = IniLoadValue(IniFile, ProfileName, "NtQueryInformationProcess", 1);
    CurrentProfile.HookNtQueryInformationJobObject = IniLoadValue(IniFile, ProfileName, "NtQueryInformationJobObject", 1);
    CurrentProfile.HookNtQueryInformationThread = IniLoadValue(IniFile, ProfileName, "NtQueryInformationThread", 1);
    CurrentProfile.HookNtQueryObject = IniLoadValue(IniFile, ProfileName, "NtQueryObject", 1);
    CurrentProfile.HookNtQueryPerformanceCounter = IniLoadValue(IniFile, ProfileName, "NtQueryPerformanceCounter", 1);
    CurrentProfile.HookNtQuerySystemInformation = IniLoadValue(IniFile, ProfileName, "NtQuerySystemInformation", 1);
    CurrentProfile.HookNtQuerySystemTime = IniLoadValue(IniFile, ProfileName, "NtQuerySystemTime", 1);
    CurrentProfile.HookNtClose = IniLoadValue(IniFile, ProfileName, "NtClose", 1);
    CurrentProfile.HookNtGetContextThread = IniLoadValue(IniFile, ProfileName, "NtGetContextThread", 1);
    CurrentProfile.HookNtSetContextThread = IniLoadValue(IniFile, ProfileName, "NtSetContextThread", 1);
    CurrentProfile.HookNtContinue = IniLoadValue(IniFile, ProfileName, "NtContinue", 1);
    CurrentProfile.HookNtCreateUserProcess = IniLoadValue(IniFile, ProfileName, "NtCreateUserProcess", 1);
    CurrentProfile.HookNtCreateProcessEx = IniLoadValue(IniFile, ProfileName, "NtCreateProcessEx", 1);
    CurrentProfile.HookNtCreateThreadEx = IniLoadValue(IniFile, ProfileName, "NtCreateThreadEx", 1);
    CurrentProfile.HookNtGetNextProcess = IniLoadValue(IniFile, ProfileName, "NtGetNextProcess", 1);
    CurrentProfile.HookNtOpenThread = IniLoadValue(IniFile, ProfileName, "NtOpenThread", 1);
    CurrentProfile.HookNtOpenProcess = IniLoadValue(IniFile, ProfileName, "NtOpenProcess", 1);
    CurrentProfile.HookNtCreateFile = IniLoadValue(IniFile, ProfileName, "NtCreateFile", 1);
    CurrentProfile.HookNtYieldExecution = IniLoadValue(IniFile, ProfileName, "NtYieldExecution", 1);
    CurrentProfile.HookNtSystemDebugControl = IniLoadValue(IniFile, ProfileName, "NtSystemDebugControl", 1);
    CurrentProfile.HookNtSetInformationThread = IniLoadValue(IniFile, ProfileName, "NtSetInformationThread", 1);
    CurrentProfile.HookNtSetInformationProcess = IniLoadValue(IniFile, ProfileName, "NtSetInformationProcess", 1);

    // Win32k Hooks
    CurrentProfile.HookNtUserBuildHwndList = IniLoadValue(IniFile, ProfileName, "NtUserBuildHwndList", 1);
    CurrentProfile.HookNtUserFindWindowEx = IniLoadValue(IniFile, ProfileName, "NtUserFindWindowEx", 1);
    CurrentProfile.HookNtUserGetForegroundWindow = IniLoadValue(IniFile, ProfileName, "NtUserGetForegroundWindow", 1);
    CurrentProfile.HookNtUserQueryWindow = IniLoadValue(IniFile, ProfileName, "NtUserQueryWindow", 1);

    // Other
    CurrentProfile.HookKiExceptionDispatch = IniLoadValue(IniFile, ProfileName, "KiExceptionDispatch", 1);
    CurrentProfile.HookKuserSharedData = IniLoadValue(IniFile, ProfileName, "HookKuserSharedData", 1);
    CurrentProfile.ClearPebBeingDebugged = IniLoadValue(IniFile, ProfileName, "PebBeingDebugged", 1);
    CurrentProfile.ClearPebNtGlobalFlag = IniLoadValue(IniFile, ProfileName, "PebNtGlobalFlag", 1);
    CurrentProfile.ClearHeapFlags = IniLoadValue(IniFile, ProfileName, "HeapFlags", 1);
    CurrentProfile.ClearKuserSharedData = IniLoadValue(IniFile, ProfileName, "ClearKuserSharedData", 1);
    CurrentProfile.ClearHideFromDebuggerFlag = IniLoadValue(IniFile, ProfileName, "ThreadHideFromDebuggerFlag", 1);
    CurrentProfile.ClearBypassProcessFreeze = IniLoadValue(IniFile, ProfileName, "ThreadBypassProcessFreeze", 1);
    CurrentProfile.ClearProcessBreakOnTerminationFlag = IniLoadValue(IniFile, ProfileName, "ProcessBreakOnTerminationFlag", 1);
    CurrentProfile.ClearThreadBreakOnTerminationFlag = IniLoadValue(IniFile, ProfileName, "ThreadBreakOnTerminationFlag", 1);
    CurrentProfile.SaveProcessDebugFlags = IniLoadValue(IniFile, ProfileName, "ProcessDebugFlags", 1);
    CurrentProfile.SaveProcessHandleTracing = IniLoadValue(IniFile, ProfileName, "ProcessHandleTracing", 1);
}

BOOL Settings::SaveProfile()
{
    BOOL Success = TRUE;

    // Nt Hooks
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtQueryInformationProcess", CurrentProfile.HookNtQueryInformationProcess);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtQueryInformationJobObject", CurrentProfile.HookNtQueryInformationJobObject);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtQueryInformationThread", CurrentProfile.HookNtQueryInformationThread);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtQueryObject", CurrentProfile.HookNtQueryObject);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtQueryPerformanceCounter", CurrentProfile.HookNtQueryPerformanceCounter);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtQuerySystemInformation", CurrentProfile.HookNtQuerySystemInformation);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtQuerySystemTime", CurrentProfile.HookNtQuerySystemTime);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtClose", CurrentProfile.HookNtClose);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtGetContextThread", CurrentProfile.HookNtGetContextThread);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtSetContextThread", CurrentProfile.HookNtSetContextThread);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtContinue", CurrentProfile.HookNtContinue);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtCreateUserProcess", CurrentProfile.HookNtCreateUserProcess);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtCreateProcessEx", CurrentProfile.HookNtCreateProcessEx);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtCreateThreadEx", CurrentProfile.HookNtCreateThreadEx);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtGetNextProcess", CurrentProfile.HookNtGetNextProcess);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtOpenThread", CurrentProfile.HookNtOpenThread);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtOpenProcess", CurrentProfile.HookNtOpenProcess);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtCreateFile", CurrentProfile.HookNtCreateFile);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtYieldExecution", CurrentProfile.HookNtYieldExecution);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtSystemDebugControl", CurrentProfile.HookNtSystemDebugControl);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtSetInformationThread", CurrentProfile.HookNtSetInformationThread);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtSetInformationProcess", CurrentProfile.HookNtSetInformationProcess);

    // Win32k Hooks
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtUserBuildHwndList", CurrentProfile.HookNtUserBuildHwndList);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtUserFindWindowEx", CurrentProfile.HookNtUserFindWindowEx);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtUserGetForegroundWindow", CurrentProfile.HookNtUserGetForegroundWindow);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "NtUserQueryWindow", CurrentProfile.HookNtUserQueryWindow);

    // Other
    Success &= IniSaveValue(IniFile, CurrentProfileName, "KiExceptionDispatch", CurrentProfile.HookKiExceptionDispatch);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "HookKuserSharedData", CurrentProfile.HookKuserSharedData);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "PebBeingDebugged", CurrentProfile.ClearPebBeingDebugged);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "PebNtGlobalFlag", CurrentProfile.ClearPebNtGlobalFlag);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "HeapFlags", CurrentProfile.ClearHeapFlags);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "ClearKuserSharedData", CurrentProfile.ClearKuserSharedData);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "ThreadHideFromDebuggerFlag", CurrentProfile.ClearHideFromDebuggerFlag);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "ThreadBypassProcessFreeze", CurrentProfile.ClearBypassProcessFreeze);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "ProcessBreakOnTerminationFlag", CurrentProfile.ClearProcessBreakOnTerminationFlag);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "ThreadBreakOnTerminationFlag", CurrentProfile.ClearThreadBreakOnTerminationFlag);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "ProcessDebugFlags", CurrentProfile.SaveProcessDebugFlags);
    Success &= IniSaveValue(IniFile, CurrentProfileName, "ProcessHandleTracing", CurrentProfile.SaveProcessHandleTracing);

    return Success;
}

BOOL Settings::AddProfile(std::string ProfileName)
{
    if (std::find(ProfileNames.begin(), ProfileNames.end(), ProfileName) != ProfileNames.end())
        return FALSE;

    ProfileNames.push_back(ProfileName);
    return TRUE;
}

VOID Settings::SetProfile(std::string ProfileName)
{
    if (CurrentProfileName == ProfileName)
        return;

    CurrentProfileName = ProfileName;
    IniSaveString(IniFile, SettingsSectionName, CurrentProfileKey, ProfileName);

    LoadProfile(ProfileName);
}

VOID Settings::Load(std::string IniPath)
{
    IniFile = IniPath + IniFileName;
    ProfileNames = IniLoadSectionNames(IniFile);

    ProfileNames.erase(std::remove(ProfileNames.begin(), ProfileNames.end(), SettingsSectionName), ProfileNames.end());

    CurrentProfileName = IniLoadString(IniFile, SettingsSectionName, CurrentProfileKey, DefaultProfile);
    LoadProfile(CurrentProfileName);
}

std::vector<std::string>& Settings::GetProfileNames()
{
    return ProfileNames;
}

Settings::Profile& Settings::GetCurrentProfile()
{
    return CurrentProfile;
}

std::string Settings::GetCurrentProfileName()
{
    return CurrentProfileName;
}