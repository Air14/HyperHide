#include <Windows.h>
#include <commctrl.h>
#include "pluginmain.h"
#include "resource.h"
#include "IniApi.h"
#include "Ioctl.h"
#include "Settings.h"
#include "Tooltips.h"
#include "HyperHideDrv.h"

enum MenuItems
{
    MENU_HIDER,
};

HINSTANCE hinst;
HWND hwndDlg;
int pluginHandle;
int hMenu;
int hMenuDisasm;
int hMenuDump;
int hMenuStack;

CONST ULONG CheckBoxNumber = IDC_CHK_SELECT_ALL - IDC_CHK_NTQUERYINFORMATIONPROCESS;

BOOLEAN Paused = FALSE;
BOOLEAN Attached = FALSE;
BOOLEAN PebFix = FALSE;
BOOLEAN BeingDebuggedCleared = FALSE;

ICONDATA IconData = { 0 };

Settings* g_Settings;
HyperHideDrv* g_HyperHideDrv;

std::string g_HyperHideIniPath;

HMODULE NtdllModule = 0;

std::string GetModulePath(HMODULE hModule)
{
    std::string FileName;
    DWORD Copied = 0;
    do {
        FileName.resize(FileName.size() + MAX_PATH);
        Copied = GetModuleFileNameA(hModule, &FileName[0], (DWORD)FileName.size());
    } while (Copied >= FileName.size());

    FileName.resize(Copied);
    return FileName;
}

BOOL SaveOptions(HWND hWnd)
{
    BOOLEAN* ProfileField = &g_Settings->GetCurrentProfile().HookNtQueryInformationProcess;
    for (size_t i = 0; i < CheckBoxNumber; i++)
        *(ProfileField + i) = IsDlgButtonChecked(hWnd, IDC_CHK_NTQUERYINFORMATIONPROCESS + i);

    return g_Settings->SaveProfile();
}

VOID UpdateOptions(HWND hDlg) 
{
    BOOLEAN* ProfileField = &g_Settings->GetCurrentProfile().HookNtQueryInformationProcess;
    for (size_t i = 0; i < CheckBoxNumber; i++)
        CheckDlgButton(hDlg, IDC_CHK_NTQUERYINFORMATIONPROCESS + i, *(ProfileField + i));
}

VOID Hide()
{
    HIDE_INFO HideInfo = { 0 };

    RtlCopyMemory(&HideInfo.HookNtQueryInformationProcess, &g_Settings->GetCurrentProfile().HookNtQueryInformationProcess, sizeof(g_Settings->GetCurrentProfile()));

    g_HyperHideDrv->Hide(HideInfo);
}

PLUG_EXPORT void CBATTACH(CBTYPE cbType, PLUG_CB_ATTACH* info) 
{
    g_HyperHideDrv->SetTargetPid(info->dwProcessId);

    if (g_HyperHideDrv->GetDriverHandleValue() == INVALID_HANDLE_VALUE)
        g_HyperHideDrv->CreateHandleToDriver();

    if (g_HyperHideDrv->GetDriverHandleValue() != INVALID_HANDLE_VALUE && Attached == FALSE)
    {
        if (g_HyperHideDrv->CallDriver(IOCTL_ADD_HIDER_ENTRY) == TRUE)
            Hide();
    }

    Attached = TRUE;
}

PLUG_EXPORT void CBDETACH(CBTYPE cbType, PLUG_CB_DETACH* info) 
{
    if (g_HyperHideDrv->GetDriverHandleValue() != INVALID_HANDLE_VALUE && Attached == TRUE)
        g_HyperHideDrv->CallDriver(IOCTL_REMOVE_HIDER_ENTRY);

    Attached = FALSE;
    Paused = FALSE;
    BeingDebuggedCleared = FALSE;
}

PLUG_EXPORT void CBEXITPROCESS(CBTYPE cbType, PLUG_CB_EXITPROCESS* info) 
{
    if (g_HyperHideDrv->GetDriverHandleValue() != INVALID_HANDLE_VALUE && Attached == TRUE)
        g_HyperHideDrv->CallDriver(IOCTL_REMOVE_HIDER_ENTRY);

    Attached = FALSE;
    Paused = FALSE;
    BeingDebuggedCleared = FALSE;
}

PLUG_EXPORT void CBPAUSEDEBUG(CBTYPE cbType, PLUG_CB_PAUSEDEBUG* info) 
{
    if (g_HyperHideDrv->GetDriverHandleValue() != INVALID_HANDLE_VALUE)
        g_HyperHideDrv->CallDriver(IOCTL_PROCESS_STOPPED);
    Paused = TRUE;
}

PLUG_EXPORT void CBRESUMEDEBUG(CBTYPE cbType, PLUG_CB_RESUMEDEBUG* info)
{
    if (g_HyperHideDrv->GetDriverHandleValue() != INVALID_HANDLE_VALUE)
        g_HyperHideDrv->CallDriver(IOCTL_PROCESS_RESUMED);
    Paused = FALSE;
}

void DebugLoop(CBTYPE cbType, void* callbackInfo) 
{
    PLUG_CB_DEBUGEVENT* de = (PLUG_CB_DEBUGEVENT*)callbackInfo;
    DEBUG_EVENT* DebugEvent = de->DebugEvent;

    if (g_Settings->GetCurrentProfile().ClearHeapFlags == TRUE)
    {
        if (PebFix == TRUE)
        {
            g_HyperHideDrv->CallDriver(IOCTL_SET_PEB_DEBUGGER_FLAG);
            PebFix = FALSE;
        }
        
        if (DebugEvent->u.LoadDll.lpBaseOfDll == NtdllModule)
        {
            g_HyperHideDrv->SetTargetPid(DebugEvent->dwProcessId);
            g_HyperHideDrv->CallDriver(IOCTL_CLEAR_PEB_DEBUGGER_FLAG);
            PebFix = TRUE;
        }
    }

    switch (DebugEvent->dwDebugEventCode)
    {
        case CREATE_PROCESS_DEBUG_EVENT:
        {
            if (DebugEvent->u.CreateProcessInfo.lpStartAddress == NULL)
            {
                if (Attached == TRUE && BeingDebuggedCleared == FALSE && g_Settings->GetCurrentProfile().ClearPebBeingDebugged == TRUE)
                {
                    BeingDebuggedCleared = TRUE;
                    g_HyperHideDrv->CallDriver(IOCTL_CLEAR_PEB_DEBUGGER_FLAG);
                }
            }

            break;
        }

        case EXCEPTION_DEBUG_EVENT:
        {
            if (DebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT)
            {
                g_HyperHideDrv->SetTargetPid(DebugEvent->dwProcessId);

                // Try to create handle to our driver
                if (g_HyperHideDrv->GetDriverHandleValue() == INVALID_HANDLE_VALUE)
                    g_HyperHideDrv->CreateHandleToDriver();

                if (g_HyperHideDrv->GetDriverHandleValue() != INVALID_HANDLE_VALUE && Attached == FALSE && g_HyperHideDrv->CallDriver(IOCTL_ADD_HIDER_ENTRY) == TRUE)
                    Hide();

                Attached = TRUE;
            }
            break;
        }
    }
}

INT_PTR CALLBACK HiderDialog(HWND hDlg, UINT Message, WPARAM wParam, LPARAM lParam)
{
    switch (Message)
    {
        case WM_INITDIALOG:
        {
            UpdateOptions(hDlg);

            for (size_t i = 0; i < g_Settings->GetProfileNames().size(); i++)
            {
                SendDlgItemMessageA(hDlg, IDC_COB_CURRENTPROFILE, CB_ADDSTRING, 0, (LPARAM)g_Settings->GetProfileNames()[i].c_str());
                if(g_Settings->GetCurrentProfileName() == g_Settings->GetProfileNames()[i])
                    SendDlgItemMessageA(hDlg, IDC_COB_CURRENTPROFILE, CB_SETCURSEL, i, 0);
            }

            CreateTooltips(hDlg);
            return TRUE;
        }

        case WM_CLOSE:
        {
            EndDialog(hDlg, 0);
            return TRUE;
        }

        case WM_COMMAND:
        {
            switch (LOWORD(wParam))
            {
                case IDC_BTN_OK: 
                {
                    if (SaveOptions(hDlg) == FALSE)
                    {
                        _plugin_logprintf("Error: Saving options failed\n");
                        break;
                    }

                    MessageBoxW(hDlg, L"Settings applied!", L"[HyperHide Options]", MB_ICONINFORMATION);

                    UpdateOptions(hDlg);

                    Hide();

                    break;
                }

                case IDC_BTN_CREATENEWPROFILE: 
                {
                    std::string NewProfileName;
                    NewProfileName.resize(GUI_MAX_LINE_SIZE);
                    if (!GuiGetLineWindow("Pass new profile name", &NewProfileName[0]))
                        break;

                    if (g_Settings->AddProfile(NewProfileName) == FALSE)
                        break;

                    g_Settings->SaveProfile();
                    g_Settings->SetProfile(NewProfileName);
                    SendDlgItemMessageA(hDlg, IDC_COB_CURRENTPROFILE, CB_ADDSTRING, 0, (LPARAM)NewProfileName.c_str());
                    int ProfileCount = SendDlgItemMessageA(hDlg, IDC_COB_CURRENTPROFILE, CB_GETCOUNT, 0, 0);
                    SendDlgItemMessageA(hDlg, IDC_COB_CURRENTPROFILE, CB_SETCURSEL, ProfileCount - 1, 0);

                    UpdateOptions(hDlg);

                    break;
                }

                case IDC_COB_CURRENTPROFILE: 
                {
                    if (HIWORD(wParam) != CBN_SELCHANGE)
                        break;

                    int ProfileIdx = (int)SendDlgItemMessageA(hDlg, IDC_COB_CURRENTPROFILE, CB_GETCURSEL, 0, 0);
                    g_Settings->SetProfile(g_Settings->GetProfileNames()[ProfileIdx]);

                    UpdateOptions(hDlg);
                    break;
                }

                case IDC_CHK_SELECT_ALL:
                {
                    if (IsDlgButtonChecked(hDlg, IDC_CHK_SELECT_ALL) == TRUE)
                    {
                        for (size_t i = 0; i < CheckBoxNumber; i++)
                        {
                            BOOL status = CheckDlgButton(hDlg, i + IDC_CHK_NTQUERYINFORMATIONPROCESS, BST_CHECKED);
                        }
                    }

                    else
                    {
                        for (size_t i = 0; i < CheckBoxNumber; i++)
                        {
                            CheckDlgButton(hDlg, i + IDC_CHK_NTQUERYINFORMATIONPROCESS, BST_UNCHECKED);
                        }
                    }

                    break;
                }
            }
        }
        return TRUE;
    }

    return FALSE;
}

void MenuEntry(CBTYPE cbType, void* CallbackInfo)
{
    PLUG_CB_MENUENTRY* Info = (PLUG_CB_MENUENTRY*)CallbackInfo;
    switch (Info->hEntry)
    {
        case MENU_HIDER:
        {
            if (g_HyperHideDrv->GetDriverHandleValue() == INVALID_HANDLE_VALUE)
            {
                if (g_HyperHideDrv->CreateHandleToDriver() == FALSE)
                {
                    MessageBoxA(hwndDlg, "Couldn't establish connection with HyperHide Driver\r\n", "Error", MB_OK);
                    break;
                }
            }

            DialogBox(hinst, MAKEINTRESOURCE(DLG_MAIN), NULL, HiderDialog);
            break;
        }
        default:
        {
            break;
        }
    }
}


PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
    pluginHandle = initStruct->pluginHandle;

    _plugin_registercallback(initStruct->pluginHandle, CB_MENUENTRY, MenuEntry);
    _plugin_registercallback(pluginHandle, CB_DEBUGEVENT, DebugLoop);

    return true;
}

PLUG_EXPORT bool plugstop()
{
    delete g_HyperHideDrv;
    return true;
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    hwndDlg = setupStruct->hwndDlg;
    hMenu = setupStruct->hMenu;
    hMenuDisasm = setupStruct->hMenuDisasm;
    hMenuDump = setupStruct->hMenuDump;
    hMenuStack = setupStruct->hMenuStack;
    
    g_HyperHideDrv = new HyperHideDrv();
    g_HyperHideDrv->CreateHandleToDriver();
    g_Settings = new Settings();
    g_Settings->Load(g_HyperHideIniPath);

    _plugin_menuaddentry(hMenu, MENU_HIDER, "&Options");

    HRSRC Icon = FindResourceW(hinst, MAKEINTRESOURCEW(IDB_ICON), L"PNG");
    if (Icon != NULL)
    {
        HGLOBAL IconResource = LoadResource(hinst, Icon);
        if (IconResource != NULL)
        {
            IconData.data = LockResource(IconResource);
            IconData.size = SizeofResource(hinst, Icon);

            if (IconData.data != NULL && IconData.size != NULL)
                _plugin_menuseticon(hMenu, &IconData);
        }
    }

}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,   
    LPVOID lpReserved) 
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            hinst = hinstDLL;
            g_HyperHideIniPath = GetModulePath(hinstDLL);
            g_HyperHideIniPath.resize(g_HyperHideIniPath.find_last_of(L'\\') + 1);
            NtdllModule = GetModuleHandleW(L"ntdll.dll");
            break;
        }

    }

    return TRUE;
}