#include <Windows.h>
#include <commctrl.h>
#include "resource.h"

HWND CreateTooltips(HWND hDlg)
{
    static const struct
    {
        unsigned Id;
        const wchar_t* Text;
    }Tooltips[] = {
        {
            IDC_BTN_OK,
            L"Apply Settings and save profile"
        },
        {
            IDC_CHK_SELECT_ALL,
            L"Set all checkboxes"
        },
        {
            IDC_CHK_NTQUERYINFORMATIONPROCESS,
            L"PROCESSINFOCLASS values can be used to detect a debugger.\r\n"
            L"ProcessDebugFlags: Should return 1 in the supplied buffer.\r\n"
            L"ProcessDebugPort: Should return 0 in the supplied buffer.\r\n"
            L"ProcessDebugObjectHandle: Should return 0 in the supplied buffer\r\nand the error STATUS_PORT_NOT_SET(0xC0000353)\r\n"
            L"ProcessBasicInformation: Reveals the parent process ID.\r\n"
            L"ProcessBreakOnTermination: Return depends on value passed to NtSetInformationProcess.\r\n"
            L"ProcessHandleTracing: Return depends on value passed to NtSetInformationProcess.\r\n"
            L"ProcessIoCounters: Field OtherOperationCount in IO_COUNTERS should be 1"
        },
        {
            IDC_CHK_NTSETINFORMATIONTHREAD,
            L"First THREADINFOCLASS value ThreadHideFromDebugger is a well-known\r\n"
            L"anti-debug techinque. The debugger cannot handle hidden threads.\r\n"
            L"This leads to a loss of control over the target.HyperHide will save information which thread supposed to be hidden\r\n"
            L"and uses that information in NtQueryInformationThread"
            L"Second THREADINFOCLASS value ThreadWow64Context can be used only in WOW64 app\r\n"
            L"and it can be used to clear hardware breakpoints\r\n"
            L"Third THREADINFOCLASS ThreadBreakOnTermination can cause a bsod when thread is being terminated\r\n"
            L"HyperHide will save information which thread has this flag set"
        },
        {
            IDC_CHK_NTQUERYINFORMATIONTHREAD,
            L"THREADINFOCLASS value ThreadHideFromDebugger can be used to retrive information if thread has HideFromDebugger flag set\r\n"
            L"THREADINFOCLASS value ThreadWow64Context can be used to retrive context of thread, can be only used in WOW64 app\r\n"
            L"THREADINFOCLASS value ThreadBreakOnTermination can be used to retrive information if thread has BreakOnTermination flag set"
        },
        {
            IDC_CHK_NTQUERYOBJECT,
            L"OBJECT_INFORMATION_CLASS ObjectTypesInformation and ObjectTypeInformation\r\n"
            L"can be used to detect debuggers. HyperHide filters only debugger DebugObject references because debugged process\r\n"
            L"can also create DebugObject."
        },
        {
            IDC_CHK_NTSYSTEMDEBUGCONTROL,
            L"The SYSDBG_COMMAND SysDbgGetTriageDump should return STATUS_INFO_LENGTH_MISMATCH\r\n"
            L"and for other values STATUS_DEBUGGER_INACTIVE."
        },
        {
            IDC_CHK_NTCLOSE,
            L"This is called with an invalid handle or with handle protected from closing to detect a debugger.\r\n"
            L"HyperHide calls ZwQueryObject to check the validity of the handle."
        },
        {
            IDC_CHK_NTSETCONTEXTTHREAD,
            L"NtSetContextThread is used to clear hardware breakpoints"
            L"Doens't work under WOW64 Process."
        },
        {
            IDC_CHK_NTQUERYSYSTEMINFORMATION,
            L"SYSTEM_INFORMATION_CLASS values SystemKernelDebuggerInformation,SystemKernelDebuggerInformationEx\r\n"
            L"and SystemKernelDebuggerFlags can be used to detect kernel debuggers.\r\n"
            L"SYSTEM_INFORMATION_CLASS values SystemProcessInformation,SystemSessionProcessInformation\r\n"
            L"SystemExtendedProcessInformation and SystemFullProcessInformation\r\n"
            L"are used to get a process list and process parent pid\r\n"
            L"SystemHandleInformation and SystemExtendedHandleInformation are used to\r\n"
            L"enumerate system process handles to detect e.g. handles to the debuggee process.\r\n"
            L"The SYSTEM_INFORMATION_CLASS value SystemCodeIntegrityInformation can be used to detect test signing mode."
        },
        {
            IDC_CHK_NTGETCONTEXTTHREAD,
            L"NtGetContextThread is used to check hardware breakpoints\r\n"
            L"Doens't work under WOW64 Process."
        },
        {
            IDC_CHK_NTCREATETHREADEX,
            L"NtCreateThreadEx can be used to create thread with ThreadHideFromDebugger which effect is the same\r\n"
            L"as NtSetInformationThread or with ThreadCreateFlagsBypassFrocessFreeze\r\n"
            L"which can make thread unable to pause (this option is only avalibe on windows 19h1 and newer)"
        },
        {
            IDC_CHK_NTCREATEFILE,
            L"NtCreateFile can be used to create handle to some driver for example\r\n"
            L"Hypervisor or HyperHide driver."
        },
        {
            IDC_CHK_NTYIELDEXECUTION,
            L"A very unrealiable anti-debug method. This is only used in some UnpackMe's\r\n"
            L"or in some Proof of Concept code. Only activate this if you really need it.\r\n"
            L"Probably you will never need this option."
        },
        {
            IDC_CHK_NTCREATEUSERPROCESS,
            L"NtCreateProcessEx can be used to create a process with thread\r\n"
            L"HyperHide will hide process which was created by another hidden process."
        },
        {
            IDC_CHK_NTUSERBUILDHWNDLIST,
            L"This is a system call function in user32.dll.\r\n"
            L"The windows APIs EnumWindows and EnumThreadWindows call this internally.\r\n"
            L"The debugger and other tools (procmon,procexp,wireshark etc.) windows will be hidden."
        },
        {
            IDC_CHK_NTUSERFINDWINDOWEX,
            L"This is a system call function in user32.dll.\r\n"
            L"The windows APIs FindWindowA/W and FindWindowExA/W call this internally.\r\n"
            L"The debugger and other tools (procmon,procexp,wireshark etc.) windows will be hidden."
        },
        {
            IDC_CHK_NTUSERQUERYWINDOW,
            L"This is a system call function in user32.dll.\r\n"
            L"The windows API GetWindowThreadProcessId calls this internally.\r\n"
            L"This is used to hide the debugger and other tools (procmon,procexp,wireshark etc.) processes."
        },
        {
            IDC_CHK_NTQUERYSYSTEMTIME,
            L"There are a few windows APIs to measure the time. Timing can be used to\r\n"
            L"detect debuggers, because they slow down the execution. If KsuerSharedData option is checked\r\n"
            L"this function will return value from spoofed KsuerSharedData page."
        },
        {
            IDC_CHK_NTQUERYPERFORMANCECOUNTER,
            L"There are a few windows APIs to measure the time. Timing can be used to\r\n"
            L"detect debuggers, because they slow down the execution. If KsuerSharedData option is checked\r\n"
            L"this function will return value from spoofed KsuerSharedData page."
        },
        {
            IDC_CHK_KUSER_SHARED_DATA,
            L"If checked it will replace debugee pfn of kusershareddata with our new created page pfn\r\n"
            L"When process is paused all counters won't update until you unpause so no time attacks will be possible."
        },
        {
            IDC_CHK_NTCONTINUE,
            L"NtContinue can be used to detect/clear hardware breakpoints"
        },
        {
            IDC_CHK_KIEXCEPTIONDISPATCH,
            L"If checked HyperHideDrv will clear all hardware breakpoints and restore them in NtContinue so\r\n"
            L"hooked KiUserExceptionDispatcher won't spot anything"
        },
        {
            IDC_CHK_NTQUERYINFORMATIONJOBOBJECT,
            L"When process is created by x64dbg/x32dbg it belongs to his job object\r\n"
            L"so we have to clear it"
        },
        {
            IDC_CHK_NTCREATEPROCESSEX,
            L"Probably you won't ever use this because it's deprecated function and is no longer used to create user mode process\r\n"
            L"If checked HyperHide will also hide process which was created by another hidden process."
        },
        {
            IDC_CHK_NTGETNEXTPROCESS,
            L"Can be used to enumerate all existing process so we have to filter it in case of our debugge or other toolsr"
        },
        {
            IDC_CHK_NTOPENPROCESS,
            L"Can be used to enumerate all existing process so we have to filter it in case of our debugger or other tools"
        },
        {
            IDC_CHK_NTOPENTHREAD,
            L"Can be used to enumerate all existing threads so we have to filter it in case of our debugger or other tools"
        },
        {
            IDC_CHK_NTUSERGETFOREGROUNDWINDOW,
            L"This is a system call function in user32.dll.\r\n"
            L"The windows API GetForegroundWindow calls this internally.\r\n"
            L"The debugger window will be hidden."
        },
        {
            IDC_CHK_NTSETINFORMATIONPROCESS,
            L"PROCESSINFOCLASS values ProcessHandleTracing and ProcessDebugFlags can be used to\r\n"
            L"detect a debugger (Valuse passed to NtSetInformationProcess will be saved and later used in NtQueryInformation Process).\r\n"
            L"PROCESSINFOCLASS value ProcessBreakOnTermination can be used to generate a bsod on process termination."
        },
        {
            IDC_CHK_CLEARPEBBEINGDEBUGGED,
            L"Clear BeingDebugged which indicates that process is debugged"
        },
        {
            IDC_CHK_CLEARHEAPFLAGS,
            L"Clear HeapFlags and HeapForceFlags which indicates that process is debugged"
        },
        {
            IDC_CHK_CLEARPEBNTGLOBALFLAG,
            L"Clear NtGlobalFlag which indcates that process is debugged."
        },
        {
            IDC_CHK_CLEARKUSERSHAREDDATA,
            L"It clears KernelDebugging flag from kusershareddata spoofed page\r\n"
            L"Use only if you checked Kusershareddata option and if kernel debugger is present"
        },
        {
            IDC_CHK_CLEARHIDEFROMDEBUGGER,
            L"If you are attaching to existing process it will clear ThreadHideFromDebugger flag from\r\n"
            L"all threads and will save information about which one were hidden, for use in NtQueryThreadInformation"
        },
        {
            IDC_CHK_CLEARBYPASSFREEZEFLAG,
            L"If you are attaching to existing process it will clear BypassFreezeFlag flag from all process threads"
        },
        {
            IDC_CHK_CLEARPROCESSBREAKONTERM,
            L"If you are attaching to existing process it will clear ProcessBreakOnTremination flag\r\n"
            L"and will save information about it, for use in NtQueryInformationProcess"
        },
        {
            IDC_CHK_CLEARTHREADBREAKONTERM,
            L"If you are attaching to existing process it will clear ThreadBreakOnTermination flag from\r\n"
            L"all process threads and will save information about which one were hidden, for use in NtQueryThreadInformation"
        },
        {
            IDC_CHK_SAVEPROCESSDEBUGFLAGS,
            L"If you are attaching to existing process it will save ProcessDebugFlags value for use in NtQueryProcessInformation"
        },
        {
            IDC_CHK_SAVEPROCESSHANDLETRACING,
            L"If you are attaching to existing process it will save ProcessHandleTracing value for use in NtQueryProcessInformation"
        }
    };

    HINSTANCE Instance = (HINSTANCE)GetWindowLongPtrW(hDlg, GWLP_HINSTANCE);
    if (Instance == NULL)
        return 0;

    HWND TooltipsWnd = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, 0,
        WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        hDlg, 0, Instance, 0);

    if (TooltipsWnd == NULL)
        return 0;

    for (int i = 0; i < sizeof(Tooltips) / sizeof(Tooltips[0]); i++)
    {
        HWND Ctrl = GetDlgItem(hDlg, Tooltips[i].Id);
        if (!Ctrl)
            continue;

        TOOLINFOA Ti;
        Ti.cbSize = TTTOOLINFOW_V1_SIZE;
        Ti.uFlags = TTF_SUBCLASS | TTF_IDISHWND;
        Ti.hwnd = hDlg;
        Ti.uId = (UINT_PTR)Ctrl;
        Ti.hinst = Instance;
        Ti.lpszText = (char*)(Tooltips[i].Text);
        Ti.lParam = 0;

        SendMessageW(TooltipsWnd, TTM_ADDTOOL, 0, (LPARAM)&Ti);
    }

    SendMessageW(TooltipsWnd, TTM_SETMAXTIPWIDTH, 0, 500);
    SendMessageW(TooltipsWnd, TTM_ACTIVATE, TRUE, 0);

    return TooltipsWnd;
}