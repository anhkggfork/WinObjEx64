/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       EXTRASPSLIST.C
*
*  VERSION:     1.73
*
*  DATE:        16 Mar 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#define OEMRESOURCE
#include "global.h"
#include "propDlg.h"
#include "extras.h"
#include "extrasPSList.h"
#include "treelist/treelist.h"
#include "resource.h"

#define Y_SPLITTER_SIZE 4
#define Y_SPLITTER_MIN  80

#define T_IDLE_PROCESS TEXT("Idle")
#define T_IDLE_PROCESS_LENGTH sizeof(T_IDLE_PROCESS)

EXTRASCONTEXT   PsDlgContext;
static int      y_splitter_pos = 200, y_capture_pos = 0, y_splitter_max = 0;

HANDLE g_PsListWait = NULL;
ULONG g_DialogQuit = 0, g_DialogRefresh = 0;
HANDLE g_PsListHeap = NULL;

/*
* PsxAllocateUnnamedObjectEntry
*
* Purpose:
*
* Allocate PROP_UNNAMED_OBJECT_INFO entry.
*
*/
PROP_UNNAMED_OBJECT_INFO *PsxAllocateUnnamedObjectEntry(
    _In_ PVOID Data,
    _In_ SIZE_T DataSize,
    _In_ BOOL IsProcess
)
{
    PSYSTEM_PROCESSES_INFORMATION processEntry;
    PROP_UNNAMED_OBJECT_INFO *objectEntry;

    objectEntry = (PROP_UNNAMED_OBJECT_INFO*)RtlAllocateHeap(g_PsListHeap,
        HEAP_ZERO_MEMORY, sizeof(PROP_UNNAMED_OBJECT_INFO));

    if (objectEntry == NULL)
        return NULL;

    objectEntry->DataPointer = RtlAllocateHeap(g_PsListHeap,
        HEAP_ZERO_MEMORY, DataSize);

    if (objectEntry->DataPointer == NULL) {
        supHeapFree(objectEntry);
        return NULL;
    }
    else {
        RtlCopyMemory(objectEntry->DataPointer, Data, DataSize);
        objectEntry->DataSize = DataSize;
    }

    if (IsProcess) {
        processEntry = (PSYSTEM_PROCESSES_INFORMATION)Data;

        objectEntry->ImageName.MaximumLength = processEntry->ImageName.MaximumLength;
        objectEntry->ImageName.Buffer = (PWSTR)RtlAllocateHeap(g_PsListHeap,
            HEAP_ZERO_MEMORY,
            objectEntry->ImageName.MaximumLength);
        if (objectEntry->ImageName.Buffer) {
            RtlCopyUnicodeString(&objectEntry->ImageName, &processEntry->ImageName);
        }

    }
    return objectEntry;
}

/*
* PsListDialogResize
*
* Purpose:
*
* WM_SIZE handler.
*
*/
INT_PTR PsListDialogResize(
    VOID
)
{
    RECT r, szr;

    RtlSecureZeroMemory(&r, sizeof(RECT));
    RtlSecureZeroMemory(&szr, sizeof(RECT));

    SendMessage(PsDlgContext.StatusBar, WM_SIZE, 0, 0);
    GetClientRect(PsDlgContext.hwndDlg, &r);
    GetClientRect(PsDlgContext.StatusBar, &szr);
    y_splitter_max = r.bottom - Y_SPLITTER_MIN;

    SetWindowPos(PsDlgContext.TreeList, 0,
        0, 0,
        r.right,
        y_splitter_pos,
        SWP_NOOWNERZORDER);

    SetWindowPos(PsDlgContext.ListView, 0,
        0, y_splitter_pos + Y_SPLITTER_SIZE,
        r.right,
        r.bottom - y_splitter_pos - Y_SPLITTER_SIZE - szr.bottom,
        SWP_NOOWNERZORDER);

    return 1;
}

/*
* PsListHandlePopupMenu
*
* Purpose:
*
* Processes/threads list popup construction
*
*/
VOID PsListHandlePopupMenu(
    _In_ HWND hwndDlg,
    _In_ LPPOINT point,
    _In_ UINT itemCopy,
    _In_ UINT itemRefresh
)
{
    HMENU hMenu;

    hMenu = CreatePopupMenu();
    if (hMenu) {
        InsertMenu(hMenu, 0, MF_BYCOMMAND, itemCopy, T_COPYOBJECT);
        InsertMenu(hMenu, 1, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
        InsertMenu(hMenu, 2, MF_BYCOMMAND, itemRefresh, T_VIEW_REFRESH);
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, point->x, point->y, 0, hwndDlg, NULL);
        DestroyMenu(hMenu);
    }

}

/*
* PsListCompareFunc
*
* Purpose:
*
* Dialog listview comparer function.
*
*/
INT CALLBACK PsListCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort
)
{
    INT nResult = 0;

    switch (lParamSort) {
    case 0: //TID
    case 1: //BasePriority
        return supGetMaxOfTwoULongFromString(
            PsDlgContext.ListView,
            lParam1,
            lParam2,
            PsDlgContext.lvColumnToSort,
            PsDlgContext.bInverseSort);
    case 2: //string (fixed size)
    case 5: //string (fixed size)
        return supGetMaxCompareTwoFixedStrings(
            PsDlgContext.ListView,
            lParam1,
            lParam2,
            PsDlgContext.lvColumnToSort,
            PsDlgContext.bInverseSort);
    case 3: //ethread (hex)
    case 4: //address (hex)
        return supGetMaxOfTwoU64FromHex(
            PsDlgContext.ListView,
            lParam1,
            lParam2,
            PsDlgContext.lvColumnToSort,
            PsDlgContext.bInverseSort);
    }

    return nResult;
}

/*
* PsListGetObjectEntry
*
* Purpose:
*
* Return pointer to data from selected object list entry.
*
*/
PROP_UNNAMED_OBJECT_INFO *PsListGetObjectEntry(
    _In_ BOOL bTreeList,
    _In_opt_ HTREEITEM hTreeItem)
{
    INT nSelected;
    TVITEMEX itemex;
    TL_SUBITEMS_FIXED *subitems = NULL;
    PROP_UNNAMED_OBJECT_INFO *ObjectEntry = NULL;

    if (bTreeList) {
        //RtlSecureZeroMemory(&itemex, sizeof(itemex));
        if (hTreeItem) {
            itemex.hItem = hTreeItem;
        }
        else {
            itemex.hItem = TreeList_GetSelection(PsDlgContext.TreeList);
        }
        if (TreeList_GetTreeItem(PsDlgContext.TreeList, &itemex, &subitems))
            if (subitems)
                ObjectEntry = (PROP_UNNAMED_OBJECT_INFO*)subitems->UserParam;
    }
    else {
        nSelected = ListView_GetSelectionMark(PsDlgContext.ListView);
        supGetListViewItemParam(PsDlgContext.ListView, nSelected, (PVOID*)&ObjectEntry);
    }

    return ObjectEntry;
}

/*
* PsListHandleObjectProp
*
* Purpose:
*
* Show properties for selected object.
*
*/
VOID PsListHandleObjectProp(
    _In_ BOOL bProcessList,
    _In_ PROP_UNNAMED_OBJECT_INFO* ObjectEntry)
{
    SIZE_T sz;
    LPWSTR lpName;
    HANDLE UniqueProcessId = NULL, ObjectHandle = NULL;

    PUNICODE_STRING ImageName = NULL;

    PROP_UNNAMED_OBJECT_INFO *tempEntry;

    if (g_PsPropWindow != NULL) {
        return;
    }

    if (bProcessList) {

        if (NT_SUCCESS(supOpenProcess(
            ObjectEntry->Process->UniqueProcessId,
            PROCESS_QUERY_LIMITED_INFORMATION,
            &ObjectHandle)))
        {
            supQueryObjectFromHandle(ObjectHandle, &ObjectEntry->ObjectAddress, NULL);
            NtClose(ObjectHandle);
        }

        ImageName = &ObjectEntry->ImageName;
        UniqueProcessId = ObjectEntry->Process->UniqueProcessId;
    }
    else {

        tempEntry = PsListGetObjectEntry(TRUE, NULL);
        if (tempEntry) {
            UniqueProcessId = tempEntry->Process->UniqueProcessId;
            ImageName = &tempEntry->ImageName;

            if (NT_SUCCESS(supOpenThread(
                ObjectEntry->Thread->ClientId.UniqueProcess,
                ObjectEntry->Thread->ClientId.UniqueThread,
                THREAD_QUERY_LIMITED_INFORMATION,
                &ObjectHandle)))
            {
                supQueryObjectFromHandle(ObjectHandle, &ObjectEntry->ObjectAddress, NULL);
                NtClose(ObjectHandle);
            }

        }
    }

    if (ImageName == NULL)
        return;

    //
    // Create fake name for display.
    //
    sz = 1024 + ImageName->Length;
    lpName = (LPWSTR)supHeapAlloc(sz);
    if (lpName == NULL)
        return;

    if (ImageName->Length == 0) {
        if (UniqueProcessId == NULL) {
            _strcpy(lpName, T_IDLE_PROCESS);
        }
        else {
            _strcpy(lpName, TEXT("UnknownProcess"));
        }
    }
    else {
        RtlCopyMemory(lpName,
            ImageName->Buffer,
            ImageName->Length);
    }
    _strcat(lpName, TEXT(" PID:"));
    ultostr(HandleToULong(UniqueProcessId), _strend(lpName));

    if (!bProcessList) {
        _strcat(lpName, TEXT(" TID:"));
        ultostr(HandleToULong(ObjectEntry->Thread->ClientId.UniqueThread), _strend(lpName));
    }

    propCreateDialog(
        0,
        lpName,
        (bProcessList) ? OBTYPE_NAME_PROCESS : OBTYPE_NAME_THREAD,
        NULL,
        NULL,
        ObjectEntry);

    supHeapFree(lpName);
}

/*
* PsListProcessInServicesList
*
* Purpose:
*
* Return TRUE if given process is in SCM snapshot.
*
*/
BOOLEAN PsListProcessInServicesList(
    _In_ HANDLE ProcessId,
    _In_ SCMDB *ServicesList
)
{
    DWORD u;
    LPENUM_SERVICE_STATUS_PROCESS pInfo = NULL;

    pInfo = (LPENUM_SERVICE_STATUS_PROCESS)ServicesList->Entries;
    for (u = 0; u < ServicesList->NumberOfEntries; u++) {
        if (pInfo[u].ServiceStatusProcess.dwProcessId)
            if (UlongToHandle(pInfo[u].ServiceStatusProcess.dwProcessId) == ProcessId)
            {
                return TRUE;
            }
    }
    return FALSE;
}

/*
* AddProcessEntryTreeList
*
* Purpose:
*
* Insert process entry to the treelist.
*
*/
HTREEITEM AddProcessEntryTreeList(
    _In_opt_ HTREEITEM RootItem,
    _In_ OBEX_PROCESS_LOOKUP_ENTRY* Entry,
    _In_ ULONG_PTR ObjectAddress,
    _In_ SCMDB *ServicesList,
    _In_ PSID OurSid
)
{
    HTREEITEM hTreeItem = NULL;
    PSID ProcessSid = NULL;
    PSYSTEM_PROCESSES_INFORMATION processEntry;
    PROP_UNNAMED_OBJECT_INFO *objectEntry;
    TL_SUBITEMS_FIXED subitems;

    ULONG Length, r;
    PWSTR Caption = NULL, PtrString, UserName = NULL;

    PROCESS_EXTENDED_BASIC_INFORMATION exbi;
    WCHAR szEPROCESS[32];

    SID SidLocalService = { SID_REVISION, 1, SECURITY_NT_AUTHORITY, { SECURITY_LOCAL_SERVICE_RID } };

    objectEntry = PsxAllocateUnnamedObjectEntry(Entry->EntryPtr, Entry->EntrySize, TRUE);
    if (objectEntry == NULL)
        return NULL;

    processEntry = (PSYSTEM_PROCESSES_INFORMATION)objectEntry->DataPointer;

    //
    // Id + Name
    //
    Length = 32;
    if (objectEntry->ImageName.Length) {
        Length += objectEntry->ImageName.Length;
    }
    else {
        if (processEntry->UniqueProcessId == 0) {
            Length += T_IDLE_PROCESS_LENGTH;
        }
    }

    RtlSecureZeroMemory(&subitems, sizeof(subitems));

    Caption = (PWSTR)supHeapAlloc(Length);
    if (Caption) {

        PtrString = _strcat(Caption, TEXT("["));
        ultostr(HandleToULong(processEntry->UniqueProcessId), PtrString);
        _strcat(Caption, TEXT("]"));

        _strcat(Caption, TEXT(" "));

        if (processEntry->UniqueProcessId == 0) {
            _strcat(Caption, T_IDLE_PROCESS);
        }
        else {
            if (objectEntry->ImageName.Buffer) {
                _strcat(Caption, objectEntry->ImageName.Buffer);
            }
            else {
                _strcat(Caption, T_Unknown);
            }
        }
    }

    //
    // EPROCESS value (can be NULL)
    //
    szEPROCESS[0] = 0;
    if (ObjectAddress) {
        szEPROCESS[0] = L'0';
        szEPROCESS[1] = L'x';
        u64tohex(ObjectAddress, &szEPROCESS[2]);
    }

    subitems.UserParam = (PVOID)objectEntry;
    subitems.Count = 2;
    subitems.Text[0] = szEPROCESS;

    //
    // Colors.
    //
    //
    // 1. Services.
    //

    if (Entry->hProcess) {
        ProcessSid = supQueryProcessSid(Entry->hProcess);
    }

    if (PsListProcessInServicesList(processEntry->UniqueProcessId, ServicesList) ||
        ((ProcessSid) && RtlEqualSid(&SidLocalService, ProcessSid)))
    {
        subitems.ColorFlags = TLF_BGCOLOR_SET;
        subitems.BgColor = 0xd0d0ff;
    }

    //
    // 2. Store process.
    // 3. Protected process.
    //
    if (Entry->hProcess) {
        if (g_ExtApiSet.IsImmersiveProcess) {
            if (g_ExtApiSet.IsImmersiveProcess(Entry->hProcess)) {
                subitems.ColorFlags = TLF_BGCOLOR_SET;
                subitems.BgColor = 0xeaea00;
            }
        }

        exbi.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);
        if (NT_SUCCESS(NtQueryInformationProcess(Entry->hProcess, ProcessBasicInformation,
            &exbi, sizeof(exbi), &r)))
        {
            if (exbi.IsProtectedProcess) {
                subitems.ColorFlags = TLF_BGCOLOR_SET;
                subitems.BgColor = 0xe6ffe6;
            }
        }
    }

    //
    // User.
    //
    if (ProcessSid) {

        //
        // 4. Current user process.
        //
        if (RtlEqualSid(OurSid, ProcessSid)) {
            subitems.ColorFlags = TLF_BGCOLOR_SET;
            subitems.BgColor = 0xffd0d0;
        }

        if (supLookupSidUserAndDomain(ProcessSid, &UserName)) {
            subitems.Text[1] = UserName;
        }
        supHeapFree(ProcessSid);
    }

    hTreeItem = TreeListAddItem(
        PsDlgContext.TreeList,
        RootItem,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        Caption,
        &subitems);

    if (UserName)
        supHeapFree(UserName);
    if (Caption)
        supHeapFree(Caption);

    return hTreeItem;
}

typedef BOOL(CALLBACK *FINDITEMCALLBACK)(
    HWND TreeList,
    HTREEITEM htItem,
    ULONG_PTR UserContext
    );

/*
* FindItemByProcessIdCallback
*
* Purpose:
*
* Search callback.
*
*/
BOOL CALLBACK FindItemMatchCallback(
    _In_ HWND TreeList,
    _In_ HTREEITEM htItem,
    _In_ ULONG_PTR UserContext
)
{
    HANDLE             ParentProcessId = (HANDLE)UserContext;
    TL_SUBITEMS_FIXED *subitems = NULL;
    TVITEMEX           itemex;

    PROP_UNNAMED_OBJECT_INFO* Entry;

    RtlSecureZeroMemory(&itemex, sizeof(itemex));
    itemex.hItem = htItem;
    TreeList_GetTreeItem(TreeList, &itemex, &subitems);

    if (subitems) {
        if (subitems->UserParam == NULL)
            return FALSE;

        Entry = (PROP_UNNAMED_OBJECT_INFO*)subitems->UserParam;
        return (ParentProcessId == Entry->Process->UniqueProcessId);
    }

    return FALSE;
}

/*
* FindItemRecursive
*
* Purpose:
*
* Recursive find item.
*
*/
HTREEITEM FindItemRecursive(
    _In_ HWND TreeList,
    _In_ HTREEITEM htStart,
    _In_ FINDITEMCALLBACK FindItemCallback,
    _In_ ULONG_PTR UserContext
)
{
    HTREEITEM htItemMatch = NULL;
    HTREEITEM htItemCurrent = htStart;

    if (FindItemCallback == NULL)
        return NULL;

    while (htItemCurrent != NULL && htItemMatch == NULL) {
        if (FindItemCallback(TreeList, htItemCurrent, UserContext)) {
            htItemMatch = htItemCurrent;
        }
        else {
            htItemMatch = FindItemRecursive(TreeList,
                TreeList_GetChild(TreeList, htItemCurrent), FindItemCallback, UserContext);
        }
        htItemCurrent = TreeList_GetNextSibling(TreeList, htItemCurrent);
    }
    return htItemMatch;
}

/*
* FindParentItem
*
* Purpose:
*
* Return treelist item with given parent process id.
*
*/
HTREEITEM FindParentItem(
    _In_ HWND TreeList,
    _In_ HANDLE ParentProcessId
)
{
    HTREEITEM htiRoot = TreeList_GetRoot(TreeList);
    return FindItemRecursive(TreeList,
        htiRoot, FindItemMatchCallback, (ULONG_PTR)ParentProcessId);
}

/*
* PsListGetThreadStateAsString
*
* Purpose:
*
* Return thread state string description.
*
*/
LPWSTR PsListGetThreadStateAsString(
    _In_ THREAD_STATE ThreadState,
    _In_ KWAIT_REASON WaitReason,
    _In_ LPWSTR StateBuffer)
{
    LPWSTR lpState = T_Unknown;
    LPWSTR lpWaitReason = T_Unknown;

    if (ThreadState == StateWait) {

        _strcpy(StateBuffer, TEXT("Wait:"));

        if (WaitReason < MAX_KNOWN_WAITREASON)
            lpWaitReason = T_WAITREASON[WaitReason];

        _strcat(StateBuffer, lpWaitReason);
    }
    else {


        switch (ThreadState) {
        case StateInitialized:
            lpState = TEXT("Initiailized");
            break;
        case StateReady:
            lpState = TEXT("Ready");
            break;
        case StateRunning:
            lpState = TEXT("Running");
            break;
        case StateStandby:
            lpState = TEXT("Standby");
            break;
        case StateTerminated:
            lpState = TEXT("Terminated");
            break;
        case StateTransition:
            lpState = TEXT("Transition");
            break;
        case StateUnknown:
        default:
            break;
        }

        _strcpy(StateBuffer, lpState);
    }
    return StateBuffer;
}

/*
* CreateThreadListProc
*
* Purpose:
*
* Build and output process threads list.
*
*/
DWORD WINAPI CreateThreadListProc(
    _In_ PROP_UNNAMED_OBJECT_INFO *ObjectEntry
)
{
    INT ItemIndex;
    ULONG i, ThreadCount, ErrorCount = 0;
    HANDLE UniqueProcessId;
    PVOID ProcessList = NULL;
    PSYSTEM_PROCESSES_INFORMATION Process;
    PSYSTEM_THREAD_INFORMATION Thread;
    PRTL_PROCESS_MODULES pModules = NULL;
    PSYSTEM_HANDLE_INFORMATION_EX pHandles = NULL;
    PSYSTEM_HANDLE_INFORMATION_EX SortedHandleList = NULL;

    PROP_UNNAMED_OBJECT_INFO *objectEntry, *threadEntry;
    OBEX_THREAD_LOOKUP_ENTRY *stl = NULL, *stlptr;

    LVITEM lvitem;
    WCHAR szBuffer[MAX_PATH];

    ULONG_PTR startAddress = 0, objectAddress = 0;

    DWORD dwWaitResult;

    __try {

        dwWaitResult = WaitForSingleObject(g_PsListWait, INFINITE);
        if (dwWaitResult == WAIT_OBJECT_0) {

            ListView_DeleteAllItems(PsDlgContext.ListView);

            UniqueProcessId = ObjectEntry->Process->UniqueProcessId;

            //
            // Refresh thread list.
            //
            ProcessList = supGetSystemInfo(SystemProcessInformation, NULL);
            if (ProcessList == NULL)
                __leave;

            //
            // Leave if process died.
            //
            if (!supQueryProcessEntryById(UniqueProcessId, ProcessList, &Process))
                __leave;

            pModules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation, NULL);

            ThreadCount = Process->ThreadCount;
            stl = (OBEX_THREAD_LOOKUP_ENTRY*)supHeapAlloc(ThreadCount * sizeof(OBEX_THREAD_LOOKUP_ENTRY));
            if (stl == NULL)
                __leave;

            stlptr = stl;

            for (i = 0, Thread = Process->Threads;
                i < ThreadCount;
                i++, Thread++, stlptr++)
            {
                objectEntry = PsxAllocateUnnamedObjectEntry(Thread, sizeof(SYSTEM_THREAD_INFORMATION), FALSE);
                if (objectEntry) {

                    stlptr->EntryPtr = (PVOID)objectEntry;

                    if (!NT_SUCCESS(supOpenThread(Thread->ClientId.UniqueProcess,
                        Thread->ClientId.UniqueThread,
                        THREAD_QUERY_INFORMATION,
                        &stlptr->hThread)))
                    {
                        supOpenThread(
                            Thread->ClientId.UniqueProcess,
                            Thread->ClientId.UniqueThread,
                            THREAD_QUERY_LIMITED_INFORMATION,
                            &stlptr->hThread);
                    }
                }
            }

            supHeapFree(ProcessList);
            ProcessList = NULL;

            pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation, NULL);
            if (pHandles) {
                SortedHandleList = supHandlesCreateFilteredAndSortedList(pHandles);
                supHeapFree(pHandles);
                pHandles = NULL;
            }

            stlptr = stl;

            for (i = 0; i < ThreadCount; i++, stlptr++) {

                threadEntry = (PROP_UNNAMED_OBJECT_INFO*)stlptr->EntryPtr;

                //
                // TID
                //               
                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                ultostr(HandleToULong(threadEntry->Thread->ClientId.UniqueThread), szBuffer);

                RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
                lvitem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
                lvitem.iItem = MAXINT;
                lvitem.iImage = I_IMAGENONE;
                lvitem.pszText = szBuffer;
                lvitem.cchTextMax = MAX_PATH;
                lvitem.lParam = (LPARAM)threadEntry;
                ItemIndex = ListView_InsertItem(PsDlgContext.ListView, &lvitem);

                //
                // Priority
                //
                szBuffer[0] = 0;
                ultostr(threadEntry->Thread->Priority, szBuffer);

                lvitem.mask = LVIF_TEXT;
                lvitem.iSubItem++;
                lvitem.pszText = szBuffer;
                lvitem.iItem = ItemIndex;
                ListView_SetItem(PsDlgContext.ListView, &lvitem);

                //
                // State
                //
                lvitem.mask = LVIF_TEXT;
                lvitem.iSubItem++;

                lvitem.pszText = PsListGetThreadStateAsString(
                    threadEntry->Thread->State,
                    threadEntry->Thread->WaitReason, szBuffer);

                lvitem.iItem = ItemIndex;
                ListView_SetItem(PsDlgContext.ListView, &lvitem);

                // Query thread specific information - object and win32 start address (need elevation).
                startAddress = 0;
                objectAddress = 0;

                if (stlptr->hThread) {

                    if (!supQueryThreadWin32StartAddress(
                        stlptr->hThread,
                        &startAddress))
                    {
                        ErrorCount += 1;
                    }

                    if (SortedHandleList) {

                        if (!supHandlesQueryObjectAddress(
                            SortedHandleList,
                            stlptr->hThread,
                            &objectAddress))
                        {
                            ErrorCount += 1;
                        }

                    }
                    else {
                        ErrorCount += 1;
                    }

                    NtClose(stlptr->hThread);
                }

                if (startAddress == 0)
                    startAddress = (ULONG_PTR)threadEntry->Thread->StartAddress;

                //
                // ETHREAD
                //
                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                szBuffer[0] = TEXT('0');
                szBuffer[1] = TEXT('x');
                u64tohex(objectAddress, &szBuffer[2]);

                lvitem.mask = LVIF_TEXT;
                lvitem.iSubItem++;
                lvitem.pszText = szBuffer;
                lvitem.iItem = ItemIndex;
                ListView_SetItem(PsDlgContext.ListView, &lvitem);

                //
                // StartAddress (either Win32StartAddress if possible or StartAddress from NtQSI)
                //
                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                szBuffer[0] = TEXT('0');
                szBuffer[1] = TEXT('x');

                u64tohex((ULONG_PTR)startAddress, &szBuffer[2]);

                lvitem.mask = LVIF_TEXT;
                lvitem.iSubItem++;
                lvitem.pszText = szBuffer;
                lvitem.iItem = ItemIndex;
                ListView_SetItem(PsDlgContext.ListView, &lvitem);

                //
                // Module (for system threads)
                //
                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                if ((startAddress > g_kdctx.SystemRangeStart) && (pModules)) {
                    if (!supFindModuleNameByAddress(
                        pModules,
                        (PVOID)startAddress,
                        szBuffer,
                        MAX_PATH))
                    {
                        _strcpy(szBuffer, T_Unknown);
                    }
                }
                lvitem.mask = LVIF_TEXT;
                lvitem.iSubItem++;
                lvitem.pszText = szBuffer;
                lvitem.iItem = ItemIndex;
                ListView_SetItem(PsDlgContext.ListView, &lvitem);
            }

            if (ErrorCount != 0) {
                _strcpy(szBuffer, TEXT("Some queries for threads information are failed"));
            }
            else {
                _strcpy(szBuffer, TEXT("All queries for threads information are succeeded"));
            }
            SendMessage(PsDlgContext.StatusBar, SB_SETTEXT, 2, (LPARAM)&szBuffer);

            ListView_SortItemsEx(
                PsDlgContext.ListView,
                PsListCompareFunc,
                PsDlgContext.lvColumnToSort);

        }
    }
    __finally {
        if (pHandles) supHeapFree(pHandles);
        if (pModules) supHeapFree(pModules);
        if (stl) supHeapFree(stl);

        supHandlesFreeList(SortedHandleList);

        if (ProcessList) supHeapFree(ProcessList);
        ReleaseMutex(g_PsListWait);
    }

    return 0;
}

/*
* CreateProcessListProc
*
* Purpose:
*
* Build and output process tree list.
*
*/
DWORD WINAPI CreateProcessListProc(
    PVOID Parameter
)
{
    BOOL bRefresh = (BOOL)(ULONG_PTR)Parameter;
    DWORD ServiceEnumType, dwWaitResult;
    ULONG NextEntryDelta = 0, NumberOfProcesses = 0, NumberOfThreads = 0, ReturnLength = 0, szl;

    HTREEITEM ViewRootHandle;

    ULONG_PTR ObjectAddress;

    HANDLE hProcess = NULL;
    PVOID InfoBuffer = NULL;
    PSYSTEM_HANDLE_INFORMATION_EX pHandles = NULL;
    PSYSTEM_HANDLE_INFORMATION_EX SortedHandleList = NULL;
    PSID OurSid = NULL;

    OBEX_PROCESS_LOOKUP_ENTRY *spl = NULL, *LookupEntry;

    SCMDB ServicesList;

    OBJECT_ATTRIBUTES obja = RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)NULL, 0);

    WCHAR szBuffer[100];

    union {
        PSYSTEM_PROCESSES_INFORMATION ProcessEntry;
        PBYTE ListRef;
    } List;



    __try {
        dwWaitResult = WaitForSingleObject(g_PsListWait, INFINITE);
        if (dwWaitResult == WAIT_OBJECT_0) {

            InterlockedIncrement((PLONG)&g_DialogRefresh);

            if (bRefresh) {
                HeapDestroy(g_PsListHeap);
                g_PsListHeap = HeapCreate(0, 0, 0);
                if (g_PsListHeap == NULL)
                    __leave;
            }

            TreeList_ClearTree(PsDlgContext.TreeList);
            ListView_DeleteAllItems(PsDlgContext.ListView);

            ServicesList.NumberOfEntries = 0;
            ServicesList.Entries = NULL;
            OurSid = supQueryProcessSid(NtCurrentProcess());

            if (g_NtBuildNumber >= 14393) {
                ServiceEnumType = SERVICE_TYPE_ALL;
            }
            else if (g_NtBuildNumber >= 10240) {
                ServiceEnumType = SERVICE_WIN32 |
                    SERVICE_ADAPTER |
                    SERVICE_DRIVER |
                    SERVICE_INTERACTIVE_PROCESS |
                    SERVICE_USER_SERVICE |
                    SERVICE_USERSERVICE_INSTANCE;
            }
            else {
                ServiceEnumType = SERVICE_DRIVER | SERVICE_WIN32;
            }
            if (!supCreateSCMSnapshot(ServiceEnumType, &ServicesList))
                __leave;

            InfoBuffer = supGetSystemInfo(SystemProcessInformation, &ReturnLength);
            if (InfoBuffer == NULL)
                __leave;

            List.ListRef = (PBYTE)InfoBuffer;

            //
            // Calculate process handle list size.
            //
            do {

                List.ListRef += NextEntryDelta;

                if (List.ProcessEntry->ThreadCount) {
                    NumberOfProcesses += 1;
                    NumberOfThreads += List.ProcessEntry->ThreadCount;
                }

                NextEntryDelta = List.ProcessEntry->NextEntryDelta;

            } while (NextEntryDelta);

            //
            // Build process handle list.
            //
            spl = (OBEX_PROCESS_LOOKUP_ENTRY*)supHeapAlloc(NumberOfProcesses * sizeof(OBEX_PROCESS_LOOKUP_ENTRY));
            if (spl == NULL)
                __leave;

            LookupEntry = spl;

            NextEntryDelta = 0;
            List.ListRef = (PBYTE)InfoBuffer;
            szl = 0;

            do {
                List.ListRef += NextEntryDelta;
                hProcess = NULL;

                if (List.ProcessEntry->ThreadCount) {
                    NtOpenProcess(
                        &hProcess,
                        PROCESS_QUERY_LIMITED_INFORMATION,
                        &obja,
                        &List.ProcessEntry->Threads[0].ClientId);
                }

                NextEntryDelta = List.ProcessEntry->NextEntryDelta;
                szl += NextEntryDelta;

                LookupEntry->hProcess = hProcess;
                LookupEntry->EntryPtr = List.ListRef;
                if (NextEntryDelta) {
                    LookupEntry->EntrySize = NextEntryDelta;
                }
                else {
                    LookupEntry->EntrySize = ReturnLength - szl;
                }
                LookupEntry = (OBEX_PROCESS_LOOKUP_ENTRY*)RtlOffsetToPointer(LookupEntry,
                    sizeof(OBEX_PROCESS_LOOKUP_ENTRY));

            } while (NextEntryDelta);

            LookupEntry = spl;

            pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation, NULL);
            if (pHandles) {
                SortedHandleList = supHandlesCreateFilteredAndSortedList(pHandles);
                supHeapFree(pHandles);
                pHandles = NULL;
            }

            //
            // Show processes/threads count
            //
            _strcpy(szBuffer, TEXT("Processes: "));
            ultostr(NumberOfProcesses, _strend(szBuffer));
            SendMessage(PsDlgContext.StatusBar, SB_SETTEXT, 0, (LPARAM)&szBuffer);

            _strcpy(szBuffer, TEXT("Threads: "));
            ultostr(NumberOfThreads, _strend(szBuffer));
            SendMessage(PsDlgContext.StatusBar, SB_SETTEXT, 1, (LPARAM)&szBuffer);

            //idle     
            AddProcessEntryTreeList(
                NULL,
                LookupEntry,
                0,
                &ServicesList,
                OurSid);

            NumberOfProcesses--;
            ViewRootHandle = NULL;

            while (NumberOfProcesses) {

                LookupEntry = (OBEX_PROCESS_LOOKUP_ENTRY*)RtlOffsetToPointer(
                    LookupEntry, sizeof(OBEX_PROCESS_LOOKUP_ENTRY));

                ViewRootHandle = FindParentItem(PsDlgContext.TreeList,
                    LookupEntry->ProcessInformation->InheritedFromUniqueProcessId);

                supHandlesQueryObjectAddress(SortedHandleList,
                    LookupEntry->hProcess,
                    &ObjectAddress);

                if (ViewRootHandle == NULL) {
                    ViewRootHandle = AddProcessEntryTreeList(NULL,
                        LookupEntry, ObjectAddress,
                        &ServicesList, OurSid);
                }
                else {
                    AddProcessEntryTreeList(ViewRootHandle,
                        LookupEntry, ObjectAddress,
                        &ServicesList, OurSid);
                }

                if (LookupEntry->hProcess)
                    NtClose(LookupEntry->hProcess);

                NumberOfProcesses--;
            }
        }
    }
    __finally {
        if (OurSid) supHeapFree(OurSid);
        supFreeSCMSnapshot(&ServicesList);
        if (pHandles) supHeapFree(pHandles);
        if (spl) supHeapFree(spl);
        if (InfoBuffer) supHeapFree(InfoBuffer);

        supHandlesFreeList(SortedHandleList);

        InterlockedDecrement((PLONG)&g_DialogRefresh);
        ReleaseMutex(g_PsListWait);
    }
    return 0;
}

/*
* CreateObjectList
*
* Purpose:
*
* Build and output process/threads list.
*
*/
VOID CreateObjectList(
    _In_ BOOL ListThreads,
    _In_opt_ PVOID ThreadParam
)
{
    DWORD ThreadId;
    HANDLE hThread;
    LPTHREAD_START_ROUTINE lpThreadRoutine;

    if (g_DialogQuit)
        return;

    if (ListThreads)
        lpThreadRoutine = (LPTHREAD_START_ROUTINE)CreateThreadListProc;
    else
        lpThreadRoutine = (LPTHREAD_START_ROUTINE)CreateProcessListProc;

    hThread = CreateThread(NULL,
        0,
        lpThreadRoutine,
        ThreadParam,
        0,
        &ThreadId);

    if (hThread) {
        CloseHandle(hThread);
    }
}

/*
* PsListHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for dialog listview.
*
*/
INT_PTR PsListHandleNotify(
    _In_ HWND hwndDlg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    UINT    hdrcode;
    LPNMHDR nhdr = (LPNMHDR)lParam;
    INT     nImageIndex;

    TVHITTESTINFO   hti;
    POINT pt;

    HWND TreeControl;

    PROP_UNNAMED_OBJECT_INFO *ObjectEntry;

    UNREFERENCED_PARAMETER(hwndDlg);

    if ((g_DialogRefresh) || (nhdr == NULL) || (g_DialogQuit))
        return 0;

    TreeControl = (HWND)TreeList_GetTreeControlWindow(PsDlgContext.TreeList);

    if (nhdr->hwndFrom == PsDlgContext.ListView) {

        switch (nhdr->code) {

        case NM_DBLCLK:
            ObjectEntry = PsListGetObjectEntry(FALSE, NULL);
            if (ObjectEntry) {
                PsListHandleObjectProp(FALSE, ObjectEntry);
            }

            return 1;
            break;

        case LVN_COLUMNCLICK:
            PsDlgContext.bInverseSort = !PsDlgContext.bInverseSort;
            PsDlgContext.lvColumnToSort = ((NMLISTVIEW *)lParam)->iSubItem;

            ListView_SortItemsEx(PsDlgContext.ListView, &PsListCompareFunc, (LPARAM)PsDlgContext.lvColumnToSort);

            nImageIndex = ImageList_GetImageCount(g_ListViewImages);
            if (PsDlgContext.bInverseSort)
                nImageIndex -= 2;
            else
                nImageIndex -= 1;

            supUpdateLvColumnHeaderImage(
                PsDlgContext.ListView,
                PsDlgContext.lvColumnCount,
                PsDlgContext.lvColumnToSort,
                nImageIndex);

            return 1;
            break;

        default:
            break;
        }

    }
    else if (nhdr->hwndFrom == TreeControl) {

        hdrcode = nhdr->code;

        switch (hdrcode) {

        case NM_DBLCLK:
            nhdr->code = NM_RETURN;
            return PostMessage(hwndDlg, WM_NOTIFY, wParam, lParam);
            break;

        case NM_RETURN:

            GetCursorPos(&pt);
            hti.pt = pt;
            ScreenToClient(TreeControl, &hti.pt);
            if (TreeView_HitTest(TreeControl, &hti) &&
                (hti.flags & (TVHT_ONITEM | TVHT_ONITEMRIGHT)))
            {
                ObjectEntry = PsListGetObjectEntry(TRUE, hti.hItem);
                if (ObjectEntry) {
                    PsListHandleObjectProp(TRUE, ObjectEntry);
                }
            }
            return 1;
            break;

        case TVN_SELCHANGED:
            ObjectEntry = PsListGetObjectEntry(TRUE, NULL);
            if (ObjectEntry) {
                CreateObjectList(TRUE, ObjectEntry);
            }
            return 1;
            break;

        default:
            break;
        }

    }

    return 0;
}

/*
* PsListHandleThreadRefresh
*
* Purpose:
*
* Refresh thread list handler.
*
*/
VOID PsListHandleThreadRefresh(
    VOID
)
{
    PROP_UNNAMED_OBJECT_INFO *ObjectEntry;

    ObjectEntry = PsListGetObjectEntry(TRUE, NULL);
    if (ObjectEntry) {
        CreateObjectList(TRUE, ObjectEntry);
    }
}

/*
* PsListDialogProc
*
* Purpose:
*
* Drivers Dialog window procedure.
*
*/
INT_PTR CALLBACK PsListDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    INT dy;
    RECT crc;
    INT mark;
    HWND TreeListControl;

    switch (uMsg) {

    case WM_CONTEXTMENU:

        RtlSecureZeroMemory(&crc, sizeof(crc));

        TreeListControl = TreeList_GetTreeControlWindow(PsDlgContext.TreeList);

        if ((HWND)wParam == TreeListControl) {
            GetCursorPos((LPPOINT)&crc);
            PsListHandlePopupMenu(hwndDlg, (LPPOINT)&crc, ID_OBJECT_COPY, ID_VIEW_REFRESH);
        }

        if ((HWND)wParam == PsDlgContext.ListView) {

            mark = ListView_GetSelectionMark(PsDlgContext.ListView);

            if (lParam == MAKELPARAM(-1, -1)) {
                ListView_GetItemRect(PsDlgContext.ListView, mark, &crc, TRUE);
                crc.top = crc.bottom;
                ClientToScreen(PsDlgContext.ListView, (LPPOINT)&crc);
            }
            else
                GetCursorPos((LPPOINT)&crc);

            PsListHandlePopupMenu(hwndDlg, (LPPOINT)&crc, ID_OBJECT_COPY + 1, ID_VIEW_REFRESH + 1);
        }

        break;

    case WM_NOTIFY:
        return PsListHandleNotify(hwndDlg, wParam, lParam);
        break;

    case WM_COMMAND:

        switch (LOWORD(wParam)) {

        case IDCANCEL:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;
        case ID_OBJECT_COPY:
        case ID_OBJECT_COPY + 1:
            if (LOWORD(wParam) == ID_OBJECT_COPY) {
                supCopyTreeListSubItemValue(PsDlgContext.TreeList, 0);
            }
            else {
                supCopyListViewSubItemValue(PsDlgContext.ListView, 3);
            }
            break;
        case ID_VIEW_REFRESH:
            CreateObjectList(FALSE, (PVOID)1);
            break;

        case ID_VIEW_REFRESH + 1:
            PsListHandleThreadRefresh();
            break;
        default:
            break;
        }
        break;

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            ((PMINMAXINFO)lParam)->ptMinTrackSize.x = 640;
            ((PMINMAXINFO)lParam)->ptMinTrackSize.y = 480;
        }
        break;

    case WM_SIZE:
        return PsListDialogResize();

    case WM_LBUTTONDOWN:
        SetCapture(hwndDlg);
        y_capture_pos = (int)(short)HIWORD(lParam);
        break;

    case WM_LBUTTONUP:
        ReleaseCapture();
        break;

    case WM_MOUSEMOVE:

        if (wParam & MK_LBUTTON) {
            dy = (int)(short)HIWORD(lParam) - y_capture_pos;
            if (dy != 0) {
                y_capture_pos = (int)(short)HIWORD(lParam);
                y_splitter_pos += dy;
                if (y_splitter_pos < Y_SPLITTER_MIN)
                {
                    y_splitter_pos = Y_SPLITTER_MIN;
                    y_capture_pos = Y_SPLITTER_MIN;
                }

                if (y_splitter_pos > y_splitter_max)
                {
                    y_splitter_pos = y_splitter_max;
                    y_capture_pos = y_splitter_max;
                }
                SendMessage(hwndDlg, WM_SIZE, 0, 0);
            }
        }

        break;

    case WM_CLOSE:
        InterlockedAdd((PLONG)&g_DialogQuit, 1);
        if (g_PsListWait) {
            CloseHandle(g_PsListWait);
            g_PsListWait = NULL;
        }

        DestroyWindow(PsDlgContext.TreeList);
        DestroyWindow(hwndDlg);
        g_WinObj.AuxDialogs[wobjPsListDlgId] = NULL;
        if (g_PsListHeap) {
            HeapDestroy(g_PsListHeap);
            g_PsListHeap = NULL;
        }
        return TRUE;
    }

    return DefDlgProc(hwndDlg, uMsg, wParam, lParam);
}

/*
* extrasCreatePsListDialog
*
* Purpose:
*
* Create and initialize Process List Dialog.
*
*/
VOID extrasCreatePsListDialog(
    _In_ HWND hwndParent
)
{
    LONG_PTR    wndStyles;
    HDITEM      hdritem;
    LVCOLUMN    col;
    WNDCLASSEX  wincls;

    INT SbParts[] = { 160, 320, -1 };

    //allow only one dialog
    if (g_WinObj.AuxDialogs[wobjPsListDlgId]) {
        if (IsIconic(g_WinObj.AuxDialogs[wobjPsListDlgId]))
            ShowWindow(g_WinObj.AuxDialogs[wobjPsListDlgId], SW_RESTORE);
        else
            SetActiveWindow(g_WinObj.AuxDialogs[wobjPsListDlgId]);
        return;
    }

    RtlSecureZeroMemory(&wincls, sizeof(wincls));
    wincls.cbSize = sizeof(WNDCLASSEX);
    wincls.lpfnWndProc = &PsListDialogProc;
    wincls.cbWndExtra = DLGWINDOWEXTRA;
    wincls.hInstance = g_WinObj.hInstance;
    wincls.hCursor = (HCURSOR)LoadImage(NULL,
        MAKEINTRESOURCE(OCR_SIZENS), IMAGE_CURSOR, 0, 0, LR_SHARED);
    wincls.hIcon = (HICON)LoadImage(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDI_ICON_MAIN), IMAGE_ICON, 0, 0, LR_SHARED);
    wincls.lpszClassName = PSLISTCLASSNAME;

    RegisterClassEx(&wincls);

    RtlSecureZeroMemory(&PsDlgContext, sizeof(PsDlgContext));
    PsDlgContext.hwndDlg = CreateDialogParam(
        g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_PSLIST),
        hwndParent,
        NULL,
        0);

    if (PsDlgContext.hwndDlg == NULL) {
        return;
    }

    if (g_kdctx.IsFullAdmin == FALSE) {
        SetWindowText(PsDlgContext.hwndDlg, TEXT("Processes (Non elevated mode, not all information can be queried)"));
    }

    g_WinObj.AuxDialogs[wobjPsListDlgId] = PsDlgContext.hwndDlg;

    PsDlgContext.ListView = GetDlgItem(PsDlgContext.hwndDlg, IDC_PSLIST_LISTVIEW);
    PsDlgContext.StatusBar = GetDlgItem(PsDlgContext.hwndDlg, IDC_PSLIST_STATUSBAR);
    PsDlgContext.TreeList = GetDlgItem(PsDlgContext.hwndDlg, IDC_PSLIST_TREELIST);

    SendMessage(PsDlgContext.StatusBar, SB_SETPARTS, 3, (LPARAM)&SbParts);

    if (PsDlgContext.ListView) {
        ListView_SetImageList(PsDlgContext.ListView, g_ListViewImages, LVSIL_SMALL);
        ListView_SetExtendedListViewStyle(PsDlgContext.ListView,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_LABELTIP | LVS_EX_DOUBLEBUFFER);
        SetWindowTheme(PsDlgContext.ListView, TEXT("Explorer"), NULL);

        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
        col.iSubItem++;
        col.pszText = TEXT("TID");
        col.fmt = LVCFMT_CENTER | LVCFMT_BITMAP_ON_RIGHT;
        col.iImage = ImageList_GetImageCount(g_ListViewImages) - 1;
        col.cx = 60;
        ListView_InsertColumn(PsDlgContext.ListView, col.iSubItem, &col);

        col.iImage = I_IMAGENONE;
        col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;

        col.iSubItem++;
        col.pszText = TEXT("Priority");
        col.iOrder++;
        col.cx = 100;
        ListView_InsertColumn(PsDlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("State");
        col.iOrder++;
        col.cx = 150;
        ListView_InsertColumn(PsDlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Object");
        col.iOrder++;
        col.cx = 150;
        ListView_InsertColumn(PsDlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("StartAddress");
        col.iOrder++;
        col.cx = 140;
        ListView_InsertColumn(PsDlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("Module (System threads)");
        col.iOrder++;
        col.cx = 200;
        ListView_InsertColumn(PsDlgContext.ListView, col.iSubItem, &col);

        PsDlgContext.lvColumnCount = col.iSubItem;
    }

    if (PsDlgContext.TreeList) {
        RtlSecureZeroMemory(&hdritem, sizeof(hdritem));
        hdritem.mask = HDI_FORMAT | HDI_TEXT | HDI_WIDTH;
        hdritem.fmt = HDF_LEFT | HDF_BITMAP_ON_RIGHT | HDF_STRING;
        hdritem.cxy = 300;
        hdritem.pszText = TEXT("Process");
        TreeList_InsertHeaderItem(PsDlgContext.TreeList, 0, &hdritem);

        hdritem.cxy = 130;
        hdritem.pszText = TEXT("Object");
        TreeList_InsertHeaderItem(PsDlgContext.TreeList, 1, &hdritem);

        hdritem.cxy = 180;
        hdritem.pszText = TEXT("User");
        TreeList_InsertHeaderItem(PsDlgContext.TreeList, 2, &hdritem);

        wndStyles = GetWindowLongPtr(PsDlgContext.TreeList, GWL_STYLE);
        SetWindowLongPtr(PsDlgContext.TreeList, GWL_STYLE, wndStyles | TLSTYLE_LINKLINES);
    }

    PsListDialogResize();

    g_DialogQuit = 0;
    g_DialogRefresh = 0;
    g_PsListWait = CreateMutex(NULL, FALSE, NULL);
    g_PsListHeap = HeapCreate(0, 0, 0);
    if (g_PsListHeap) {
        CreateObjectList(FALSE, NULL);
    }
}
