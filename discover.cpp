#define UNICODE

#include <stdio.h>
#include <string.h>
#include <initguid.h>
#include <winsock2.h>
#include <ws2bth.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

void startup()
{
    WSADATA wsa_data = {0};
    ULONG startup_return = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (startup_return != 0)
    {
        printf("[FATAL] Unable to initialize Winsock version 2.2 > %d\n", startup_return);
        exit(1);
    }
}

ULONG get_query_set_size()
{
    return sizeof(WSAQUERYSET);
}

PWSAQUERYSET get_query_set()
{
    HANDLE process_heap = GetProcessHeap();
    ULONG query_set_size = get_query_set_size();
    LPVOID query_set_alloc = HeapAlloc(process_heap, HEAP_ZERO_MEMORY, query_set_size);

    PWSAQUERYSET query_set = (PWSAQUERYSET)query_set_alloc;
    if (query_set == NULL)
    {
        printf("[ERROR] Unable to allocate memory for WSAQUERYSET\n");
        exit(1);
    }

    return query_set;
}

ULONG get_begin_flags(IN bool flush_cache)
{
    // WSALookupService is used for both service search and device inquiry
    // LUP_CONTAINERS is the flag which signals that we're doing a device inquiry.
    ULONG flags = LUP_CONTAINERS;

    // Friendly device name (if available) will be returned in lpszServiceInstanceName
    flags |= LUP_RETURN_NAME;

    // BTH_ADDR will be returned in lpcsaBuffer member of WSAQUERYSET
    flags |= LUP_RETURN_ADDR;

    if (flush_cache)
    {
        // Flush the device cache for all inquiries, except for the first inquiry.
        // By setting LUP_FLUSHCACHE flag, we're asking the lookup service to do
        // a fresh lookup instead of pulling the information from device cache.
        flags |= LUP_FLUSHCACHE;
    }

    return flags;
}

void analyze_memory_layout(const char *name, char *field, unsigned long long size)
{
    printf("--start-- %s\n", name);
    for (int i = 0; i < size; i++)
    {
        printf("%02x ", (unsigned int)(field)[i]);
    }
    printf("\n--end-- %s\n", name);
}

void analyze_query_set_memory_layout(PWSAQUERYSET query_set)
{
    analyze_memory_layout("Query set", (char *)&query_set, sizeof(query_set));
    // TODO somehow read the value of query_set allocation
    // HANDLE hProcess = GetCurrentProcess();
    // ReadProcessMemory(hProcess, (LPCVOID)query_set, pBuf, m_ModuleBaseSize, &nBytes);

    analyze_memory_layout("Query set -> dwSize", (char *)&query_set->dwSize, sizeof(query_set->dwSize));
    analyze_memory_layout("Query set -> lpszServiceInstanceName", (char *)&query_set->lpszServiceInstanceName, sizeof(query_set->lpszServiceInstanceName));
    analyze_memory_layout("Query set -> lpServiceClassId", (char *)&query_set->lpServiceClassId, sizeof(query_set->lpServiceClassId));
    analyze_memory_layout("Query set -> lpVersion", (char *)&query_set->lpVersion, sizeof(query_set->lpVersion));
    analyze_memory_layout("Query set -> lpszComment", (char *)&query_set->lpszComment, sizeof(query_set->lpszComment));
    analyze_memory_layout("Query set -> dwNameSpace", (char *)&query_set->dwNameSpace, sizeof(query_set->dwNameSpace));
    analyze_memory_layout("Query set -> lpNSProviderId", (char *)&query_set->lpNSProviderId, sizeof(query_set->lpNSProviderId));
    analyze_memory_layout("Query set -> lpszContext", (char *)&query_set->lpszContext, sizeof(query_set->lpszContext));
    analyze_memory_layout("Query set -> dwNumberOfProtocols", (char *)&query_set->dwNumberOfProtocols, sizeof(query_set->dwNumberOfProtocols));
    analyze_memory_layout("Query set -> lpafpProtocols", (char *)&query_set->lpafpProtocols, sizeof(query_set->lpafpProtocols));
    analyze_memory_layout("Query set -> lpszQueryString", (char *)&query_set->lpszQueryString, sizeof(query_set->lpszQueryString));
    analyze_memory_layout("Query set -> dwNumberOfCsAddrs", (char *)&query_set->dwNumberOfCsAddrs, sizeof(query_set->dwNumberOfCsAddrs));
    analyze_memory_layout("Query set -> lpcsaBuffer", (char *)&query_set->lpcsaBuffer, sizeof(query_set->lpcsaBuffer));
    analyze_memory_layout("Query set -> dwOutputFlags", (char *)&query_set->dwOutputFlags, sizeof(query_set->dwOutputFlags));
    analyze_memory_layout("Query set -> lpBlob", (char *)&query_set->lpBlob, sizeof(query_set->lpBlob));
}

void lookup_service_next_error(PWSAQUERYSET *query_set)
{
    int last_error = WSAGetLastError();
    if (last_error == WSA_E_NO_MORE)
    {
        printf("[INFO] No more devices.\n");
    }
    else if (last_error == WSAEFAULT)
    {
        HeapFree(GetProcessHeap(), 0, query_set);
        query_set = NULL;
        printf("[ERROR] The system detected an invalid pointer address in attempting to use a pointer argument of a call.\n");
    }
    else
    {
        printf("[CRITICAL] WSALookupServiceNext() failed with error code %d\n", last_error);
    }
}

char *get_device_name(PWSAQUERYSET query_set)
{
    int device_name_len = wcslen(query_set->lpszServiceInstanceName) + 1;
    char *device = new char[device_name_len];
    wcstombs(device, query_set->lpszServiceInstanceName, device_name_len);
    return device;
}

void discover_iterator(HANDLE lookup, PWSAQUERYSET query_set)
{
    ULONG flags = get_begin_flags(false);
    bool continue_lookup = true;
    int counter = 0;

    while (continue_lookup)
    {
        printf("Iteration: %d", counter);
        counter++;

        ULONG query_set_size = get_query_set_size();
        int next_result = WSALookupServiceNext(lookup, flags, &query_set_size, query_set);

        if (next_result == NO_ERROR)
        {
            printf("lofasz");
            char *device_name = get_device_name(query_set);
            if (strstr(device_name, "D135"))
            {
                BTH_ADDR *bluetooth_address;
                CopyMemory(
                    bluetooth_address,
                    &((PSOCKADDR_BTH)query_set->lpcsaBuffer->RemoteAddr.lpSockaddr)->btAddr,
                    sizeof(*bluetooth_address));
                printf("[INFO] Address found: %X\n", *bluetooth_address);
                continue_lookup = false;
            }
        }
        else
        {
            lookup_service_next_error(&query_set);
            continue_lookup = false;
        }
    }
}

void discover()
{
    ULONG flags = get_begin_flags(false);
    PWSAQUERYSET query_set = get_query_set();
    query_set->dwNameSpace = NS_BTH;
    query_set->dwSize = get_query_set_size();
    analyze_query_set_memory_layout(query_set);

    HANDLE lookup = 0;
    int begin_result = WSALookupServiceBegin(query_set, flags, &lookup);

    discover_iterator(lookup, query_set);

    WSALookupServiceEnd(lookup);

    // WSAQUERYSET qs; TODO
    // qs.dwNameSpace = NS_BTH;
    // qs.dwSize = get_query_set_size();
    // analyze_query_set_memory_layout(qs);
}

int _cdecl main(int argc, char *argv[])
{
    startup();
    discover();
}
