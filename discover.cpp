#define UNICODE

#include <stdio.h>
#include <string.h>
#include <initguid.h>
#include <winsock2.h>
#include <ws2bth.h>
#include <stdint.h>
#include <time.h>

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

char *get_device_name(PWSAQUERYSET query_set)
{
    int device_name_len = wcslen(query_set->lpszServiceInstanceName) + 1;
    char *device = new char[device_name_len];
    wcstombs(device, query_set->lpszServiceInstanceName, device_name_len);
    return device;
}

void baswap(BTH_ADDR *dst, const BTH_ADDR *src)
{
    register unsigned char *d = (unsigned char *)dst;
    register const unsigned char *s = (const unsigned char *)src;
    register int i;
    for (i = 0; i < 6; i++)
        d[i] = s[5 - i];
}

void ba2str(const BTH_ADDR *ba, char *result)
{
    uint8_t b[6];
    baswap((BTH_ADDR *)b, ba);
    char data[17];

    int j = 0;
    char first = '0';
    for (int i = 0; i < 6; i++)
    {

        char hex_val[2];
        sprintf(hex_val, "%x", b[i]);
        if (i == 0)
        {
            first = hex_val[0];
        }
        data[j] = hex_val[0];
        j++;
        data[j] = hex_val[1];
        j++;
        if (i != 5)
        {
            data[j] = ':';
            j++;
        }
    }
    data[0] = first;
    memcpy(result, data, 17);
}

void discover_iterator(HANDLE lookup, PWSAQUERYSET query_set)
{
    ULONG flags = get_begin_flags(true);
    ULONG query_set_size = get_query_set_size();
    // Set the deadline to 5 sec
    time_t deadline = time(0) + 5;

    bool continue_lookup = true;
    BTH_ADDR *bluetooth_address;
    while (continue_lookup)
    {
        time_t now = time(0);

        if (now > deadline)
        {
            continue_lookup = false;
        }

        int next_result = WSALookupServiceNextW(lookup, flags, &query_set_size, query_set);
        if (next_result == NO_ERROR)
        {
            // Found a device
            int device_name_len = wcslen(query_set->lpszServiceInstanceName) + 1;
            char *device_name = new char[device_name_len];
            wcstombs(device_name, query_set->lpszServiceInstanceName, device_name_len);
            printf("Device: %s\n", device_name);

            LPCSADDR_INFO buffer = query_set->lpcsaBuffer;
            SOCKET_ADDRESS remote_address = buffer->RemoteAddr;
            PSOCKADDR_BTH sockaddr = (PSOCKADDR_BTH)remote_address.lpSockaddr;
            BTH_ADDR address = sockaddr->btAddr;
            char result_address[11] = {0};
            ba2str(&address, result_address);
            printf("\taddress: %s\n\n", result_address);
        }
        else
        {
            int last_error = WSAGetLastError();
            if (last_error == WSA_E_NO_MORE)
            {
                printf("No more devices");
                continue_lookup = false;
            }
            else if (last_error == WSAEFAULT)
            {
                HeapFree(GetProcessHeap(), 0, query_set);
                query_set = NULL;
                query_set = (PWSAQUERYSET)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, query_set_size);
                if (query_set == NULL)
                {
                    printf("[ERROR] Unable to allocate memory for WSAQERYSET\n");
                    continue_lookup = false;
                }
            }
            else
            {
                printf("[CRITICAL] WSALookupServiceNext() failed with error code %d\n", last_error);
                continue_lookup = false;
            }
        }
    }
}

void discover()
{
    ULONG query_set_size = get_query_set_size();
    ULONG flags = get_begin_flags(false);
    PWSAQUERYSET query_set = get_query_set();
    ZeroMemory(query_set, query_set_size);
    query_set->dwNameSpace = NS_BTH;
    query_set->dwSize = query_set_size;
    //analyze_query_set_memory_layout(query_set);

    HANDLE lookup = 0;
    int result = WSALookupServiceBeginW(query_set, flags, &lookup);

    discover_iterator(lookup, query_set);

    // End the lookup service
    WSALookupServiceEnd(lookup);
}

int _cdecl main(int argc, char *argv[])
{
    startup();
    discover();
}
