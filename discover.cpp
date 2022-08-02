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
    // analyze_query_set_memory_layout(query_set);

    HANDLE lookup = 0;
    int result = WSALookupServiceBeginW(query_set, flags, &lookup);

    discover_iterator(lookup, query_set);

    // End the lookup service
    WSALookupServiceEnd(lookup);
}

DEFINE_GUID(g_guidServiceClass, 0x49535343, 0xfe7d, 0x4ae5, 0x8f, 0xa9, 0x9f, 0xaf, 0xd2, 0x05, 0xe4, 0x55);
DEFINE_GUID(g_guidProviderID, 0x49535343, 0xfe7d, 0x4ae5, 0x8f, 0xa9, 0x9f, 0xaf, 0xd2, 0x05, 0xe4, 0x55);

void memory_layout_WSAQUERYSET()
{
    WSAQUERYSET qs1 = {0};
    qs1.dwNameSpace = NS_BTH;
    qs1.dwSize = get_query_set_size();

    // lpafpProtocols
    AFPROTOCOLS proto = {0};
    proto.iAddressFamily = 12222;
    proto.iProtocol = 12333123;
    //analyze_memory_layout("AFPROTOCOLS", (char *)&proto, sizeof(proto));

    qs1.lpafpProtocols = &proto;

    // lpszServiceInstanceName
    char sin = 'x';
    qs1.lpszServiceInstanceName = (LPWSTR)&sin;

    // lpServiceClassId
    qs1.lpServiceClassId = (LPGUID)&g_guidServiceClass;

    // lpVersion
    WSAVERSION version = {0};
    version.dwVersion = 1234123;
    version.ecHow = WSAECOMPARATOR::COMP_NOTLESS;
    //analyze_memory_layout("WSAVERSION", (char *)&version, sizeof(version));
    qs1.lpVersion = (LPWSAVERSION)&version;

    // lpszComment
    char comment = 'x';
    qs1.lpszComment = (LPWSTR)&comment;

    // lpNSProviderId
    qs1.lpNSProviderId = (LPGUID)&g_guidProviderID;

    // lpszContext
    char context = 'x';
    qs1.lpszContext = (LPWSTR)&context;

    // dwNumberOfProtocols
    qs1.dwNumberOfProtocols = 123412;

    // lpszQueryString
    char query_string = 'x';
    qs1.lpszQueryString = (LPWSTR)&query_string;

    // dwNumberOfCsAddrs
    qs1.dwNumberOfCsAddrs = 12234;

    // lpcsaBuffer
    CSADDR_INFO addr_info = {0};
    addr_info.iProtocol = 12;
    addr_info.iSocketType = 300;

    SOCKET_ADDRESS remote_sock_addr = {0};
    remote_sock_addr.iSockaddrLength = 10;
    sockaddr sockAddr = {};
    sockAddr.sa_family = 44;
    char sa_data[14] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23};
    memcpy(&sockAddr.sa_data, sa_data, sizeof(sockAddr.sa_data));
    //analyze_memory_layout("sockAddr", (char *)&sockAddr, sizeof(sockAddr));
    remote_sock_addr.lpSockaddr = (LPSOCKADDR)&sockAddr;
    //analyze_memory_layout("SOCKET_ADDRESS", (char *)&remote_sock_addr, sizeof(remote_sock_addr));

    SOCKET_ADDRESS local_sock_addr = {0};
    local_sock_addr.iSockaddrLength = 10;
    sockaddr sockAddr_local = {};
    sockAddr_local.sa_family = 44;
    char sa_data_local[14] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23};
    memcpy(&sockAddr_local.sa_data, sa_data_local, sizeof(sockAddr_local.sa_data));
    //analyze_memory_layout("sockAddr", (char *)&sockAddr_local, sizeof(sockAddr_local));
    local_sock_addr.lpSockaddr = (LPSOCKADDR)&sockAddr_local;
   // analyze_memory_layout("SOCKET_ADDRESS", (char *)&local_sock_addr, sizeof(local_sock_addr));

    // TODO
    addr_info.RemoteAddr = remote_sock_addr;
    addr_info.LocalAddr = local_sock_addr;
    // analyze_memory_layout("CSADDR_INFO", (char *)&addr_info, sizeof(addr_info));
    // analyze_memory_layout("CSADDR_INFO.RemoteAddr", (char *)&addr_info.RemoteAddr, sizeof(addr_info.RemoteAddr));
    // analyze_memory_layout("CSADDR_INFO.LocalAddr", (char *)&addr_info.LocalAddr, sizeof(addr_info.LocalAddr));
    qs1.lpcsaBuffer = (LPCSADDR_INFO)&addr_info;

    // dwOutputFlags
    qs1.dwOutputFlags = 123234;

    // lpBlob
    BLOB blob = {0};
    blob.cbSize = 10;
    BYTE blob_data = 'x';
    blob.pBlobData = (BYTE *)&blob_data;

    analyze_memory_layout("BLOB", (char *)&blob, sizeof(blob));
    qs1.lpBlob = (LPBLOB)&blob;

    // analyze_memory_layout("Query set main", (char *)&qs1, sizeof(qs1));

    // analyze_memory_layout("Query set -> dwSize", (char *)&qs1.dwSize, sizeof(qs1.dwSize));
    // analyze_memory_layout("Query set -> lpszServiceInstanceName", (char *)&qs1.lpszServiceInstanceName, sizeof(qs1.lpszServiceInstanceName));
    // analyze_memory_layout("Query set -> lpServiceClassId", (char *)&qs1.lpServiceClassId, sizeof(qs1.lpServiceClassId));
    // analyze_memory_layout("Query set -> lpVersion", (char *)&qs1.lpVersion, sizeof(qs1.lpVersion));
    // analyze_memory_layout("Query set -> lpszComment", (char *)&qs1.lpszComment, sizeof(qs1.lpszComment));
    // analyze_memory_layout("Query set -> dwNameSpace", (char *)&qs1.dwNameSpace, sizeof(qs1.dwNameSpace));
    // analyze_memory_layout("Query set -> lpNSProviderId", (char *)&qs1.lpNSProviderId, sizeof(qs1.lpNSProviderId));
    // analyze_memory_layout("Query set -> lpszContext", (char *)&qs1.lpszContext, sizeof(qs1.lpszContext));
    // analyze_memory_layout("Query set -> dwNumberOfProtocols", (char *)&qs1.dwNumberOfProtocols, sizeof(qs1.dwNumberOfProtocols));
    // analyze_memory_layout("Query set -> lpafpProtocols", (char *)&qs1.lpafpProtocols, sizeof(qs1.lpafpProtocols));
    // analyze_memory_layout("Query set -> lpszQueryString", (char *)&qs1.lpszQueryString, sizeof(qs1.lpszQueryString));
    // analyze_memory_layout("Query set -> dwNumberOfCsAddrs", (char *)&qs1.dwNumberOfCsAddrs, sizeof(qs1.dwNumberOfCsAddrs));
    // analyze_memory_layout("Query set -> lpcsaBuffer", (char *)&qs1.lpcsaBuffer, sizeof(qs1.lpcsaBuffer));
    // analyze_memory_layout("Query set -> dwOutputFlags", (char *)&qs1.dwOutputFlags, sizeof(qs1.dwOutputFlags));
    // analyze_memory_layout("Query set -> lpBlob", (char *)&qs1.lpBlob, sizeof(qs1.lpBlob));
}

int _cdecl main(int argc, char *argv[])
{
    startup();
    discover();
    //memory_layout_WSAQUERYSET();
}
