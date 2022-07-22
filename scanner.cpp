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

// g++ -o scanner.exe scanner.cpp -lws2_32

// {49535343-FE7D-4AE5-8FA9-9FAFD205E455}
DEFINE_GUID(g_guidServiceClass, 0x49535343, 0xfe7d, 0x4ae5, 0x8f, 0xa9, 0x9f, 0xaf, 0xd2, 0x05, 0xe4, 0x55);

#define DEFAULT_BUFLEN 512
#define BTADDR_LEN 17 // Device address length, 48-bit hexadecimal address (like MAC address)
#define MAX_INQUIRY_RETRY 3
#define DELAY_NEXT_INQUIRY 15

char device_remote_name[BTH_MAX_NAME_SIZE + 1] = {0};
char device_remote_address[BTADDR_LEN + 1] = {0};
int max_connection_cycles = 1;
int output_level = 0;

ULONG parse_command_line(IN int argc, IN char *argv[])
{
    for (int i = 1; i < argc; i++)
    {
        char *arg_token = argv[i];

        if (*arg_token == '-' || *arg_token == '/')
        {
            char flag;
            arg_token++; // NOTE: Skip the - or /
            flag = *arg_token;
            arg_token++; // NOTE: Go over the flag to the data

            int token_length = lstrlen((LPCTSTR)arg_token);
            switch (flag)
            {
            case 'n':
                if ((0 < token_length) && (BTH_MAX_NAME_SIZE >= token_length))
                {
                    lstrcpy((LPTSTR)device_remote_name, (LPTSTR)arg_token);
                }
                else
                {
                    printf("[ERROR] Unable to parse -n<RemoteName>, length error (min 1 char, max %d chars)\n", BTH_MAX_NAME_SIZE);
                    return 2;
                }
                break;
            case 'a':
                if (BTADDR_LEN == token_length)
                {
                    lstrcpy((LPTSTR)device_remote_address, (LPTSTR)arg_token);
                }
                else
                {
                    printf("[ERROR] Unable to parse -a<RemoteAddress>, Remote bluetooth radio address string length expected %d | Found: %d)\n", BTADDR_LEN, token_length);
                    return 2;
                }
                break;
            case 'c':
                if (0 < arg_token)
                {
                    sscanf(arg_token, "%d", &max_connection_cycles);
                    if (0 > max_connection_cycles)
                    {
                        printf("[ERROR] Must provide +ve or 0 value with -c option\n");
                        return 2;
                    }
                }
                else
                {
                    printf("[ERROR] Must provide a value with -c option\n");
                    return 2;
                }
            case 'o':
                if (0 < arg_token)
                {
                    sscanf(arg_token, "%d", &output_level);
                    if (0 > output_level)
                    {
                        printf("[ERROR] Must provide a +ve or 0 value with -o option\n");
                        return 2;
                    }
                }
                else
                {
                    printf("[ERROR] Must provide a value with -o option\n");
                    return 2;
                }
            case '?':
            case 'h':
            case 'H':
            default:
                return 1;
            }
        }
        else
        {
            return 1;
        }
    }

    return 0;
}

void cli_help(void)
{
    printf(
        "\n  Bluetooth example application for demonstrating connection and data transfer."
        "\n"
        "\n"
        "\n  BTHCxnDemo.exe  [-n<RemoteName> | -a<RemoteAddress>] "
        "\n                  [-c<ConnectionCycles>] [-o<Output Level>]"
        "\n"
        "\n"
        "\n  Switches applicable for Client mode:"
        "\n    -n<RemoteName>        Specifies name of remote BlueTooth-Device."
        "\n"
        "\n    -a<RemoteAddress>     Specifies address of remote BlueTooth-Device."
        "\n                          The address is in form XX:XX:XX:XX:XX:XX"
        "\n                          where XX is a hexidecimal byte"
        "\n"
        "\n                          One of the above two switches is required for client."
        "\n"
        "\n"
        "\n  Switches applicable for both Client and Server mode:"
        "\n    -c<ConnectionCycles>  Specifies number of connection cycles."
        "\n                          Default value for this parameter is 1.  Specify 0 to "
        "\n                          run infinite number of connection cycles."
        "\n"
        "\n    -o<OutputLevel>       Specifies level of information reporting in cmd window."
        "\n                          Default value for this parameter is 0 (minimal info)."
        "\n                          Possible values: 1 (more info), 2 (all info)."
        "\n"
        "\n"
        "\n  Command Line Examples:"
        "\n    \"BTHCxnDemo.exe -c0\""
        "\n    Runs the BTHCxnDemo server for infinite connection cycles."
        "\n    The application reports minimal information onto the cmd window."
        "\n"
        "\n    \"BTHCxnDemo.exe -nServerDevice -c50 -o2\""
        "\n    Runs the BTHCxnDemo client connecting to remote device (having name "
        "\n    \"ServerDevice\" for 50 connection cycles."
        "\n    The application reports minimal information onto the cmd window."
        "\n");
}

ULONG name_to_address(IN const char *remote_name, OUT BTH_ADDR *bluetooth_address)
{
    ULONG pqs_size = sizeof(WSAQUERYSET);

    if ((remote_name == NULL) || (bluetooth_address == NULL))
    {
        printf("[ERROR] Missing arguments in name_to_address\n");
        return 1;
    }

    PWSAQUERYSET query_set = (PWSAQUERYSET)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pqs_size);
    if (query_set == NULL)
    {
        printf("[ERROR] Unable to allocate memory for WSAQUERYSET\n");
    }

    // Search for the device with the correct name
    int retries = 0;
    bool device_found = false;
    for (retries = 0; !device_found && (retries < MAX_INQUIRY_RETRY); retries++)
    {
        // WSALookupService is used for both service search and device inquiry
        // LUP_CONTAINERS is the flag which signals that we're doing a device inquiry.
        ULONG flags = LUP_CONTAINERS;

        // Friendly device name (if available) will be returned in lpszServiceInstanceName
        flags |= LUP_RETURN_NAME;

        // BTH_ADDR will be returned in lpcsaBuffer member of WSAQUERYSET
        flags |= LUP_RETURN_ADDR;

        if (retries == 0)
        {
            printf("[INFO] Inquiring device from cache...\n");
        }
        else
        {
            // Flush the device cache for all inquiries, except for the first inquiry.
            // By setting LUP_FLUSHCACHE flag, we're asking the lookup service to do
            // a fresh lookup instead of pulling the information from device cache.
            flags |= LUP_FLUSHCACHE;

            // Pause for some time before all the inquiries after the first inquiry
            printf("[INFO] Unable to find device.  Waiting for %d seconds before re-inquiry...\n", DELAY_NEXT_INQUIRY);
            Sleep(DELAY_NEXT_INQUIRY * 1000);
            printf("[INFO] Inquiring device ...\n");
        }

        // Start the lookup service
        ZeroMemory(query_set, pqs_size);
        query_set->dwNameSpace = NS_BTH;
        query_set->dwSize = pqs_size;
        HANDLE lookup = 0;
        int result = WSALookupServiceBegin(query_set, flags, &lookup);

        bool continue_lookup = false;
        if ((NO_ERROR == result) && (lookup != NULL))
        {
            continue_lookup = true;
        }
        else if (retries > 0)
        {
            printf("[CRITICAL] WSALookupServiceBegin() failed with error code %d, WSALastError = %d\n", result, WSAGetLastError());
            if (NULL != query_set)
            {
                HeapFree(GetProcessHeap(), 0, query_set);
                query_set = NULL;
            }
            return 1;
        }

        while (continue_lookup)
        {
            int next_result = WSALookupServiceNext(lookup, flags, &pqs_size, query_set);
            if (next_result == NO_ERROR)
            {
                // Found a device
                int device_name_len = wcslen(query_set->lpszServiceInstanceName) + 1;
                printf("Device name length: %d", device_name_len);
                char *device = new char[device_name_len];
                wcstombs(device, query_set->lpszServiceInstanceName, device_name_len);
                // wsprintfA(device, "%S", query_set->lpszServiceInstanceName);
                printf("Device: %s\n", device);
                if (strstr(device, "D135"))
                {
                    CopyMemory(
                        bluetooth_address,
                        &((PSOCKADDR_BTH)query_set->lpcsaBuffer->RemoteAddr.lpSockaddr)->btAddr,
                        sizeof(*bluetooth_address));
                    printf("[INFO] Address found: %X\n", *bluetooth_address);
                    device_found = true;
                    continue_lookup = false;
                }
            }
            else
            {
                int last_error = WSAGetLastError();
                if (last_error == WSA_E_NO_MORE)
                {
                    continue_lookup = false;
                }
                else if (last_error == WSAEFAULT)
                {
                    HeapFree(GetProcessHeap(), 0, query_set);
                    query_set = NULL;
                    query_set = (PWSAQUERYSET)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pqs_size);
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

        // End the lookup service
        WSALookupServiceEnd(lookup);
    }

    if (NULL != query_set)
    {
        HeapFree(GetProcessHeap(), 0, query_set);
        query_set = NULL;
    }
    if (device_found)
    {
        return 0;
    }
    return 1;
}

void recv_internal(SOCKET socket_descriptor)
{
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;
    int recv_result = recv(socket_descriptor, recvbuf, recvbuflen, 0);
    if (recv_result > 0)
        printf("[RECV] Bytes received: %d\n", recv_result);
    else if (recv_result == 0)
        printf("[RECV] Connection closed\n");
    else
        printf("[RECV] failed: %d\n", WSAGetLastError());

    printf("[RECV] ");
    for (int i = 0; i < recv_result; i++)
    {
        printf("%d ", recvbuf[i]);
    }
    printf("\n");
}

ULONG client_mode(BTH_ADDR address, int max_cycles)
{
    SOCKADDR_BTH sockaddr_bth;
    sockaddr_bth.addressFamily = AF_BTH;
    sockaddr_bth.btAddr = (BTH_ADDR)address;
    // sockaddr_bth.serviceClassId = g_guidServiceClass;
    sockaddr_bth.port = 6;

    ULONG return_code = 0;
    for (int count = 0; (return_code == 0) && (count < max_cycles || max_cycles == 0); count++)
    {
        // Open a socket descriptor
        SOCKET socket_descriptor = socket(AF_BTH, SOCK_STREAM, BTHPROTO_RFCOMM);
        if (socket_descriptor == INVALID_SOCKET)
        {
            printf("[CRITICAL] socket() call failed. WSAGetLastError = [%d]\n", WSAGetLastError());
            return 1;
        }

        printf("Salalala\n");
        for (int i = 0; i < sizeof(sockaddr_bth); i++)
        {
            printf("%02x ", (unsigned int)((char *)&sockaddr_bth)[i]);
        }
        printf("\nSalalala\n");
        printf("[INFO] socket() call succeeded. Socket = [0x%X]\n", socket_descriptor);
        printf("[INFO] connect() attempt with Remote BTHAddr = [0x%X]\n", address);
        printf("Size of SOCKADDR_BTH: %d\n", sizeof(SOCKADDR_BTH));
        printf("Size of GUID: %d\n", sizeof(GUID));
        printf("Size of BTH_ADDR: %d\n", sizeof(BTH_ADDR));
        printf("Size of ULONG: %d\n", sizeof(ULONG));
        printf("Size of USHORT: %d\n", sizeof(USHORT));

        printf("[INFO] connecting...");
        int conn = connect(socket_descriptor, (struct sockaddr *)&sockaddr_bth, sizeof(SOCKADDR_BTH));
        if (conn == SOCKET_ERROR)
        {
            printf("[CRITICAL] connect() call failed. WSAGetLastError=[%d]\n", WSAGetLastError());
            if (socket_descriptor != INVALID_SOCKET)
            {
                closesocket(socket_descriptor);
                socket_descriptor = INVALID_SOCKET;
            }
            return 1;
        }
        printf("[INFO] connect() call succeeded\n");
        printf("Send packet\n");
        char b[] = {2, 1, 0, 1, 0, 1, 0, 0, 3, 3};
        int err = send(socket_descriptor, b, 10, 0);
        if (err == SOCKET_ERROR)
        {
            printf("[CRITICAL] send() call failed w/socket = [0x%X], szData = [%d], dataLen = [%d]. WSAGetLastError=[%d]\n", socket_descriptor, 1, 10, WSAGetLastError());
        }
        printf("Hello\n");
        Sleep(0.70);

        recv_internal(socket_descriptor);

        char b11[] = {2, 1, 0, 0, 0, 1, 0, 1, 6, 5, 3};
        err = send(socket_descriptor, b11, 11, 0);
        if (err == SOCKET_ERROR)
        {
            printf("[CRITICAL] send() call failed w/socket = [0x%X], szData = [%d], dataLen = [%d]. WSAGetLastError=[%d]\n", socket_descriptor, 3, 11, WSAGetLastError());
        }
        printf("ACK\n");
        Sleep(0.70);

        char b1[] = {2, 1, 3, -24, 0, 1, 0, 2, -128, 0, 107, 3};
        err = send(socket_descriptor, b1, 12, 0);
        if (err == SOCKET_ERROR)
        {
            printf("[CRITICAL] send() call failed w/socket = [0x%X], szData = [%d], dataLen = [%d]. WSAGetLastError=[%d]\n", socket_descriptor, 2, 12, WSAGetLastError());
        }
        printf("Connect\n");
        Sleep(0.70);

        recv_internal(socket_descriptor);

        char b2[] = {2, 1, 0, 0, 0, 1, 0, 1, 6, 5, 3};
        err = send(socket_descriptor, b2, 11, 0);
        if (err == SOCKET_ERROR)
        {
            printf("[CRITICAL] send() call failed w/socket = [0x%X], szData = [%d], dataLen = [%d]. WSAGetLastError=[%d]\n", socket_descriptor, 3, 11, WSAGetLastError());
        }
        printf("ACK\n");
        Sleep(0.70);

        char b3[] = {2, 1, 3, -23, 0, 1, 0, 37, -128, 64, 1, 0, 32, -97, 2, 6, 0, 0, 0, 16, 0, 0, -100, 1, 0, 95, 42, 2, 1, 1, 95, 54, 1, 0, -102, 3, 34, 6, 2, -97, 33, 3, 16, 0, 87, 96, 3};
        err = send(socket_descriptor, b3, 37, 0);
        if (err == SOCKET_ERROR)
        {
            printf("[CRITICAL] send() call failed w/socket = [0x%X], szData = [%d], dataLen = [%d]. WSAGetLastError=[%d]\n", socket_descriptor, 4, 37, WSAGetLastError());
        }
        printf("Set data\n");
        Sleep(2);

        recv_internal(socket_descriptor);

        char b4[] = {2, 1, 0, 0, 0, 1, 0, 1, 6, 5, 3};
        err = send(socket_descriptor, b4, 11, 0);
        if (err == SOCKET_ERROR)
        {
            printf("[CRITICAL] send() call failed w/socket = [0x%X], szData = [%d], dataLen = [%d]. WSAGetLastError=[%d]\n", socket_descriptor, 5, 11, WSAGetLastError());
        }
        printf("ACK\n");
        Sleep(0.70);

        char b5[] = {2, 1, 3, -22, 0, 1, 0, 2, -128, 48, 89, 3};
        err = send(socket_descriptor, b5, 12, 0);
        if (err == SOCKET_ERROR)
        {
            printf("[CRITICAL] send() call failed w/socket = [0x%X], szData = [%d], dataLen = [%d]. WSAGetLastError=[%d]\n", socket_descriptor, 6, 12, WSAGetLastError());
        }
        printf("Start transaction\n");
        Sleep(0.70);
        printf("Send packet succeed\n");

        recv_internal(socket_descriptor);

        // TODO sending some data
    }
    return 0;
}

// 2022-06-02T10:00:03+02:00 [[34mINFO[0m]  Dashboard server listening on :9032
// 2022-06-02T10:00:03+02:00 [[34mINFO[0m]  Server listening on :9031
// 2022-06-02T10:00:49+02:00 [[34mINFO[0m]  connecting to device...
// 2022-06-02T10:00:49+02:00 [[37mDEBUG[0m]  unix socket returned a file descriptor:  9
// 2022-06-02T10:00:56+02:00 [[37mDEBUG[0m]  unix socket linked with an RFCOMM
// 2022-06-02T10:00:56+02:00 [[34mINFO[0m]  connected to device
// 2022-06-02T10:00:56+02:00 [[37mDEBUG[0m]  >>>>>>>>>>>> protoComm.Write: [2 1 0 1 0 1 0 0 3 3]
// 2022-06-02T10:00:57+02:00 [[37mDEBUG[0m]  >>>>>>>>>>>> protoComm.Read: [2 1 0 1 0 1 0 8 0 0 19 36 0 0 3 212 235 3]
// 2022-06-02T10:00:57+02:00 [[34mINFO[0m]  [0 0 19 36 0 0 3 212]
// 2022-06-02T10:00:57+02:00 [[37mDEBUG[0m]  PackSize: 4900, FrameSize: 980
// 2022-06-02T10:00:57+02:00 [[37mDEBUG[0m]  >>>>>>>>>>>> protoComm.Write: [2 1 3 232 0 1 0 2 128 0 107 3]
// 2022-06-02T10:00:57+02:00 [[37mDEBUG[0m]  >>>>>>>>>>>> protoComm.Read: [2 1 0 0 0 1 0 1 6 5 3 2 1 3 232 0 1 0 70 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 47 3]
// 2022-06-02T10:00:57+02:00 [[37mDEBUG[0m]  >>>>>>>>>>>> protoComm.Write: [2 1 0 0 0 1 0 1 6 5 3]
// 2022-06-02T10:00:57+02:00 [[37mDEBUG[0m]  CONNECT>>RECV  [128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
// 2022-06-02T10:00:57+02:00 [[37mDEBUG[0m]  PackSize: 4900, FrameSize: 980
// 2022-06-02T10:00:57+02:00 [[37mDEBUG[0m]  >>>>>>>>>>>> protoComm.Write: [2 1 3 233 0 1 0 37 128 64 1 0 32 159 2 6 0 0 0 16 0 0 156 1 0 95 42 2 1 1 95 54 1 0 154 3 34 6 2 159 33 3 16 0 87 96 3]
// 2022-06-02T10:00:57+02:00 [[37mDEBUG[0m]  >>>>>>>>>>>> protoComm.Read: [2 1 0 0 0 1 0 1 6 5 3]
// 2022-06-02T10:00:57+02:00 [[37mDEBUG[0m]  >>>>>>>>>>>> protoComm.Read: [2 1 3 233 0 1 0 70 128 64 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 110 3]
// 2022-06-02T10:00:57+02:00 [[37mDEBUG[0m]  >>>>>>>>>>>> protoComm.Write: [2 1 0 0 0 1 0 1 6 5 3]
// 2022-06-02T10:00:57+02:00 [[34mINFO[0m]  TransactionStart started
// 2022-06-02T10:00:57+02:00 [[37mDEBUG[0m]  PackSize: 4900, FrameSize: 980
// 2022-06-02T10:00:57+02:00 [[37mDEBUG[0m]  >>>>>>>>>>>> protoComm.Write: [2 1 3 234 0 1 0 2 128 48 89 3]
// 2022-06-02T10:00:57+02:00 [[37mDEBUG[0m]  >>>>>>>>>>>> protoComm.Read: [2 1 0 0 0 1 0 1 6 5 3]
// 2022-06-02T10:00:57+02:00 [[37mDEBUG[0m]  >>>>>>>>>>>> protoComm.Read: [2 1 0 3 0 1 0 106 123 34 99 117 114 114 101 110 116 83 116 97 116 117 115 34 58 34 115 101 97 114 99 104 77 111 100 101 34 44 10 34 112 114 111 109 112 116 115 34 58 34 80 76 83 32 83 119 105 112 101 47 73 110 115 101 114 116 47 84 97 112 32 67 97 114 100 34 44 10 34 106 115 111 110 68 97 116 97 34 58 123 10 34 99 117 114 83 101 97 114 99 104 77 111 100 101 34 58 34 55 34 10 125 10 125 65 3]
// 2022-06-02T10:00:57+02:00 [[34mINFO[0m]  >>> Reporting: {"currentStatus":"searchMode",

ULONG address_string_to_address(IN const char *remote_address, OUT BTH_ADDR *bluetooth_address)
{
    if ((remote_address == NULL) || (bluetooth_address == NULL))
    {
        return 1;
    }

    *bluetooth_address = 0;
    ULONG address_data[6];
    sscanf(remote_address,
           "%02x:%02x:%02x:%02x:%02x:%02x",
           &address_data[0], &address_data[1], &address_data[2], &address_data[3], &address_data[4], &address_data[5]);

    for (int i = 0; i < 6; i++)
    {
        BTH_ADDR address_temp = (BTH_ADDR)(address_data[i] & 0xFF);
        *bluetooth_address = ((*bluetooth_address) << 8) + address_temp;
    }
    return 0;
}

typedef struct
{
    uint8_t b[6];
} __attribute__((packed)) bdaddr_t;

int bachk(const char *str)
{
    if (!str)
        return -1;

    if (strlen(str) != 17)
        return -1;

    while (*str)
    {
        if (!isxdigit(*str++))
            return -1;

        if (!isxdigit(*str++))
            return -1;

        if (*str == 0)
            break;

        if (*str++ != ':')
            return -1;
    }

    return 0;
}

int str2ba3(const char *str, bdaddr_t *ba)
{
    int i;

    if (bachk(str) < 0)
    {
        memset(ba, 0, sizeof(*ba));
        return -1;
    }

    for (i = 5; i >= 0; i--, str += 3)
        ba->b[i] = strtol(str, NULL, 16);

    printf("3333333333333333\n");
    printf("%X\n", ba->b);

    return 0;
}

int str2ba(char *str_bt_addr, BTH_ADDR *bt_addr) // for converting string to bluetooth address
{
    unsigned int addr[6];
    // 54:81:2d:7f:cd:d2
    // if (sscanf_s(str_bt_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
    // &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5]) != 6)
    // {
    //     return 1;
    // }
    // for (int i = 0;i < 6;++i) {
    //     printf("%X\n", addr[i]);
    // }
    // *bt_addr = 0;
    // BTH_ADDR tmpaddr;
    // int i;
    // for (i = 0;i < 6;++i)
    // {
    //     tmpaddr = (BTH_ADDR)(addr[i] & 0xff);
    //     *bt_addr = ((*bt_addr) << 8) + tmpaddr;
    // }
    // printf("%X\n", *bt_addr);
    *bt_addr = 0x54812D7FCDD2;
    return 0;
}

int _cdecl main(int argc, char *argv[])
{
    ULONGLONG remote_bluetooth_address = 0;

    ULONG parse_return = parse_command_line(argc, argv);
    if (parse_return == 0)
    {
        // Ask for Winsock version 2.2
        WSADATA wsa_data = {0};
        ULONG startup_return = WSAStartup(MAKEWORD(2, 2), &wsa_data);
        if (startup_return != 0)
        {
            printf("[FATAL] Unable to initialize Winsock version 2.2\n");
            return startup_return;
        }

        if (device_remote_name[0] != '\0')
        {
            // Get address from name of the remote device name and run the application in client mode
            int result = name_to_address(device_remote_name, (BTH_ADDR *)&remote_bluetooth_address);
            if (result != 0)
            {
                printf("[FATAL] Unable to get address of the remote radio having name %s\n", device_remote_name);
                return result;
            }
            printf("Device address after name to address: %X", remote_bluetooth_address);

            // 54:81:2d:7f:cd:d2
            // BTH_ADDR bt_addr;
            // char* server_address = "54:81:2d:7f:cd:d2";
            // if (str2ba(server_address, &bt_addr) == 1)
            // {
            //     printf("[FATAL] Unable to get address of the remote radio having name %s\n", server_address);
            //     //Sleep(2000);
            //     return 1;
            // }

            // bdaddr_t bdaddr;
            // str2ba3("54:81:2d:7f:cd:d2", &bdaddr);

            return client_mode(remote_bluetooth_address, max_connection_cycles);
        }
        else if (device_remote_address[0] != '\0')
        {
            int result = address_string_to_address(device_remote_address, (BTH_ADDR *)&remote_bluetooth_address);
            if (result != 0)
            {
                printf("[FATAL] Unable to get address of the remote radio having formated address-string %s\n", device_remote_address);
                return result;
            }

            return client_mode(remote_bluetooth_address, max_connection_cycles);
        }
    }
    else if (parse_return == 1)
    {
        cli_help();
    }
    else
    {
        printf("[FATAL] Error in parsing command line");
    }
}
