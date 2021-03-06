#include <iostream>
#include <iomanip>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <windows.h>
#include <string>

#include "iocommon.h"

using namespace std;

void PrintSetUsage()
{
    wcout<<endl<<"  ptctl set commands: "<<endl;
    wcout<<"    ptctl set ratio [ratio_value]"<<endl;
    wcout<<"    ptctl set offset [offset_value]"<<endl;
    wcout<<"    ptctl set adjacent [adjacent_value]"<<endl;
    wcout<<"    ptctl set prefix [prefix/prefixlen]"<<endl;
    wcout<<"    ptctl set gateway [XX-XX-XX-XX-XX-XX]"<<endl;
}

void PrintShowUsage()
{
    wcout<<endl<<"  ptctl show commands: "<<endl;
    wcout<<"    ptctl show ratio"<<endl;
    wcout<<"    ptctl show offset"<<endl;
    wcout<<"    ptctl show adjacent"<<endl;
    wcout<<"    ptctl show prefix"<<endl;
    wcout<<"    ptctl show gateway"<<endl;
}

void PrintStartUsage()
{
    wcout<<endl<<"  ptctl start commands: "<<endl;
    wcout<<"    ptctl start arp"<<endl;
    wcout<<"    ptctl start multiplex"<<endl;
    wcout<<"    ptctl start lookup"<<endl;
    wcout<<"    ptctl start xlate"<<endl;
}

void PrintStopUsage()
{
    wcout<<endl<<"  ptctl stop commands: "<<endl;
    wcout<<"    ptctl stop xlate"<<endl;
    wcout<<"    ptctl stop arp"<<endl;
    wcout<<"    ptctl stop lookup"<<endl;
    wcout<<"    ptctl stop multiplex"<<endl;
}

void PrintAllUsage()
{
    wcout<<endl<<"ptctl command usage: "<<endl;
    
    PrintSetUsage();
    
    PrintShowUsage();

    PrintStartUsage();

    PrintStopUsage();

    wcout<<endl<<"For more information, please contact the author at 'wentaoshang@gmail.com'."<<endl<<endl;
}

int wmain(int argc, wchar_t *argv[])
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0)
    {
        /* Tell the user that we could not find a usable */
        /* Winsock DLL.                                  */
        wcout<<"WSAStartup failed with error: "<<err<<endl;
        return 1;
    }

    /* Confirm that the WinSock DLL supports 2.2.*/
    /* Note that if the DLL supports versions greater    */
    /* than 2.2 in addition to 2.2, it will still return */
    /* 2.2 in wVersion since that is the version we      */
    /* requested.                                        */

    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
    {
        /* Tell the user that we could not find a usable */
        /* WinSock DLL.                                  */
        wcout<<"Could not find a usable version of Winsock.dll"<<endl;
        WSACleanup();
        return 1;
    }
    
    BOOL ret = FALSE;
    DWORD byteReturned = 0;

    HANDLE PtHandle = CreateFile(
        L"\\\\.\\PassThru",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (PtHandle == INVALID_HANDLE_VALUE)
    {
        wcout<<"Failed to open 'PassThru' device."<<endl;
        WSACleanup();
        return 1;
    }

    if (argc < 2)
    {
        PrintAllUsage();
        CloseHandle(PtHandle);
        WSACleanup();
        return 0;
    }

    if (wcscmp(argv[1], L"set") == 0)
    {
        // 'set' commands
        if (argc != 4)
        {
            PrintSetUsage();
            CloseHandle(PtHandle);
            WSACleanup();
            return 0;
        }

        if (wcscmp(argv[2], L"prefix") == 0)
        {
            // 'set prefix XXXX:XXXX::/XX'
            wstring prefixString = wstring(argv[3]);
            size_t pos = prefixString.find(L"/");
            size_t strsize = prefixString.length();
            wstring lenString = prefixString.substr(pos + 1, strsize - pos - 1);
            BYTE prefixLength = (BYTE)(_wtoi(lenString.c_str()));
            SOCKADDR_IN6 prefix;
            int wsaRet = sizeof(SOCKADDR_IN6);

            if (WSAStringToAddress((LPTSTR)((prefixString.substr(0, pos)).c_str()), AF_INET6, NULL, (LPSOCKADDR)&prefix, &wsaRet) == SOCKET_ERROR)
            {
	            wcout<<"WSAStringToAddress() failed with error "<<WSAGetLastError()<<endl;
	            CloseHandle(PtHandle);
                WSACleanup();
                return 1;
            }

            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_SET_PREFIX, prefix.sin6_addr.u.Byte, 16, NULL, 0, &byteReturned, NULL);
            if (ret == FALSE)
            {
                wcout<<"ptctl: set prefix failed."<<endl;
                CloseHandle(PtHandle);
                WSACleanup();
                return 1;
            }

            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_SET_PREFIXLENGTH, &prefixLength, sizeof(prefixLength), NULL, 0, &byteReturned, NULL);
            if (ret == FALSE)
            {
                wcout<<"ptctl: set prefix length failed."<<endl;
                CloseHandle(PtHandle);
                WSACleanup();
                return 1;
            }
            wcout<<"Done."<<endl;
        }
        else if (wcscmp(argv[2], L"gateway") == 0)
        {
            // 'set gateway XX-XX-XX-XX-XX-XX'
            wchar_t macString[20];
            wcscpy(macString, argv[3]);
            UCHAR mac[6];
            wchar_t *nptr = macString;
            wchar_t *endptr = NULL;
            for (int i = 0; i < 6; i++)
            {
                mac[i] = (UCHAR)(wcstol(nptr, &endptr, 16));
                nptr = endptr + 1;
            }

            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_SET_GATEWAYMAC, mac, 6, NULL, 0, &byteReturned, NULL);
            if (ret == FALSE)
            {
                wcout<<"ptctl: set gateway failed."<<endl;
                CloseHandle(PtHandle);
                WSACleanup();
                return 1;
            }
            wcout<<"Done."<<endl;
        }
        else if (wcscmp(argv[2], L"ratio") == 0)
        {
            // 'set ratio XXX'
            USHORT ratio = (USHORT)(_wtoi(argv[3]));
            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_SET_RATIO, &ratio, sizeof(ratio), NULL, 0, &byteReturned, NULL);
            if (ret == FALSE)
            {
                wcout<<"ptctl: set ratio failed."<<endl;
                CloseHandle(PtHandle);
                WSACleanup();
                return 1;
            }
            wcout<<"Done."<<endl;
        }
        else if (wcscmp(argv[2], L"offset") == 0)
        {
            // 'set offset XXX'
            USHORT offset = (USHORT)(_wtoi(argv[3]));
            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_SET_OFFSET, &offset, sizeof(offset), NULL, 0, &byteReturned, NULL);
            if (ret == FALSE)
            {
                wcout<<"ptctl: set offset failed."<<endl;
                CloseHandle(PtHandle);
                WSACleanup();
                return 1;
            }
            wcout<<"Done."<<endl;
        }
        else if (wcscmp(argv[2], L"adjacent") == 0)
        {
            // 'set offset XXX'
            USHORT adjacent = (USHORT)(_wtoi(argv[3]));
            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_SET_ADJACENT, &adjacent, sizeof(adjacent), NULL, 0, &byteReturned, NULL);
            if (ret == FALSE)
            {
                wcout<<"ptctl: set adjacent failed."<<endl;
                CloseHandle(PtHandle);
                WSACleanup();
                return 1;
            }
            wcout<<"Done."<<endl;
        }
        else
        {
            PrintSetUsage();
        }
    }
    else if (wcscmp(argv[1], L"show") == 0)
    {
        // 'show' commands
        if (argc != 3)
        {
            PrintShowUsage();
            CloseHandle(PtHandle);
            WSACleanup();
            return 0;
        }

        wcout<<endl;

        if (wcscmp(argv[2], L"prefix") == 0)
        {
            // 'show prefix'
            SOCKADDR_IN6 prefix;
            BYTE  prefixlen;

            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_GET_PREFIX, NULL, 0, prefix.sin6_addr.u.Byte, 16, &byteReturned, NULL);
            if (ret == FALSE)
            {
                wcout<<"ptctl: get prefix failed."<<endl;
                CloseHandle(PtHandle);
                WSACleanup();
                return 1;
            }

            prefix.sin6_family = AF_INET6;
            prefix.sin6_flowinfo = 0;
            prefix.sin6_port = 0;

            wchar_t prefixchars[200];
            if (WSAAddressToString((LPSOCKADDR)&prefix, sizeof(prefix), NULL, prefixchars, &byteReturned) == SOCKET_ERROR) 
            { 
	            wcout<<"WSAAdressToString() failed with error "<<WSAGetLastError()<<endl;;
	            CloseHandle(PtHandle);
                WSACleanup();
                return 1;
            }
            
            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_GET_PREFIXLENGTH, NULL, 0, &prefixlen, sizeof(prefixlen), &byteReturned, NULL);
            if (ret == FALSE)
            {
                wcout<<"ptctl : get prefix length failed."<<endl;
                CloseHandle(PtHandle);
                WSACleanup();
                return 1;
            }

            wstring prefixString = wstring(prefixchars);
            size_t pos = prefixString.find(L"%");
            wcout<<prefixString.substr(0, pos)<<"/"<<((int)prefixlen)<<endl;
        }
        else if (wcscmp(argv[2], L"gateway") == 0)
        {
            // 'show gateway'
            UCHAR mac[6];
            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_GET_GATEWAYMAC, NULL, 0, mac, 6, &byteReturned, NULL);
            if (ret == FALSE)
            {
                wcout<<"ptctl: get gateway failed."<<endl;
                CloseHandle(PtHandle);
                WSACleanup();
                return 1;
            }

            wcout<<hex<<setw(2)<<setfill(L'0')<<mac[0];
            wcout<<"-";
            wcout<<hex<<setw(2)<<setfill(L'0')<<mac[1];
            wcout<<"-";
            wcout<<hex<<setw(2)<<setfill(L'0')<<mac[2];
            wcout<<"-";
            wcout<<hex<<setw(2)<<setfill(L'0')<<mac[3];
            wcout<<"-";
            wcout<<hex<<setw(2)<<setfill(L'0')<<mac[4];
            wcout<<"-";
            wcout<<hex<<setw(2)<<setfill(L'0')<<mac[5]<<endl;
        }
        else if (wcscmp(argv[2], L"ratio") == 0)
        {
            USHORT ratio;
            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_GET_RATIO, NULL, 0, &ratio, sizeof(ratio), &byteReturned, NULL );
            if (ret == FALSE)
            {
                wcout<<"ptctl: get ratio failed."<<endl;
                CloseHandle(PtHandle);
                WSACleanup();
                return 1;
            }
            wcout<<ratio<<endl;
        }
        else if (wcscmp(argv[2], L"offset") == 0)
        {
            USHORT offset;
            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_GET_OFFSET, NULL, 0, &offset, sizeof(offset), &byteReturned, NULL );
            if (ret == FALSE)
            {
                wcout<<"ptctl: get offset failed."<<endl;
                CloseHandle(PtHandle);
                WSACleanup();
                return 1;
            }
            wcout<<offset<<endl;
        }
        else if (wcscmp(argv[2], L"adjacent") == 0)
        {
            USHORT adjacent;
            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_GET_ADJACENT, NULL, 0, &adjacent, sizeof(adjacent), &byteReturned, NULL );
            if (ret == FALSE)
            {
                wcout<<"ptctl: get adjacent failed."<<endl;
                CloseHandle(PtHandle);
                WSACleanup();
                return 1;
            }
            wcout<<adjacent<<endl;
        }
        else
        {
            PrintShowUsage();
        }
    }
    else if (wcscmp(argv[1], L"start") == 0)
    {
        // 'start' commands
        if (argc != 3)
        {
            PrintStartUsage();
            CloseHandle(PtHandle);
            WSACleanup();
            return 0;
        }

        wcout<<endl;

        if (wcscmp(argv[2], L"xlate") == 0)
        {
            // 'start xlate'
            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_ENABLE_XLATE, NULL, 0, NULL, 0, &byteReturned, NULL);
            if (ret == FALSE)
            {
                wcout<<"ioctl: start ivi failed."<<endl;
            }
            wcout<<"Done."<<endl;
        }
        else if (wcscmp(argv[2], L"arp") == 0)
        {
            // 'start arp'
            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_ENABLE_ARPREPLY, NULL, 0, NULL, 0, &byteReturned, NULL);
            if (ret == FALSE)
            {
                wcout<<"ioctl: enable arp auto reply failed."<<endl;
            }
            wcout<<"Done."<<endl;
        }
        else if (wcscmp(argv[2], L"multiplex") == 0)
        {
            // 'start multiplex'
            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_ENABLE_MULTIPLEX, NULL, 0, NULL, 0, &byteReturned, NULL);
            if (ret == FALSE)
            {
                wcout<<"ioctl: enable address multiplex failed."<<endl;
            }
            wcout<<"Done."<<endl;
        }
        else if (wcscmp(argv[2], L"lookup") == 0)
        {
            // 'start lookup'
            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_ENABLE_PREFIXLOOKUP, NULL, 0, NULL, 0, &byteReturned, NULL);
            if (ret == FALSE)
            {
                wcout<<"ioctl: enable prefix lookup failed."<<endl;
            }
            wcout<<"Done."<<endl;
        }
        else
        {
            PrintStartUsage();
        }
    }
    else if (wcscmp(argv[1], L"stop") == 0)
    {
        // 'stop' commands
        if (argc != 3)
        {
            PrintStopUsage();
            CloseHandle(PtHandle);
            WSACleanup();
            return 0;
        }

        wcout<<endl;

        if (wcscmp(argv[2], L"xlate") == 0)
        {
            // 'stop xlate'
            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_DISABLE_XLATE, NULL, 0, NULL, 0, &byteReturned, NULL);
            if (ret == FALSE)
            {
                wcout<<"ioctl: stop ivi failed."<<endl;
            }
            wcout<<"Done."<<endl;
        }
        else if (wcscmp(argv[2], L"arp") == 0)
        {
            // 'stop arp'
            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_DISABLE_ARPREPLY, NULL, 0, NULL, 0, &byteReturned, NULL);
            if (ret == FALSE)
            {
                wcout<<"ioctl: disable arp auto reply failed."<<endl;
            }
            wcout<<"Done."<<endl;
        }
        else if (wcscmp(argv[2], L"multiplex") == 0)
        {
            // 'stop multiplex'
            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_DISABLE_MULTIPLEX, NULL, 0, NULL, 0, &byteReturned, NULL);
            if (ret == FALSE)
            {
                wcout<<"ioctl: disable address multiplex failed."<<endl;
            }
            wcout<<"Done."<<endl;
        }
        else if (wcscmp(argv[2], L"lookup") == 0)
        {
            // 'stop lookup'
            ret = DeviceIoControl(PtHandle, IOCTL_PTUSERIO_DISABLE_PREFIXLOOKUP, NULL, 0, NULL, 0, &byteReturned, NULL);
            if (ret == FALSE)
            {
                wcout<<"ioctl: disable prefix lookup failed."<<endl;
            }
            wcout<<"Done."<<endl;
        }
        else
        {
            PrintStopUsage();
        }
    }
    else
    {
        PrintAllUsage();
    }

    CloseHandle(PtHandle);
    WSACleanup();
    return 0;
}