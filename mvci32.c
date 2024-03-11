#define _WINDOWS

#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "des_crypt.h"

#include "ftd2xx.h"

#include "j2534_v0404.h"

#define REG_PT_KEY "PassThruSupport.04.04"
#define REG_MVCI_SUBKEY "XHorse - MVCI"

#define MVCI_USB_DESC "M-VCI"

#define J2534_MAX_STR_SIZE 80

#define MAX_CHANNELS 3
#define MAX_FILTERS 100
#define MAX_PER_MSGS (MAX_CHANNELS * 10)

#define MAX_PT_MSG_SIZE (sizeof(((PASSTHRU_MSG *)NULL)->Data))
#define BUF_SIZE (MAX_PT_MSG_SIZE + 256)

// Read/write communication timeout (milliseconds)
#define MVCI_TIMEOUT 5500

// Wait time after reset
#define MVCI_RESET_SLEEP 400

// MVCI Command codes
#define MVCI_OPEN_ENC               0x01
#define MVCI_CLOSE_ENC              0x02
#define MVCI_READVERSION            0x03
#define MVCI_CONNECT                0x07
#define MVCI_DISCONNECT             0x08
#define MVCI_READMSG                0x09
#define MVCI_WRITEMSG               0x0A
#define MVCI_STARTMSGFILTER         0x0B
#define MVCI_STOPMSGFILTER          0x0C
#define MVCI_SETPROGRAMMINGVOLTAGE  0x0D
#define MVCI_IOCTL                  0x0E
#define MVCI_STARTPERIODICMSG       0x0F
#define MVCI_STOPPERIODICMSG        0x10


HANDLE *g_mvciHandle = INVALID_HANDLE_VALUE;
FT_HANDLE g_mvciFTHandle = INVALID_HANDLE_VALUE;

// Directs the functions to use either the Win32 Comm API or the FTDI D2XX API

DWORD g_useD2XX = 0;
HMODULE g_hFTD2XX = NULL;

BOOL g_mvci_isOpen = FALSE;

unsigned long g_deviceID = 0;
unsigned long g_numChannels = 0;
unsigned long g_numFilters = 0;
unsigned long g_numPerMsgs = 0;

unsigned long g_channelIDs[MAX_CHANNELS], g_protocolIDs[MAX_CHANNELS];
unsigned long g_filterIDs[MAX_FILTERS], g_filterProtocolIDs[MAX_FILTERS];
unsigned long g_perMsgIDs[MAX_PER_MSGS], g_perMsgProtocolIDs[MAX_PER_MSGS];

// COM/Serial path (for Win32 API) or USB description string (for D2XX API)

char g_devicePath[256];

char *g_DllVersion = "MVCI32 J2534 DLL V1.0001";
char *g_ApiVersion = "04.04";
char g_FirmwareVersion[80];

char *g_errorStrings[] = {
    "Success",
    "Function not supported",
    "Invalid channel ID",
    "Invalid protocol ID",
    "NULL parameter",
    "Invalid IOCTL value",
    "Invalid flags",
    "Operation failed",
    "Device not connected",
    "Timeout",
    "Invalid message",
    "Invalid time interval",
    "Exceeded limit",
    "Invalid message ID",
    "Device in use",
    "Invalid Ioctl ID",
    "Buffer empty",
    "Buffer full",
    "Buffer overflow",
    "Invalid pin number",
    "Channel in use",
    "Incorrect protocol ID",
    "Invalid filter ID",
    "No flow control filter",
    "Not unique ID",
    "Invalid baud rate",
    "Invalid device ID",
    NULL };

long g_lastError = STATUS_NOERROR;

// Macro to simplify storing the last error code and returning from function

#define PT_RETURN(status) { g_lastError = (status); return (status); }

// FTD2XX Function Pointers

FT_STATUS WINAPI (*ftOpenEx)(PVOID pArg1, DWORD Flags, FT_HANDLE *pHandle);
FT_STATUS WINAPI (*ftClose)(FT_HANDLE ftHandle);
FT_STATUS WINAPI (*ftRead)(FT_HANDLE ftHandle, LPVOID lpBuffer, DWORD dwBytesToRead, LPDWORD lpBytesReturned);
FT_STATUS WINAPI (*ftWrite)(FT_HANDLE ftHandle, LPVOID lpBuffer, DWORD dwBytesToWrite, LPDWORD lpBytesWritten);
FT_STATUS WINAPI (*ftSetBaudRate)(FT_HANDLE ftHandle, ULONG BaudRate);
FT_STATUS WINAPI (*ftSetDataCharacteristics)(FT_HANDLE ftHandle, UCHAR WordLength, UCHAR StopBits, UCHAR Parity);
FT_STATUS WINAPI (*ftSetTimeouts)(FT_HANDLE ftHandle, ULONG ReadTimeout, ULONG WriteTimeout);
FT_STATUS WINAPI (*ftSetFlowControl)(FT_HANDLE ftHandle, USHORT FlowControl, UCHAR XonChar, UCHAR XoffChar);
FT_STATUS WINAPI (*ftSetDtr)(FT_HANDLE ftHandle);
FT_STATUS WINAPI (*ftClrDtr)(FT_HANDLE ftHandle);
FT_STATUS WINAPI (*ftSetRts)(FT_HANDLE ftHandle);
FT_STATUS WINAPI (*ftClrRts)(FT_HANDLE ftHandle);
FT_STATUS WINAPI (*ftPurge)(FT_HANDLE ftHandle, ULONG Mask);
FT_STATUS WINAPI (*ftResetDevice)(FT_HANDLE ftHandle);


unsigned int writeBytes(unsigned char *buf, unsigned int len)
{
    unsigned int bytesLeft = len;
    DWORD bytesWritten;
    BOOL ret = FALSE;
    
    DWORD startTime = GetTickCount();
    while((bytesLeft > 0) && ((GetTickCount() - startTime) < MVCI_TIMEOUT))
    {
        if(g_useD2XX)
        {
            ret = (ftWrite(g_mvciFTHandle, buf, bytesLeft, &bytesWritten) == FT_OK);
        }
        else
        {
            ret = WriteFile(g_mvciHandle, buf, bytesLeft, &bytesWritten, NULL);
        }
        
        buf += bytesWritten;
        bytesLeft -= bytesWritten;
    }
    
    if(ret)
        return STATUS_NOERROR;
        
    if(bytesLeft > 0)
        return ERR_TIMEOUT;
        
    return ERR_FAILED;
}

BOOL readBytes(unsigned char *buf, unsigned int size, unsigned int *bytesRead, unsigned int timeout)
{
    unsigned int bytesLeft = size;
    DWORD l_bytesRead;
    BOOL ret = FALSE;

    *bytesRead = 0;
    DWORD startTime = GetTickCount();
    while((bytesLeft > 0) && ((GetTickCount() - startTime) < timeout))
    {
        if(g_useD2XX)
        {
            ret = (ftRead(g_mvciFTHandle, buf, bytesLeft, &l_bytesRead) == FT_OK);
        }
        else
        {
            ret = ReadFile(g_mvciHandle, buf, bytesLeft, &l_bytesRead, NULL);
        }
    
        buf += l_bytesRead;
        *bytesRead += l_bytesRead;
        bytesLeft -= l_bytesRead;
    }
    
    if(ret)
        return TRUE;
        
    if(bytesLeft > 0)
        return FALSE;
        
    return FALSE;
}

unsigned int sendRequest(unsigned char *buf, unsigned int len, BOOL crypt)
{
    unsigned char *tempBuf;

    if(len < 1)
        return ERR_FAILED;
            
    unsigned int dataLen = len + 2;         // Data + 2 byte length

#ifndef MVCI_NOCRYPT
    if(crypt)
        dataLen = (dataLen + 7) & ~0x07;    // Pad to multiple of 8 if encrypting
#endif

    unsigned int packetLen = dataLen + 3;   // Data + 2 byte length + 2 byte size of overall packet + 1-byte XOR checksum
    if(!(tempBuf = malloc(packetLen)))
        return ERR_FAILED;
    
    memset(tempBuf, 0, packetLen);
    
    // Packet length (2 bytes, little endian)
    tempBuf[0] = (packetLen & 0xFF);
    tempBuf[1] = (packetLen >> 8) & 0xFF;
    
    // Data length (2 bytes, little endian, not including the length header)
    tempBuf[2] = (len & 0xFF);
    tempBuf[3] = (len >> 8) & 0xFF;
    
    memcpy_s(tempBuf + 4, packetLen - 5, buf, len);

#ifndef MVCI_NOCRYPT
    if(crypt)
    {
        DES_crypt(tempBuf + 2, dataLen, tempBuf + 2, TRUE);
    }
#endif
    
    unsigned int i;
    unsigned char checksum = 0;
    for(i = 0; i < (packetLen - 1); i++)
        checksum ^= tempBuf[i];
    
    tempBuf[i] = checksum;
    
    unsigned int ret = writeBytes(tempBuf, packetLen);
    free(tempBuf);
    return ret;
}

BOOL readResponse(unsigned char *buf, unsigned int size, unsigned int *responseLength, BOOL crypt, unsigned int timeout)
{
    unsigned int l_bytesRead;
    unsigned char *respBuf;
    
    if(size < 3)
        return FALSE;

    *responseLength = 0;
        
    if(!(respBuf = malloc(size)))
        return FALSE;
    
    memset(respBuf, 0, size);

    // Read packet length from device
    unsigned int ret = readBytes(respBuf, 2, &l_bytesRead, timeout);
    if(ret && (l_bytesRead >= 2))
    {
        unsigned int dataLen = (respBuf[0] | (respBuf[1] << 8)) - 2;
        if(dataLen > (size + 3)) // 2 bytes data length + 1 byte XOR checksum at end of packet
            dataLen = size + 3;

        unsigned int ret = readBytes(respBuf, dataLen, &l_bytesRead, timeout);
        if(ret)
        {

#ifndef MVCI_NOCRYPT
            if(crypt)
                DES_crypt(respBuf, l_bytesRead - 1, respBuf, FALSE); // Checksum not included in encrypted data
#endif

            unsigned int len = (respBuf[0] | (respBuf[1] << 8)); // Skip length bytes
            if(len > (l_bytesRead - 3))
                len = l_bytesRead - 3;

            memcpy_s(buf, size, respBuf + 2, len);
            *responseLength = len;
        }
    }
    
    free(respBuf);
    return ret;
}

void d2xxCleanup(void)
{
        if(g_mvciFTHandle != INVALID_HANDLE_VALUE)
        {
            ftClose(g_mvciFTHandle);
            g_mvciFTHandle = INVALID_HANDLE_VALUE;
        }

        if(g_hFTD2XX)
        {
            FreeLibrary(g_hFTD2XX);
            g_hFTD2XX = NULL;
        }

        ftOpenEx = NULL;
        ftClose = NULL;
        ftRead = NULL;
        ftWrite = NULL;
        ftSetBaudRate = NULL;
        ftSetDataCharacteristics = NULL;
        ftSetTimeouts = NULL;
        ftSetFlowControl = NULL;
        ftSetDtr = NULL;
        ftClrDtr = NULL;
        ftSetRts = NULL;
        ftClrRts = NULL;
        ftResetDevice = NULL;
}

__declspec(dllexport)
long WINAPI PassThruOpen(void* pName, unsigned long *pDeviceID)
{
#ifndef MVCI_NOCRYPT
    static unsigned char mvciName[] = {'M', 'V', 'C', 'I', '-', 'T'};
#endif

    if(!pDeviceID)
        PT_RETURN(ERR_INVALID_DEVICE_ID);

    if(g_mvci_isOpen)
        PT_RETURN(ERR_DEVICE_IN_USE);
        
    DWORD dataSize = sizeof(g_useD2XX);
    if(SHRegGetValueA(HKEY_LOCAL_MACHINE,
            "Software\\" REG_PT_KEY "\\" REG_MVCI_SUBKEY "\\Parameter",
            "UseD2XX",
            SRRF_RT_DWORD,
            NULL,
            &g_useD2XX,
            &dataSize) != ERROR_SUCCESS)
        g_useD2XX = 0;

    if(g_useD2XX)
    {
        // Using D2XX Api

        // Load library dynamically and get function pointers
        if(!g_hFTD2XX)
        {
            if((g_hFTD2XX = LoadLibraryA("ftd2xx.dll")) == NULL)
                PT_RETURN(ERR_DEVICE_NOT_CONNECTED);
        }
        
        ftOpenEx = (void *)GetProcAddress(g_hFTD2XX, "FT_OpenEx");
        ftClose = (void *)GetProcAddress(g_hFTD2XX, "FT_Close");
        ftRead = (void *)GetProcAddress(g_hFTD2XX, "FT_Read");
        ftWrite = (void *)GetProcAddress(g_hFTD2XX, "FT_Write");
        ftSetBaudRate = (void *)GetProcAddress(g_hFTD2XX, "FT_SetBaudRate");
        ftSetDataCharacteristics = (void *)GetProcAddress(g_hFTD2XX, "FT_SetDataCharacteristics");
        ftSetTimeouts = (void *)GetProcAddress(g_hFTD2XX, "FT_SetTimeouts");
        ftSetFlowControl = (void *)GetProcAddress(g_hFTD2XX, "FT_SetFlowControl");
        ftSetDtr = (void *)GetProcAddress(g_hFTD2XX, "FT_SetDtr");
        ftClrDtr = (void *)GetProcAddress(g_hFTD2XX, "FT_ClrDtr");
        ftSetRts = (void *)GetProcAddress(g_hFTD2XX, "FT_SetRts");
        ftClrRts = (void *)GetProcAddress(g_hFTD2XX, "FT_ClrRts");
        ftPurge = (void *)GetProcAddress(g_hFTD2XX, "FT_Purge");
        ftResetDevice = (void *)GetProcAddress(g_hFTD2XX, "FT_ResetDevice");
        
        if(!ftOpenEx || !ftClose || !ftRead || !ftWrite || !ftSetBaudRate ||
                !ftSetDataCharacteristics || !ftSetTimeouts || !ftSetFlowControl ||
                !ftSetDtr || !ftClrDtr || !ftSetRts || !ftClrRts || !ftPurge || !ftResetDevice)
            goto cleanup;
        
        DWORD dataSize = sizeof(g_devicePath);
        if(SHRegGetValueA(HKEY_LOCAL_MACHINE,
                "Software\\" REG_PT_KEY "\\" REG_MVCI_SUBKEY "\\Parameter",
                "USBDescription",
                SRRF_RT_REG_SZ,
                NULL,
                g_devicePath,
                &dataSize) != ERROR_SUCCESS)
            strcpy_s(g_devicePath, sizeof(g_devicePath), MVCI_USB_DESC);

        if(ftOpenEx(g_devicePath, FT_OPEN_BY_DESCRIPTION, &g_mvciFTHandle) != FT_OK)
            goto cleanup;
        
        if(!((ftSetBaudRate(g_mvciFTHandle, FT_BAUD_115200) == FT_OK) &&
           (ftSetDataCharacteristics(g_mvciFTHandle, FT_BITS_8, FT_STOP_BITS_1, FT_PARITY_NONE) == FT_OK) &&
           (ftSetTimeouts(g_mvciFTHandle, MVCI_TIMEOUT, MVCI_TIMEOUT) == FT_OK) &&
           (ftSetFlowControl(g_mvciFTHandle, FT_FLOW_NONE, 0, 0) == FT_OK)))
        {
            goto cleanup;
        }

        ftPurge(g_mvciFTHandle, FT_PURGE_RX);
        ftResetDevice(g_mvciFTHandle);
        ftClrRts(g_mvciFTHandle);
        Sleep(1);
        
        ftSetDtr(g_mvciFTHandle);
        Sleep(1);

        ftClrDtr(g_mvciFTHandle);

        g_deviceID = (unsigned int)g_mvciFTHandle;

    } // D2XX Api
    else
    {
        // Using Win32 API

        DWORD comPort, dataSize;
        dataSize = sizeof(comPort);
        if(SHRegGetValueA(HKEY_LOCAL_MACHINE,
                "Software\\" REG_PT_KEY "\\" REG_MVCI_SUBKEY "\\Parameter",
                "Comport",
                SRRF_RT_DWORD,
                NULL,
                &comPort,
                &dataSize) != ERROR_SUCCESS)
            goto cleanup;
        
        snprintf(g_devicePath, sizeof(g_devicePath), "\\\\.\\COM%lu", comPort);
        g_mvciHandle = CreateFileA(g_devicePath,
            GENERIC_READ |
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);
    
        if(g_mvciHandle == INVALID_HANDLE_VALUE)
            goto cleanup;
        
        g_deviceID = (unsigned int)g_mvciHandle;

        COMMTIMEOUTS commTimeouts;

        // Read timeout

        commTimeouts.ReadIntervalTimeout = MAXDWORD;
        commTimeouts.ReadTotalTimeoutMultiplier = MAXDWORD;
        commTimeouts.ReadTotalTimeoutConstant = MVCI_TIMEOUT;

        // Write timeout

        commTimeouts.WriteTotalTimeoutMultiplier = 0;
        commTimeouts.WriteTotalTimeoutConstant = 0;

        SetCommTimeouts(g_mvciHandle, &commTimeouts);
        
        BOOL commStateOK;

        DCB dcb;

        dcb.DCBlength = sizeof(dcb);
        if((commStateOK = GetCommState(g_mvciHandle, &dcb)))
        {
            dcb.BaudRate = CBR_115200;
        	dcb.ByteSize = 8;
        	dcb.Parity = NOPARITY;
        	dcb.StopBits = ONESTOPBIT;
        	dcb.fBinary = TRUE;
        	dcb.fParity = FALSE;
            dcb.fOutX = FALSE;
            dcb.fInX = FALSE;

            commStateOK = commStateOK && SetCommState(g_mvciHandle, &dcb);

            commStateOK = commStateOK && EscapeCommFunction(g_mvciHandle, CLRRTS);
            Sleep(1);

            commStateOK = commStateOK &&  EscapeCommFunction(g_mvciHandle, SETDTR);
            Sleep(1);

            commStateOK = commStateOK &&  EscapeCommFunction(g_mvciHandle, CLRDTR);
        }

        if(!commStateOK)
            goto cleanup;
    } // Win32 API
    
    Sleep(MVCI_RESET_SLEEP);

    *pDeviceID = g_deviceID;

    unsigned char cmdBuf[BUF_SIZE];
    cmdBuf[0] = 0x03;
    cmdBuf[1] = 0x00;
    cmdBuf[2] = 0x03;
    writeBytes(cmdBuf, 3);
    Sleep(100);
    
    g_mvci_isOpen = TRUE;
    g_numChannels = 0;
    g_numFilters = 0;
    g_numPerMsgs = 0;

#ifndef MVCI_NOCRYPT
    cmdBuf[0] = MVCI_OPEN_ENC;
    memcpy_s(cmdBuf + 1, sizeof(cmdBuf) - 1, mvciName, sizeof(mvciName));
    sendRequest(cmdBuf, sizeof(mvciName) + 1, FALSE);
    unsigned char respBuf[BUF_SIZE];
    unsigned int respLen;
    readResponse(respBuf, sizeof(respBuf), &respLen, FALSE, MVCI_TIMEOUT);
    if(respLen > 8)
    {
        if(respBuf[0] == 1)
        {
            unsigned char DES_key[8];
            memcpy_s(DES_key, 8, respBuf + 1, 8);
            DES_init(DES_key);
            
            PT_RETURN(STATUS_NOERROR);
        }
    }

#else

    PT_RETURN(STATUS_NOERROR);

#endif

cleanup:

    g_mvci_isOpen = FALSE;
    g_deviceID = 0;
    *pDeviceID = g_deviceID;

    if(g_useD2XX)
    {
        d2xxCleanup();
    }
    else
    {
        if(g_mvciHandle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(g_mvciHandle);
            g_mvciHandle = INVALID_HANDLE_VALUE;
        }
    }

    PT_RETURN(ERR_DEVICE_NOT_CONNECTED);        
}

__declspec(dllexport)
long WINAPI PassThruClose(unsigned long DeviceID)
{
    if(!g_mvci_isOpen)
        PT_RETURN(ERR_DEVICE_NOT_CONNECTED);
        
    if(DeviceID != g_deviceID)
        PT_RETURN(ERR_INVALID_DEVICE_ID);
    
    unsigned char cmdBuf[BUF_SIZE];
    cmdBuf[0] = MVCI_CLOSE_ENC;
    sendRequest(cmdBuf, 1, TRUE);
    unsigned char respBuf[BUF_SIZE];
    unsigned int respLen;
    readResponse(respBuf, sizeof(respBuf), &respLen, FALSE, MVCI_TIMEOUT);

    if(g_useD2XX)
    {
        ftClose(g_mvciFTHandle);
        g_mvciFTHandle = INVALID_HANDLE_VALUE;
        if(g_hFTD2XX)
        {
            FreeLibrary(g_hFTD2XX);
            g_hFTD2XX = NULL;
        }

        ftOpenEx = NULL;
        ftClose = NULL;
        ftRead = NULL;
        ftWrite = NULL;
        ftSetBaudRate = NULL;
        ftSetDataCharacteristics = NULL;
        ftSetTimeouts = NULL;
        ftSetFlowControl = NULL;
        ftSetDtr = NULL;
        ftClrDtr = NULL;
        ftSetRts = NULL;
        ftClrRts = NULL;
    }
    else
    {
        CloseHandle(g_mvciHandle);
        g_mvciHandle = INVALID_HANDLE_VALUE;
    }
        
    g_mvci_isOpen = FALSE;
    g_deviceID = 0;
    g_numChannels = 0;
    g_numFilters = 0;
    g_numPerMsgs = 0;

    PT_RETURN(STATUS_NOERROR);
}

__declspec(dllexport)
long WINAPI PassThruReadVersion(unsigned long DeviceID, char *pFirmwareVersion, char *pDllVersion, char *pApiVersion)
{
    if(!g_mvci_isOpen)
        PT_RETURN(ERR_DEVICE_NOT_CONNECTED);

    if(DeviceID != g_deviceID)
        PT_RETURN(ERR_INVALID_DEVICE_ID);
        
    unsigned char cmdBuf[BUF_SIZE];
    cmdBuf[0] = MVCI_READVERSION;
    sendRequest(cmdBuf, 1, TRUE);
    unsigned char respBuf[BUF_SIZE];
    unsigned int respLen;
    readResponse(respBuf, sizeof(respBuf), &respLen, TRUE, MVCI_TIMEOUT);
    if(respLen > 1)
    {
        if(respLen > J2534_MAX_STR_SIZE)
            respLen = J2534_MAX_STR_SIZE;
            
        memcpy_s(pFirmwareVersion, J2534_MAX_STR_SIZE, respBuf + 1, respLen - 1);
        pFirmwareVersion[respLen - 1] = '\0';
    }
    
    strcpy_s(pDllVersion, J2534_MAX_STR_SIZE, g_DllVersion);
    strcpy_s(pApiVersion, J2534_MAX_STR_SIZE, g_ApiVersion);

    PT_RETURN(STATUS_NOERROR);
}

__declspec(dllexport)
long WINAPI PassThruConnect(unsigned long DeviceID, unsigned long ProtocolID, unsigned long Flags, unsigned long BaudRate, unsigned long *pChannelID)
{
    if(!g_mvci_isOpen)
        PT_RETURN(ERR_DEVICE_NOT_CONNECTED);

    if(DeviceID != g_deviceID)
        PT_RETURN(ERR_INVALID_DEVICE_ID);

    if(g_numChannels >= MAX_CHANNELS)
        PT_RETURN(ERR_INVALID_PROTOCOL_ID);
    
    for(int c = 0; c < g_numChannels; c++)
        if(g_protocolIDs[c] == ProtocolID) PT_RETURN(ERR_CHANNEL_IN_USE);
    
    unsigned char cmdBuf[BUF_SIZE];
    cmdBuf[0] = MVCI_CONNECT;

    cmdBuf[1] = ProtocolID & 0xFF;
    cmdBuf[2] = (ProtocolID >> 8) & 0xFF;
    cmdBuf[3] = (ProtocolID >> 16) & 0xFF;
    cmdBuf[4] = (ProtocolID >> 24) & 0xFF;

    cmdBuf[5] = Flags & 0xFF;
    cmdBuf[6] = (Flags >> 8) & 0xFF;
    cmdBuf[7] = (Flags >> 16) & 0xFF;
    cmdBuf[8] = (Flags >> 24) & 0xFF;

    cmdBuf[9] = BaudRate & 0xFF;
    cmdBuf[10] = (BaudRate >> 8) & 0xFF;
    cmdBuf[11] = (BaudRate >> 16) & 0xFF;
    cmdBuf[12] = (BaudRate >> 24) & 0xFF;

    sendRequest(cmdBuf, 13, TRUE);
    unsigned char respBuf[BUF_SIZE];
    unsigned int respLen;
    readResponse(respBuf, sizeof(respBuf), &respLen, TRUE, MVCI_TIMEOUT);
    if(respLen == 2)
    {
        if(respBuf[1] != 0)
            PT_RETURN(respBuf[1]);
        
        g_channelIDs[g_numChannels] = GetTickCount();
        g_protocolIDs[g_numChannels] = ProtocolID;
        
        *pChannelID = g_channelIDs[g_numChannels];
        
        g_numChannels += 1;
        
        PT_RETURN(STATUS_NOERROR);
    }

    PT_RETURN(ERR_FAILED);
}

__declspec(dllexport)
long WINAPI PassThruDisconnect(unsigned long ChannelID)
{
    if(!g_mvci_isOpen)
        PT_RETURN(ERR_DEVICE_NOT_CONNECTED);

    if(ChannelID == 0)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);

    int c;
    for(c = 0; c < g_numChannels; c++)
        if(g_channelIDs[c] == ChannelID) break;
    
    if(c >= g_numChannels)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);
        
    unsigned char cmdBuf[BUF_SIZE];
    cmdBuf[0] = MVCI_DISCONNECT;

    unsigned long protocolID = g_protocolIDs[c];
    cmdBuf[1] = protocolID & 0xFF;
    cmdBuf[2] = (protocolID >> 8) & 0xFF;
    cmdBuf[3] = (protocolID >> 16) & 0xFF;
    cmdBuf[4] = (protocolID >> 24) & 0xFF;
    
    sendRequest(cmdBuf, 5, TRUE);
    unsigned char respBuf[BUF_SIZE];
    unsigned int respLen;
    readResponse(respBuf, sizeof(respBuf), &respLen, TRUE, MVCI_TIMEOUT);
    if(respLen == 2)
    {
        if(respBuf[1] != 0)
            PT_RETURN(respBuf[1]);
        
        g_numChannels -= 1;
        for(int i = c; i < g_numChannels; i++)
        {
            g_channelIDs[i] = g_channelIDs[i+1];
            g_protocolIDs[i] = g_protocolIDs[i+1];
        }

        for(int i = g_numChannels; i < MAX_CHANNELS; i++)
        {
            g_channelIDs[i] = 0;
            g_protocolIDs[i] = 0;
        }

        // Remove any filter IDs associated with the channel's protocol ID
        
        int f = 0;
        while(f < g_numFilters)
        {
            if(g_filterProtocolIDs[f] == protocolID)
            {
                g_numFilters -= 1;
                for(int i = f; i < g_numFilters; i++)
                {
                    g_filterIDs[i] = g_filterIDs[i+1];
                    g_filterProtocolIDs[i] = g_filterProtocolIDs[i+1];
                }
            }
            else
            {
                f += 1;
            }
        }

        for(int i = g_numFilters; i < MAX_FILTERS; i++)
        {
            g_filterIDs[i] = 0;
            g_filterProtocolIDs[i] = 0;
        }

        // Remove any periodic message IDs associated with the channel's protocol ID
        
        int m = 0;
        while(m < g_numPerMsgs)
        {
            if(g_perMsgProtocolIDs[m] == protocolID)
            {
                g_numPerMsgs -= 1;
                for(int i = m; i < g_numPerMsgs; i++)
                {
                    g_perMsgIDs[i] = g_perMsgIDs[i+1];
                    g_perMsgProtocolIDs[i] = g_perMsgProtocolIDs[i+1];
                }
            }
            else
            {
                m += 1;
            }
        }

        for(int i = g_numPerMsgs; i < MAX_PER_MSGS; i++)
        {
            g_perMsgIDs[i] = 0;
            g_perMsgProtocolIDs[i] = 0;
        }

        PT_RETURN(STATUS_NOERROR);
    }

    PT_RETURN(ERR_FAILED);
}

__declspec(dllexport)
long WINAPI PassThruGetLastError(char *pErrorDescription)
{
    long error = g_lastError;
    if(error > (sizeof(g_errorStrings) / sizeof(g_errorStrings[0])))
        error = ERR_FAILED;
    
    strcpy_s(pErrorDescription, J2534_MAX_STR_SIZE, g_errorStrings[error]);
    return STATUS_NOERROR;
}

__declspec(dllexport)
long WINAPI PassThruReadMsgs(unsigned long ChannelID, PASSTHRU_MSG *pMsg, unsigned long *pNumMsgs, unsigned long Timeout)
{
    if(!g_mvci_isOpen)
        PT_RETURN(ERR_DEVICE_NOT_CONNECTED);

    if(ChannelID == 0)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);

    if(*pNumMsgs < 1)
        PT_RETURN(STATUS_NOERROR);
        
    int c;
    for(c = 0; c < g_numChannels; c++)
        if(g_channelIDs[c] == ChannelID) break;
    
    if(c >= g_numChannels)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);
        
    unsigned char cmdBuf[BUF_SIZE];
    cmdBuf[0] = MVCI_READMSG;

    unsigned long protocolID = g_protocolIDs[c];
    cmdBuf[1] = protocolID & 0xFF;
    cmdBuf[2] = (protocolID >> 8) & 0xFF;
    cmdBuf[3] = (protocolID >> 16) & 0xFF;
    cmdBuf[4] = (protocolID >> 24) & 0xFF;
    
    unsigned long nMsgsRead = 0;
    long status = STATUS_NOERROR;
    do
    {
        sendRequest(cmdBuf, 5, TRUE);
        unsigned char respBuf[BUF_SIZE];
        unsigned int respLen;
        readResponse(respBuf, sizeof(respBuf), &respLen, TRUE, MVCI_TIMEOUT);
        if(respLen < 9) // Cmd + RxStatus + ExtraDataIndex
        {
            if(respLen == 2)
                status = respBuf[1];
            else
                status = ERR_FAILED;
        }
        else
        {
            PASSTHRU_MSG *passThruMsg = &pMsg[nMsgsRead];
            passThruMsg->ProtocolID = protocolID;
            passThruMsg->RxStatus = respBuf[1] |
                                    (respBuf[2] << 8) |
                                    (respBuf[3] << 16) |
                                    (respBuf[4] << 24);
            passThruMsg->Timestamp = GetTickCount() * 1000; // Message timestamp in microseconds
            passThruMsg->DataSize = respLen - 9;
            passThruMsg->ExtraDataIndex = respBuf[5] |
                                        (respBuf[6] << 8) |
                                        (respBuf[7] << 16) |
                                        (respBuf[8] << 24);
            memcpy_s(passThruMsg->Data, MAX_PT_MSG_SIZE, respBuf + 9, respLen - 9);
            
            nMsgsRead += 1;
        }
    }
    while((nMsgsRead < *pNumMsgs) && (status == STATUS_NOERROR));
    *pNumMsgs = nMsgsRead;

    if((status == ERR_BUFFER_EMPTY) && (nMsgsRead > 0))
        PT_RETURN(STATUS_NOERROR);

    PT_RETURN(status);
}

__declspec(dllexport)
long WINAPI PassThruStartMsgFilter(unsigned long ChannelID, unsigned long FilterType, PASSTHRU_MSG *pMaskMsg, PASSTHRU_MSG *pPatternMsg, PASSTHRU_MSG *pFlowControlMsg, unsigned long *pMsgID)
{
    if(!g_mvci_isOpen)
        PT_RETURN(ERR_DEVICE_NOT_CONNECTED);

    if(ChannelID == 0)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);

    if(g_numFilters >= MAX_FILTERS)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);

    int c;
    for(c = 0; c < g_numChannels; c++)
        if(g_channelIDs[c] == ChannelID) break;
    
    if(c >= g_numChannels)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);
    
    if(c >= g_numChannels)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);
        
    // Need to fit 3 messages into buffer
    unsigned char cmdBuf[BUF_SIZE * 3];
    memset(cmdBuf, 0, sizeof(cmdBuf));
    cmdBuf[0] = MVCI_STARTMSGFILTER;

    unsigned long protocolID = g_protocolIDs[c];
    cmdBuf[1] = protocolID & 0xFF;
    cmdBuf[2] = (protocolID >> 8) & 0xFF;
    cmdBuf[3] = (protocolID >> 16) & 0xFF;
    cmdBuf[4] = (protocolID >> 24) & 0xFF;

    unsigned long filterID = GetTickCount();
    cmdBuf[5] = filterID & 0xFF;
    cmdBuf[6] = (filterID >> 8) & 0xFF;
    cmdBuf[7] = (filterID >> 16) & 0xFF;
    cmdBuf[8] = (filterID >> 24) & 0xFF;

    cmdBuf[9] = FilterType & 0xFF;
    cmdBuf[10] = (FilterType >> 8) & 0xFF;
    cmdBuf[11] = (FilterType >> 16) & 0xFF;
    cmdBuf[12] = (FilterType >> 24) & 0xFF;

    unsigned long maxMsgLen = 0;
    if(pMaskMsg && (pMaskMsg->DataSize > maxMsgLen))
        maxMsgLen = pPatternMsg->DataSize;
    if(pPatternMsg && (pPatternMsg->DataSize > maxMsgLen))
        maxMsgLen = pPatternMsg->DataSize;
    if(pFlowControlMsg && (pFlowControlMsg->DataSize > maxMsgLen))
        maxMsgLen = pPatternMsg->DataSize;
    
    if((maxMsgLen < 1) || (maxMsgLen > MAX_PT_MSG_SIZE))
        PT_RETURN(ERR_INVALID_MSG);
    
    if(pMaskMsg)
        memcpy_s(cmdBuf + 13, MAX_PT_MSG_SIZE, pMaskMsg->Data, pMaskMsg->DataSize);
        
    if(pPatternMsg)
        memcpy_s(cmdBuf + 13 + maxMsgLen, MAX_PT_MSG_SIZE, pPatternMsg->Data, pPatternMsg->DataSize);
        
    if(pFlowControlMsg)
        memcpy_s(cmdBuf + 13 + (maxMsgLen * 2), MAX_PT_MSG_SIZE, pFlowControlMsg->Data, pFlowControlMsg->DataSize);
        
    sendRequest(cmdBuf, 13 + (maxMsgLen * 3), TRUE);
    unsigned char respBuf[BUF_SIZE];
    unsigned int respLen;
    readResponse(respBuf, sizeof(respBuf), &respLen, TRUE, MVCI_TIMEOUT);

    if(respLen == 2)
    {
        if(respBuf[1] != STATUS_NOERROR)
            PT_RETURN(respBuf[1]);
        
        g_filterIDs[g_numFilters] = filterID;
        g_filterProtocolIDs[g_numFilters] = protocolID;
        *pMsgID = filterID;
        
        g_numFilters += 1;
        
        PT_RETURN(STATUS_NOERROR);
    }

    PT_RETURN(ERR_FAILED);
}

__declspec(dllexport)
long WINAPI PassThruStopMsgFilter(unsigned long ChannelID, unsigned long MsgID)
{
    if(!g_mvci_isOpen)
        PT_RETURN(ERR_DEVICE_NOT_CONNECTED);

    if(ChannelID == 0)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);

    if((MsgID == 0) || (g_numFilters < 1))
        PT_RETURN(ERR_INVALID_FILTER_ID);

    int c;
    for(c = 0; c < g_numChannels; c++)
        if(g_channelIDs[c] == ChannelID) break;
    
    if(c >= g_numChannels)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);

    unsigned long protocolID = g_protocolIDs[c];

    int f;
    for(f = 0; f < g_numFilters; f++)
        if(g_filterIDs[f] == MsgID) break;
    
    if(f >= g_numFilters)
        PT_RETURN(ERR_INVALID_FILTER_ID);

    if(g_filterProtocolIDs[f] != protocolID)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);
    
    unsigned char cmdBuf[BUF_SIZE];
    cmdBuf[0] = MVCI_STOPMSGFILTER;

    cmdBuf[1] = protocolID & 0xFF;
    cmdBuf[2] = (protocolID >> 8) & 0xFF;
    cmdBuf[3] = (protocolID >> 16) & 0xFF;
    cmdBuf[4] = (protocolID >> 24) & 0xFF;

    cmdBuf[5] = MsgID & 0xFF;
    cmdBuf[6] = (MsgID >> 8) & 0xFF;
    cmdBuf[7] = (MsgID >> 16) & 0xFF;
    cmdBuf[8] = (MsgID >> 24) & 0xFF;

    sendRequest(cmdBuf, 9, TRUE);
    unsigned char respBuf[BUF_SIZE];
    unsigned int respLen;
    readResponse(respBuf, sizeof(respBuf), &respLen, TRUE, MVCI_TIMEOUT);

    if(respLen == 2)
    {
        if(respBuf[1] != STATUS_NOERROR)
            PT_RETURN(respBuf[1]);
        
        g_numFilters -= 1;
        for(int i = f; i < g_numFilters; i++)
        {
            g_filterIDs[i] = g_filterIDs[i+1];
            g_filterProtocolIDs[i] = g_filterProtocolIDs[i+1];
        }

        for(int i = g_numFilters; i < MAX_FILTERS; i++)
        {
            g_filterIDs[i] = 0;
            g_filterProtocolIDs[i] = 0;
        }
        
        PT_RETURN(STATUS_NOERROR);
    }

    PT_RETURN(ERR_FAILED);
}

__declspec(dllexport)
long WINAPI PassThruWriteMsgs(unsigned long ChannelID, PASSTHRU_MSG *pMsg, unsigned long *pNumMsgs, unsigned long Timeout)
{
    if(!g_mvci_isOpen)
        PT_RETURN(ERR_DEVICE_NOT_CONNECTED);

    if(ChannelID == 0)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);

    if(*pNumMsgs < 1)
        PT_RETURN(STATUS_NOERROR);
        
    int c;
    for(c = 0; c < g_numChannels; c++)
        if(g_channelIDs[c] == ChannelID) break;
    
    if(c >= g_numChannels)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);
        
    unsigned char cmdBuf[BUF_SIZE];
    cmdBuf[0] = MVCI_WRITEMSG;

    unsigned long protocolID = g_protocolIDs[c];
    cmdBuf[1] = protocolID & 0xFF;
    cmdBuf[2] = (protocolID >> 8) & 0xFF;
    cmdBuf[3] = (protocolID >> 16) & 0xFF;
    cmdBuf[4] = (protocolID >> 24) & 0xFF;
    
    unsigned long nMsgsWritten = 0;
    long status = STATUS_NOERROR;
    do
    {
        PASSTHRU_MSG *passThruMsg = &pMsg[nMsgsWritten];
        if(passThruMsg->ProtocolID != protocolID)
            PT_RETURN(ERR_MSG_PROTOCOL_ID);
        
        if(passThruMsg->DataSize > MAX_PT_MSG_SIZE)
            PT_RETURN(ERR_INVALID_MSG);
        
        cmdBuf[5] = passThruMsg->TxFlags & 0xFF;
        cmdBuf[6] = (passThruMsg->TxFlags >> 8) & 0xFF;
        cmdBuf[7] = (passThruMsg->TxFlags >> 16) & 0xFF;
        cmdBuf[8] = (passThruMsg->TxFlags >> 24) & 0xFF;
        
        memcpy_s(cmdBuf + 9, MAX_PT_MSG_SIZE, passThruMsg->Data, passThruMsg->DataSize);

        sendRequest(cmdBuf, 9 + passThruMsg->DataSize, TRUE);
        unsigned char respBuf[BUF_SIZE];
        unsigned int respLen;
        readResponse(respBuf, sizeof(respBuf), &respLen, TRUE, MVCI_TIMEOUT);

        if(respLen == 2)
            status = respBuf[1];
        else
            status = ERR_FAILED;

        if(status == STATUS_NOERROR)
            nMsgsWritten += 1;
    }
    while((nMsgsWritten < *pNumMsgs) && (status == STATUS_NOERROR));
    *pNumMsgs = nMsgsWritten;

    PT_RETURN(status);
}

__declspec(dllexport)
long WINAPI PassThruStartPeriodicMsg(unsigned long ChannelID, PASSTHRU_MSG *pMsg, unsigned long *pMsgID, unsigned long TimeInterval)
{
    if(!g_mvci_isOpen)
        PT_RETURN(ERR_DEVICE_NOT_CONNECTED);

    if(ChannelID == 0)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);

    if(g_numPerMsgs >= MAX_PER_MSGS)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);
            
    int c;
    for(c = 0; c < g_numChannels; c++)
        if(g_channelIDs[c] == ChannelID) break;
    
    if(c >= g_numChannels)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);

    if(pMsg->DataSize > MAX_PT_MSG_SIZE)
        PT_RETURN(ERR_INVALID_MSG);
    
    unsigned char cmdBuf[BUF_SIZE];
    cmdBuf[0] = MVCI_STARTPERIODICMSG;

    unsigned long protocolID = g_protocolIDs[c];
    
    if(pMsg->ProtocolID != protocolID)
        PT_RETURN(ERR_MSG_PROTOCOL_ID);
    
    cmdBuf[1] = protocolID & 0xFF;
    cmdBuf[2] = (protocolID >> 8) & 0xFF;
    cmdBuf[3] = (protocolID >> 16) & 0xFF;
    cmdBuf[4] = (protocolID >> 24) & 0xFF;

    *pMsgID = GetTickCount();
    cmdBuf[5] = *pMsgID & 0xFF;
    cmdBuf[6] = (*pMsgID >> 8) & 0xFF;
    cmdBuf[7] = (*pMsgID >> 16) & 0xFF;
    cmdBuf[8] = (*pMsgID >> 24) & 0xFF;

    cmdBuf[9] = pMsg->TxFlags & 0xFF;
    cmdBuf[10] = (pMsg->TxFlags >> 8) & 0xFF;
    cmdBuf[11] = (pMsg->TxFlags >> 16) & 0xFF;
    cmdBuf[12] = (pMsg->TxFlags >> 24) & 0xFF;

    cmdBuf[13] = TimeInterval & 0xFF;
    cmdBuf[14] = (TimeInterval >> 8) & 0xFF;
    cmdBuf[15] = (TimeInterval >> 16) & 0xFF;
    cmdBuf[16] = (TimeInterval >> 24) & 0xFF;

    memcpy_s(cmdBuf + 17, MAX_PT_MSG_SIZE, pMsg->Data, pMsg->DataSize);

    sendRequest(cmdBuf, 17 + pMsg->DataSize, TRUE);
    unsigned char respBuf[BUF_SIZE];
    unsigned int respLen;
    readResponse(respBuf, sizeof(respBuf), &respLen, TRUE, MVCI_TIMEOUT);

    if(respLen == 2)
    {
        if(respBuf[1] == STATUS_NOERROR)
        {
            g_perMsgIDs[g_numPerMsgs] = *pMsgID;
            g_perMsgProtocolIDs[g_numPerMsgs] = protocolID;
            
            g_numPerMsgs += 1;
        }
        
        PT_RETURN(respBuf[1]);
    }

    PT_RETURN(ERR_FAILED);
}

__declspec(dllexport)
long WINAPI PassThruStopPeriodicMsg(unsigned long ChannelID, unsigned long MsgID)
{
    if(!g_mvci_isOpen)
        PT_RETURN(ERR_DEVICE_NOT_CONNECTED);

    if(ChannelID == 0)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);

    if((MsgID == 0) || (g_numPerMsgs < 1))
        PT_RETURN(ERR_INVALID_MSG_ID);

    int c;
    for(c = 0; c < g_numChannels; c++)
        if(g_channelIDs[c] == ChannelID) break;
    
    if(c >= g_numChannels)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);

    unsigned long protocolID = g_protocolIDs[c];

    int m;
    for(m = 0; m < g_numPerMsgs; m++)
        if(g_perMsgIDs[m] == MsgID) break;
    
    if(m >= g_numPerMsgs)
        PT_RETURN(ERR_INVALID_MSG_ID);

    if(g_perMsgProtocolIDs[m] != protocolID)
        PT_RETURN(ERR_INVALID_CHANNEL_ID);
    
    unsigned char cmdBuf[BUF_SIZE];
    cmdBuf[0] = MVCI_STOPPERIODICMSG;

    cmdBuf[1] = protocolID & 0xFF;
    cmdBuf[2] = (protocolID >> 8) & 0xFF;
    cmdBuf[3] = (protocolID >> 16) & 0xFF;
    cmdBuf[4] = (protocolID >> 24) & 0xFF;

    cmdBuf[5] = MsgID & 0xFF;
    cmdBuf[6] = (MsgID >> 8) & 0xFF;
    cmdBuf[7] = (MsgID >> 16) & 0xFF;
    cmdBuf[8] = (MsgID >> 24) & 0xFF;

    sendRequest(cmdBuf, 9, TRUE);
    unsigned char respBuf[BUF_SIZE];
    unsigned int respLen;
    readResponse(respBuf, sizeof(respBuf), &respLen, TRUE, MVCI_TIMEOUT);

    if(respLen == 2)
    {
        if(respBuf[1] != STATUS_NOERROR)
            PT_RETURN(respBuf[1]);
        
        g_numPerMsgs -= 1;
        for(int i = m; i < g_numPerMsgs; i++)
        {
            g_perMsgIDs[i] = g_perMsgIDs[i+1];
            g_perMsgProtocolIDs[i] = g_perMsgProtocolIDs[i+1];
        }

        for(int i = g_numPerMsgs; i < MAX_PER_MSGS; i++)
        {
            g_perMsgIDs[i] = 0;
            g_perMsgProtocolIDs[i] = 0;
        }
        
        PT_RETURN(STATUS_NOERROR);
    }

    PT_RETURN(ERR_FAILED);
}

__declspec(dllexport)
long WINAPI PassThruIoctl(unsigned long HandleID, unsigned long IoctlID, void *pInput, void *pOutput)
{
    unsigned char cmdBuf[BUF_SIZE], respBuf[BUF_SIZE];
    unsigned int respLen;
    
    if(!g_mvci_isOpen)
        PT_RETURN(ERR_DEVICE_NOT_CONNECTED);

    cmdBuf[0] = MVCI_IOCTL;
    cmdBuf[1] = IoctlID;
    
    if((IoctlID == READ_VBATT) || (IoctlID == READ_PROG_VOLTAGE))
    {
        if(HandleID != g_deviceID)
            PT_RETURN(ERR_INVALID_DEVICE_ID);

        if(!pOutput)
            PT_RETURN(ERR_NULL_PARAMETER);
        
        sendRequest(cmdBuf, 2, TRUE);
        readResponse(respBuf, sizeof(respBuf), &respLen, TRUE, MVCI_TIMEOUT);

        if(respLen == 2)
            PT_RETURN(respBuf[1]);

        if(respLen == 5)
        {
            // Response data is voltage
            
            *(unsigned long *)pOutput =
                        respBuf[1] |
                        (respBuf[2] << 8) |
                        (respBuf[3] << 16) |
                        (respBuf[4] << 24);

            PT_RETURN(STATUS_NOERROR);
        }

        PT_RETURN(ERR_FAILED);
    }
        
    if(IoctlID == GET_CONFIG)
    {
        if(HandleID == 0)
            PT_RETURN(ERR_INVALID_CHANNEL_ID);

        int c;
        for(c = 0; c < g_numChannels; c++)
            if(g_channelIDs[c] == HandleID) break;
        
        if(c >= g_numChannels)
            PT_RETURN(ERR_INVALID_CHANNEL_ID);

        unsigned long protocolID = g_protocolIDs[c];
        cmdBuf[2] = protocolID & 0xFF;
        cmdBuf[3] = (protocolID >> 8) & 0xFF;
        cmdBuf[4] = (protocolID >> 16) & 0xFF;
        cmdBuf[5] = (protocolID >> 24) & 0xFF;

        if(!pInput)
            PT_RETURN(ERR_NULL_PARAMETER);
        
        // One request for each parameter in list
        
        SCONFIG_LIST *sConfigList = (SCONFIG_LIST *)pInput;
        for(int i = 0; i < sConfigList->NumOfParams; i++)
        {
            SCONFIG *sConfig = (SCONFIG *)sConfigList[i].ConfigPtr;
            cmdBuf[6] = sConfig->Parameter & 0xFF;
            cmdBuf[7] = (sConfig->Parameter >> 8) & 0xFF;
            cmdBuf[8] = (sConfig->Parameter >> 16) & 0xFF;
            cmdBuf[9] = (sConfig->Parameter >> 24) & 0xFF;

            sendRequest(cmdBuf, 10, TRUE);
            readResponse(respBuf, sizeof(respBuf), &respLen, TRUE, MVCI_TIMEOUT);

            if(respLen == 2)
                PT_RETURN(respBuf[1]);

            if(respLen == 5)
            {
                // Response data is parameter value
                
                sConfig->Value =
                            respBuf[1] |
                            (respBuf[2] << 8) |
                            (respBuf[3] << 16) |
                            (respBuf[4] << 24);
            }
        }

        PT_RETURN(STATUS_NOERROR);
    }

    if(IoctlID == SET_CONFIG)
    {
        if(HandleID == 0)
            PT_RETURN(ERR_INVALID_CHANNEL_ID);

        int c;
        for(c = 0; c < g_numChannels; c++)
            if(g_channelIDs[c] == HandleID) break;
        
        if(c >= g_numChannels)
            PT_RETURN(ERR_INVALID_CHANNEL_ID);

        unsigned long protocolID = g_protocolIDs[c];
        cmdBuf[2] = protocolID & 0xFF;
        cmdBuf[3] = (protocolID >> 8) & 0xFF;
        cmdBuf[4] = (protocolID >> 16) & 0xFF;
        cmdBuf[5] = (protocolID >> 24) & 0xFF;

        if(!pInput)
            PT_RETURN(ERR_NULL_PARAMETER);
        
        // One request for each parameter in list
        
        SCONFIG_LIST *sConfigList = (SCONFIG_LIST *)pInput;
        for(int i = 0; i < sConfigList->NumOfParams; i++)
        {
            SCONFIG *sConfig = (SCONFIG *)sConfigList[i].ConfigPtr;
            cmdBuf[6] = sConfig->Parameter & 0xFF;
            cmdBuf[7] = (sConfig->Parameter >> 8) & 0xFF;
            cmdBuf[8] = (sConfig->Parameter >> 16) & 0xFF;
            cmdBuf[9] = (sConfig->Parameter >> 24) & 0xFF;

            cmdBuf[10] = sConfig->Value & 0xFF;
            cmdBuf[11] = (sConfig->Value >> 8) & 0xFF;
            cmdBuf[12] = (sConfig->Value >> 16) & 0xFF;
            cmdBuf[13] = (sConfig->Value >> 24) & 0xFF;

            sendRequest(cmdBuf, 14, TRUE);
            readResponse(respBuf, sizeof(respBuf), &respLen, TRUE, MVCI_TIMEOUT);

            if(respLen != 2)
                PT_RETURN(ERR_FAILED);

            // Response data is status code
            
            if(respBuf[1] != STATUS_NOERROR)
                PT_RETURN(respBuf[1]);
        }

        PT_RETURN(STATUS_NOERROR);
    }

    if((IoctlID == CLEAR_TX_BUFFER) ||
        (IoctlID == CLEAR_RX_BUFFER) ||
        (IoctlID == CLEAR_PERIODIC_MSGS) ||
        (IoctlID == CLEAR_MSG_FILTERS) ||
        (IoctlID == CLEAR_FUNCT_MSG_LOOKUP_TABLE))
    {
        if(HandleID == 0)
            PT_RETURN(ERR_INVALID_CHANNEL_ID);

        int c;
        for(c = 0; c < g_numChannels; c++)
            if(g_channelIDs[c] == HandleID) break;
        
        if(c >= g_numChannels)
            PT_RETURN(ERR_INVALID_CHANNEL_ID);

        unsigned long protocolID = g_protocolIDs[c];
        cmdBuf[2] = protocolID & 0xFF;
        cmdBuf[3] = (protocolID >> 8) & 0xFF;
        cmdBuf[4] = (protocolID >> 16) & 0xFF;
        cmdBuf[5] = (protocolID >> 24) & 0xFF;

        sendRequest(cmdBuf, 6, TRUE);
        readResponse(respBuf, sizeof(respBuf), &respLen, TRUE, MVCI_TIMEOUT);

        if(respLen != 2)
            PT_RETURN(ERR_FAILED);

        // Response data is status code
        
        PT_RETURN(respBuf[1]);
    }
    
    if((IoctlID == FIVE_BAUD_INIT) || (IoctlID == FAST_INIT))
    {
        if(HandleID == 0)
            PT_RETURN(ERR_INVALID_CHANNEL_ID);

        int c;
        for(c = 0; c < g_numChannels; c++)
            if(g_channelIDs[c] == HandleID) break;
        
        if(c >= g_numChannels)
            PT_RETURN(ERR_INVALID_CHANNEL_ID);

        unsigned long protocolID = g_protocolIDs[c];
        cmdBuf[2] = protocolID & 0xFF;
        cmdBuf[3] = (protocolID >> 8) & 0xFF;
        cmdBuf[4] = (protocolID >> 16) & 0xFF;
        cmdBuf[5] = (protocolID >> 24) & 0xFF;

        if(!pInput || !pOutput)
            PT_RETURN(ERR_NULL_PARAMETER);
        
        unsigned long dataLen;
        unsigned char *srcBuf;
        if(IoctlID == FIVE_BAUD_INIT)
        {
            dataLen = ((SBYTE_ARRAY *)pInput)->NumOfBytes;
            srcBuf = ((SBYTE_ARRAY *)pInput)->BytePtr;
        }

        if(IoctlID == FAST_INIT)
        {
            if(((PASSTHRU_MSG *)pInput)->ProtocolID != protocolID)
                PT_RETURN(ERR_MSG_PROTOCOL_ID);
            
            dataLen = ((PASSTHRU_MSG *)pInput)->DataSize;
            srcBuf = ((PASSTHRU_MSG *)pInput)->Data;
        }
        
        if(dataLen > MAX_PT_MSG_SIZE)
            PT_RETURN(ERR_INVALID_MSG);
        
        memcpy_s(cmdBuf + 6, MAX_PT_MSG_SIZE, srcBuf, dataLen);
        sendRequest(cmdBuf, 6 + dataLen, TRUE);
        readResponse(respBuf, sizeof(respBuf), &respLen, TRUE, MVCI_TIMEOUT);
        
        if(respLen == 2)
            PT_RETURN(respBuf[1]);
        
        if(respLen > 2)
        {
            dataLen = respLen - 1;
            unsigned char *destBuf;
            if(IoctlID == FIVE_BAUD_INIT)
            {
                destBuf = ((SBYTE_ARRAY *)pInput)->BytePtr;

                if(dataLen > ((SBYTE_ARRAY *)pInput)->NumOfBytes)
                    dataLen = ((SBYTE_ARRAY *)pInput)->NumOfBytes;
                else
                    ((SBYTE_ARRAY *)pInput)->NumOfBytes = dataLen;
            }

            if(IoctlID == FAST_INIT)
            {
                if(dataLen > ((PASSTHRU_MSG *)pInput)->DataSize)
                    dataLen = ((PASSTHRU_MSG *)pInput)->DataSize;
                else
                    ((PASSTHRU_MSG *)pInput)->DataSize = dataLen;
                
                ((PASSTHRU_MSG *)pInput)->ExtraDataIndex = 0;

                destBuf = ((PASSTHRU_MSG *)pInput)->Data;
            }
            
            memcpy_s(destBuf, dataLen, respBuf + 1, dataLen);
            
            PT_RETURN(STATUS_NOERROR);
        }
        
        PT_RETURN(ERR_FAILED);
    }
    
    if((IoctlID == ADD_TO_FUNCT_MSG_LOOKUP_TABLE) ||
        (IoctlID == DELETE_FROM_FUNCT_MSG_LOOKUP_TABLE))
    {
        if(HandleID == 0)
            PT_RETURN(ERR_INVALID_CHANNEL_ID);

        int c;
        for(c = 0; c < g_numChannels; c++)
            if(g_channelIDs[c] == HandleID) break;
        
        if(c >= g_numChannels)
            PT_RETURN(ERR_INVALID_CHANNEL_ID);

        unsigned long protocolID = g_protocolIDs[c];
        cmdBuf[2] = protocolID & 0xFF;
        cmdBuf[3] = (protocolID >> 8) & 0xFF;
        cmdBuf[4] = (protocolID >> 16) & 0xFF;
        cmdBuf[5] = (protocolID >> 24) & 0xFF;

        if(!pInput)
            PT_RETURN(ERR_NULL_PARAMETER);
        
        SBYTE_ARRAY *sByteArray = (SBYTE_ARRAY *)pInput;
        if((sByteArray->NumOfBytes < 1) || (sByteArray->NumOfBytes > MAX_PT_MSG_SIZE))
            PT_RETURN(ERR_INVALID_IOCTL_VALUE);
        
        memcpy_s(cmdBuf + 6, MAX_PT_MSG_SIZE, sByteArray->BytePtr, sByteArray->NumOfBytes);

        sendRequest(cmdBuf, 6 + sByteArray->NumOfBytes, TRUE);
        readResponse(respBuf, sizeof(respBuf), &respLen, TRUE, MVCI_TIMEOUT);

        if(respLen != 2)
            PT_RETURN(ERR_FAILED);

        // Response data is status code
        
        if(respBuf[1] != STATUS_NOERROR)
            PT_RETURN(respBuf[1]);
    }

    PT_RETURN(ERR_INVALID_IOCTL_ID);
}

__declspec(dllexport)
long WINAPI PassThruSetProgrammingVoltage(unsigned long DeviceID, unsigned long PinNumber, unsigned long Voltage)
{
    unsigned char cmdBuf[BUF_SIZE], respBuf[BUF_SIZE];
    unsigned int respLen;
    
    if(!g_mvci_isOpen)
        PT_RETURN(ERR_DEVICE_NOT_CONNECTED);

    if(DeviceID != g_deviceID)
        PT_RETURN(ERR_INVALID_DEVICE_ID);

    cmdBuf[0] = MVCI_SETPROGRAMMINGVOLTAGE;

    cmdBuf[1] = PinNumber & 0xFF;
    cmdBuf[2] = (PinNumber >> 8) & 0xFF;
    cmdBuf[3] = (PinNumber >> 16) & 0xFF;
    cmdBuf[4] = (PinNumber >> 24) & 0xFF;
    
    cmdBuf[5] = Voltage & 0xFF;
    cmdBuf[6] = (Voltage >> 8) & 0xFF;
    cmdBuf[7] = (Voltage >> 16) & 0xFF;
    cmdBuf[8] = (Voltage >> 24) & 0xFF;
    
    sendRequest(cmdBuf, 9, TRUE);
    readResponse(respBuf, sizeof(respBuf), &respLen, TRUE, MVCI_TIMEOUT);

    if(respLen == 2)
        PT_RETURN(respBuf[1]);

    PT_RETURN(ERR_FAILED);
}

/*BOOL WINAPI DllMain(HINSTANCE hinstDLL, _In_  DWORD fdwReason, _In_  LPVOID lpvReserved)
{
    HKEY hKey;
    LONG ret;

    switch(fdwReason) {
    case DLL_PROCESS_DETACH:
    break;
  }
  
  return TRUE;
}*/
