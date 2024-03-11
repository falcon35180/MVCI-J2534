# MINI-VCI J2534 DLL
J2534 library for MVCI devices
## Overview
This library implements the J2534 API for use with XHorse MINI-VCI (and clone) devices.

It was built with the MinGW GCC compiler on Linux. Testing was done using Wine and Windows 10 64-bit. The only external dependencies are the C runtime and standard Windows libraries, therefore I would not expect any major problems building with other compilers.

DES encryption/decryption code obtained from https://github.com/tarequeh/DES.
# Registry values
In accordance with the J2534 API specification, the values identifying the DLL to applications are stored under the `HKEY_LOCAL_MACHINE\Software\PassThruSupport.04.04\XHorse - MVCI` key.

There are several values under the `Parameters` subkey that can be used to control the behaviour of the DLL:
- `Comport` - the number of the COM serial port the device is connected to (if using the Win32 Comm functions). Required if `UseD2XX` parameter (see below) is zero.
- `USBDescription` - the USB description string of the device (used to open a handle to the device when using FTDI D2XX functions). Defaults to "M-VCI" if not set.
- `UseD2XX` - if set to non-zero (boolean TRUE), use the FTDI D2XX library to communicate with the device; if zero (boolean FALSE), use Win32 Comm functions. It's recommended to use D2XX on Windows and Comm functions on Linux. Defaults to zero if not set.
