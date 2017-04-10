/*

 This library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2.1 of the License, or (at your option) any later version.

 This library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public
 License along with this library; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA

*/
#define KeInitializeSpinLock(sl) {                    \
  *(sl) = 0;                                          \
}

#define AcquireXLock(gLock, oldValue, newValue) {     \
    PULONG _gLock_ = &(gLock);                        \
    __asm push ebx                                    \
    __asm mov  eax,newValue                           \
    __asm mov  ebx,_gLock_                            \
    __asm xchg eax,[ebx]                              \
    __asm mov oldValue,eax                            \
    __asm pop  ebx                                    \
}

#define KeReleaseSpinLock(sl, irql) {                 \
    ULONG isLocked;                                   \
    AcquireXLock(*(sl), isLocked, FALSE);             \
}

#define KeAcquireSpinLock(sl,irql) {                  \
    ULONG isLocked = TRUE;                            \
    while(isLocked) AcquireXLock(*(sl), isLocked, TRUE);\
}
