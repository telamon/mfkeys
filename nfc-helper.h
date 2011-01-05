/*  
    
    This file is a part of mfkeys

    Copyright (c) 2010 Christian Panton <christian@panton.org>

    mfkeys is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    mfkeys is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with mfkeys.  If not, see <http://www.gnu.org/licenses/>.
    
*/

#include <nfc/nfc.h>

#include "mifare.h"

bool mf_configure(nfc_device_t *reader);
bool mf_anticol(nfc_device_t *reader, nfc_target_info_t *target);
bool mf_checkkey(nfc_device_t *reader, byte_t *uid, uint8_t sector, uint8_t keytype, byte_t *key);
long long unsigned int bytes_to_num(byte_t* src, uint32_t len);
void hexprint(byte_t* data, uint8_t len);
bool mf_dumpsector(nfc_device_t *reader, uint8_t sector, byte_t** data, uint8_t* datalen);
