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

#define MFCUK_DARKSIDE_MAX_LEVELS       8

#define MFCUK_DARKSIDE_START_NR         0xDEADBEEF
#define MFCUK_DARKSIDE_START_AR         0xFACECAFE

#define MAX_TAG_NONCES                  65536
#define MAX_COMMON_PREFIX_STATES        (1<<20)

#define MAX_FRAME_LEN       264

#define DEFAULT_SETS_NR         5
#define DEFAULT_PROBES_NR       150
#define DEFAULT_TOLERANCE       20
#define DEFAULT_DIST_NR         15

#define TRY_KEYS                50
#define MEM_CHUNK               10000

#define odd_parity(i) (( (i) ^ (i)>>1 ^ (i)>>2 ^ (i)>>3 ^ (i)>>4 ^ (i)>>5 ^ (i)>>6 ^ (i)>>7 ^ 1) & 0x01)

typedef enum {
    keyA = 0x60,
    keyB = 0x61,
} mifare_key_type;

typedef struct {
        uint32_t       *distances;
        uint32_t       median;
        uint32_t       num_distances;
        uint32_t       tolerance;
        byte_t          parity[3];              // used for 3 bits of parity information
} denonce;                                      // Revealed information about nonce 

typedef struct {
        uint64_t        key;
        int             count;
} countKeys;

typedef struct {
        uint64_t        *possibleKeys;
        uint32_t        size;
} pKeys;

typedef struct tag_nonce_entry
{
	uint32_t tagNonce; // Tag nonce we target for fixation
    byte_t spoofFlag; // No spoofing until we have a successful auth with this tagNonce. Once we have, we want to spoof to get the encrypted 0x5 value
    uint32_t num_of_appearances; // For statistics, how many times this tag nonce appeared for the given SLEEP_ values

    // STAGE1 data for "dark side" and lsfr_common_prefix()
    uint32_t spoofNrPfx; // PARAM: used as pfx, calculated from (spoofNrEnc & 0xFFFFFF1F). BUG: weird way to denote "first 29 prefix bits" in "dark side" paper. Perhaps I see the world different
    uint32_t spoofNrEnc; // {Nr} value which we will be using to make the tag respond with 4 bits
    uint32_t spoofArEnc; // PARAM: used as rr
    uint8_t spoofParBitsEnc; // parity bits we are trying to guess for the first time
    uint8_t spoofNackEnc; // store here the encrypted NACK returned first time we match the parity bits
    uint8_t spoofKs; // store here the keystream ks used for encryptying spoofNackEnc, specifically spoofKs = spoofNackEnc ^ 0x5

    // STAGE2 data for "dark side" and lsfr_common_prefix()
    int current_out_of_8; // starting from -1 until we find parity for chosen spoofNrEnc,spoofArEnc
    uint8_t parBitsCrntCombination[MFCUK_DARKSIDE_MAX_LEVELS]; // Loops over 32 combinations of the last 5 parity bits which generated the 4 bit NACK in STAGE1
    uint32_t nrEnc[MFCUK_DARKSIDE_MAX_LEVELS]; // the 29 bits constant prefix, varying only 3 bits, thus 8 possible values
    uint32_t arEnc[MFCUK_DARKSIDE_MAX_LEVELS]; // the same reader response as spoofArEnc; redundant but... :)
    uint8_t ks[MFCUK_DARKSIDE_MAX_LEVELS]; // PARAM: used as ks, obtained as (ks[i] = nackEnc[i] ^ 0x5)
    uint8_t nackEnc[MFCUK_DARKSIDE_MAX_LEVELS]; // store here the encrypted 4 bits values which tag responded
    uint8_t parBits[MFCUK_DARKSIDE_MAX_LEVELS]; // store here the values based on spoofParBitsEnc, varying only last 5 bits
    uint8_t parBitsArr[MFCUK_DARKSIDE_MAX_LEVELS][8]; // PARAM: used as par, contains value of parBits byte-bit values just splitted out one bit per byte thus second pair of braces [8]
} tag_nonce_entry_t;

int valid_nonce(uint32_t Nt, uint32_t NtEnc, uint32_t Ks1, byte_t * parity);
byte_t oddparity(const byte_t bt);
void num_to_bytes(uint64_t n, uint32_t len, byte_t* dest);
countKeys * uniqsort(uint64_t *possibleKeys, uint32_t size);
uint32_t median(denonce d);
int compar_int(const void * a, const void * b);


int compareTagNonces (const void * a, const void * b);
bool mfcuk_key_uint64_to_arr(const uint64_t *ui64Key, byte_t *arr6Key);
uint32_t darkside_keyrecovery_inner(nfc_device_t* pnd, uint32_t uiUID, uint64_t ui64Key, mifare_key_type bKeyType, uint32_t uiBlock, uint64_t *ui64KeyRecovered);



