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
    
    Contains code partially or in full from the following projects:

    mfoc    Copyright (c) 2009 Andrei Costin <zveriu@gmail.com>, http://andreicostin.com

    mfcuk   Copyright (c) 2009 Norbert Szetei and Pavol Luptak <mifare@nethemba.com>
                               Michal Boska <boska.michal@gmail.com>
                               Romuald Conty <romuald@libnfc.org>
    
*/

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

#include <nfc/nfc.h>

#include "mfcrack.h"
#include "mifare.h"
#include "nfc-helper.h"

#include "mfkeys.h"


int main (int argc, char** argv)
{

    int i, j, k, l; // iterators

    // NFC
    nfc_device_t *reader;
    nfc_target_info_t target_info;
    
    // Mifare
    byte_t *mf_uid;
    bool mf_4k = false;
    int mf_numsectors = 0;
    
    // Keys
    
	static byte_t mf_defaultkeys[][6] = {
	    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 
	    {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}, 
	    {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}, 
	    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	    {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5},
	    {0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd},
	    {0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a},
	    {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	    {0x71, 0x4c, 0x5c, 0x88, 0x6e, 0x97},
	    {0x58, 0x7e, 0xe5, 0xf9, 0x35, 0x0f},
	    {0xa0, 0x47, 0x8c, 0xc3, 0x90, 0x91},
	    {0x53, 0x3c, 0xb6, 0xc7, 0x23, 0xf6},
	    {0x8f, 0xd0, 0xa4, 0xf2, 0x56, 0xe9}
	};
	
	static const byte_t initkey[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
	static byte_t key[6]           = {0x00,0x00,0x00,0x00,0x00,0x00};
    static byte_t userkey[6]       = {0x00,0x00,0x00,0x00,0x00,0x00};
    static byte_t tmpkey[6]        = {0x00,0x00,0x00,0x00,0x00,0x00};
    
    
    byte_t *mf_keya;   //a key table
    byte_t *mf_keyb;   //b key table
    
    bool *found_keya;  //a key valid mask
    bool *found_keyb;  //b key valid mask
    
    int found_key = 0;
    
    // Parse Options
    int option;
    bool option_verbose     = false;
    bool option_interactive = false;
    bool option_skipdefault = false;
    bool option_usekey      = false;
    bool option_usekeyfile  = false;
    bool option_dumpdata    = false;
    
    static char filename_output[PATH_MAX]  = "";
    static char filename_keyfile[PATH_MAX] = "";
    
    static struct option long_options[] =
    {
        {"help",         0, 0, 'h'},
        {"verbose",      0, 0, 'v'},
        {"dump-data",    0, 0, 'D'},
        {"skip-default", 0, 0, 's'},
        {"key",          0, 0, 'k'},
        {"keyfile",      0, 0, 'K'},
        {"version",      0, 0, 'V'},
        {"output",       1, 0, '0'},
        {0, 0, 0, 0}
    };
    
    static const char *short_options = "hvVdsK:k:o:";
    
    while ((option = getopt_long(argc, argv, short_options, long_options, NULL)) != -1)
    {
        switch (option)
        {
           case 'h':
                print_usage();
                return 1;
        
            case 'v':
                option_verbose = true;
                break;
                
            case 'V':
                print_license();
                return 1;

            case 'D':
                option_dumpdata = true;
                break;
                
            case 'k':
                if(strlen(optarg) == 12) {
                    option_usekey = true;
                    num_to_bytes(strtol(optarg, NULL, 16), 6, userkey);
                }
                else {
                    printf("Invalid keylength provided\n");
                    return EXIT_WRONGPARAM;
                }
                break;
                
            case 'K':
                option_usekeyfile = true;
                break;
                
            case 's':
                option_skipdefault = true;
                break;
                
            case 'o':
                strncpy(filename_output, optarg, PATH_MAX);
                break;
                
            case '?':
                fprintf(stderr, "Try %s --help for more information\n", argv[0]);
                return EXIT_WRONGPARAM;
                            
        }
    }

    if(option_verbose)
        printf ("Found: libnfc %s\n", nfc_version());
  
    // Connect to reader
  
    reader = nfc_connect(NULL);

    if (reader == NULL) {
        fprintf(stderr, "Unable to connect to NFC reader.\n");
        return EXIT_READERERROR;
    }
      
    if(!mf_configure(reader)) {
        fprintf(stderr, "NFC reader initialization failed.\n");
        nfc_disconnect(reader);
        return EXIT_READERERROR;
    }
    
    if(option_verbose)
        printf ("Found: NFC reader %s\n", reader->acName);
        
 
    if(!mf_anticol(reader, &target_info)){
        nfc_disconnect(reader);
        return 3;
    }
    
    mf_uid = target_info.nai.abtUid;
    mf_4k = (target_info.nai.abtAtqa[1] == 0x02);
    mf_numsectors = mf_4k ? 40 : 16;
    
    printf ("Found MIFARE Classic %ck card with UID: %02x%02x%02x%02x\n", 
            mf_4k ? '4' : '1', mf_uid[3], mf_uid[2], mf_uid[1], mf_uid[0]);
            
    found_keya  = (bool *) malloc(sizeof(bool) * mf_numsectors);
    found_keyb  = (bool *) malloc(sizeof(bool) * mf_numsectors);
    mf_keya     = (byte_t *) malloc(sizeof(byte_t) * mf_numsectors);
    mf_keyb     = (byte_t *) malloc(sizeof(byte_t) * mf_numsectors);
    
    for(i = 0; i < mf_numsectors; i++)
    {
        found_keya[i] = false;
        found_keyb[i] = false;
        memcpy(&mf_keya[i], initkey, KEYSIZE); 
        memcpy(&mf_keyb[i], initkey, KEYSIZE); 
    }
    
    if(option_usekey)
    {
        printf("Checking for provided key [%012llx] -> [", bytes_to_num(userkey, 6));
        
        for(i = 0; i < mf_numsectors; i++)
        {

            if(!found_keya[i])
            {
                if(mf_checkkey(reader, mf_uid, i, 0, userkey))
                {
                    found_keya[i] = true;
                    found_key++;
                    memcpy(&mf_keya[i], userkey, KEYSIZE); 
                }   
            }
            
            if(!found_keyb[i])
            {
                if(mf_checkkey(reader, mf_uid, i, 1, userkey))
                {
                    found_keyb[i] = true;
                    found_key++;
                    memcpy(&mf_keyb[i], userkey, KEYSIZE); 
                }
            }

            if(found_keya[i] && found_keyb[i])
                printf("x");
            else if(found_keya[i])
                printf("a");
            else if(found_keyb[i])
                printf("b");
            else
                printf(".");
            fflush(stdout);

        }
        
        printf("]\n");
     
    }
    
    if(option_usekeyfile)
    {
    
    }
                
    if(!(option_skipdefault || mf_numsectors * 2 == found_key))
    {   
        printf("Checking for %d default keys\n", (int)sizeof(mf_defaultkeys)/KEYSIZE);

        for(j=0; j < sizeof(mf_defaultkeys)/KEYSIZE; j++)
        {
            memcpy(key, &mf_defaultkeys[j], KEYSIZE);
            
            printf("[Key %02d: %012llx] -> [", (int)j+1, bytes_to_num(key,6));
            
            for(i = 0; i < mf_numsectors; i++)
            {

                if(!found_keya[i])
                {
                    if(mf_checkkey(reader, mf_uid, i, 0, key))
                    {
                        found_keya[i] = true;
                        found_key++;
                        memcpy(&mf_keya[i], key, KEYSIZE); 
                    }   
                }
                
                if(!found_keyb[i])
                {
                    if(mf_checkkey(reader, mf_uid, i, 1, key))
                    {
                        found_keyb[i] = true;
                        found_key++;
                        memcpy(&mf_keyb[i], key, KEYSIZE); 
                    }
                }

                if(found_keya[i] && found_keyb[i])
                    printf("x");
                else if(found_keya[i])
                    printf("a");
                else if(found_keyb[i])
                    printf("b");
                else
                    printf(".");
                fflush(stdout);

            }
            
            printf("]\r");
            
            if(mf_numsectors * 2 == found_key)
                break;
            
        }
        printf("\n");
    }
    
   
    if(found_key == 0)
    {
        printf("No keys were found. Trying 'darkside' key recovery\n");
        
        if(darkside_keyrecovery(reader, mf_uid, 0, 0, &key)) // let's use block 0 key A
        {
            printf("Recovered [Key A: %012llx] for sector 0 using 'darkside' key recovery\n", bytes_to_num(key,6));
            memcpy(&mf_keya[0], key, KEYSIZE);
            found_keya[0] = true;
            found_key++;
            
            mf_configure(reader); // reset to normal state
            mf_anticol(reader, NULL); // bring up the card again
            
            found_key += mf_check_card(reader, mf_uid, mf_numsectors, key, found_keya, found_keyb, mf_keya, mf_keyb);
        }
        else
        {
            printf("Could not recover keys using 'darkside'.\n");
        }   
    }
        
    if(found_key < mf_numsectors*2)
    {
        printf("%d key(s) found. Trying to recover the %d remaining key(s) using Nested Authentication key recovery.\n", found_key, mf_numsectors*2 - found_key);
        
        
        for(i = 0; i < mf_numsectors; i++){
            if(found_keya[i])
            {
                k = i;
                l = 0;
                memcpy(tmpkey, &mf_keya[i], KEYSIZE);
                
                break;
            }
            if(found_keya[i])
            {
                k = i;
                l = 1;
                memcpy(tmpkey, &mf_keyb[i], KEYSIZE);
                break;
            }
        }
        
        
        if(option_verbose)
            printf("Exploit sector is %d%c\n", k, l ? 'b' : 'a');
        
        
        printf("Finding keys: [");
        
        for(i = 0; i < mf_numsectors; i++){
            if(found_keya[i] && found_keyb[i])
                printf("x");
            else if(found_keya[i])
                printf("a");
            else if(found_keyb[i])
                printf("b");
            else
                printf(".");
        }
                    
        printf("]\rFinding keys: [");
        
        for(i = 0; i < mf_numsectors; i++)
        {
            mf_configure(reader); // reset to normal state
            mf_anticol(reader, NULL); // bring up the card again
               
            if(!found_keya[i])
            {
                if(na_keyrecovery(reader, mf_uid, 0, i, key, l, k, tmpkey))
                {
                    found_keya[i] = true;
                    found_key++;
                    memcpy(&mf_keya[i], key, KEYSIZE); 
                    
                    found_key += mf_check_card(reader, mf_uid, mf_numsectors, key, found_keya, found_keyb, mf_keya, mf_keyb);
                }   
            }
            
            if(!found_keyb[i])
            {
                if(na_keyrecovery(reader, mf_uid, 1, i, key, l, k, tmpkey))
                {
                    found_keyb[i] = true;
                    found_key++;
                    memcpy(&mf_keyb[i], key, KEYSIZE); 
                    
                    found_key += mf_check_card(reader, mf_uid, mf_numsectors, key, found_keya, found_keyb, mf_keya, mf_keyb);
                }
            }

            if(found_keya[i] && found_keyb[i])
                printf("x");
            else if(found_keya[i])
                printf("a");
            else if(found_keyb[i])
                printf("b");
            else
                printf(".");
            fflush(stdout);
            
        }
        
     printf("]\n");
     
    }
    
    
    
    
    if(found_key == 0)
    {
        printf("No keys were found\n");       
    }
    else if(found_key == mf_numsectors * 2)
    {
        printf("All keys were found\n");
    }
    else
    {
        printf("%d of %d keys were found.\n", found_key, mf_numsectors * 2);
    }
    
    
              

    free(found_keya);
    free(found_keyb);
    free(mf_keya);
    free(mf_keyb);
        
    nfc_disconnect(reader);
    return 0;   
}

void print_license()
{
    fprintf(stdout, "mfkeys %s Copyright (C) 2010  Christian Panton <christian@panton.org>\n\n", VERSION);
    
    fprintf(stdout, "   This program is free software: you can redistribute it and/or modify\n");
    fprintf(stdout, "   it under the terms of the GNU General Public License as published by\n");
    fprintf(stdout, "   the Free Software Foundation, either version 3 of the License, or\n");
    fprintf(stdout, "   (at your option) any later version.\n\n");

    fprintf(stdout, "   This program is distributed in the hope that it will be useful,\n");
    fprintf(stdout, "   but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
    fprintf(stdout, "   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
    fprintf(stdout, "   GNU General Public License for more details.\n\n");
}

void print_usage()
{
    fprintf(stdout, "Usage: mfkeys [options]\n");
	fprintf(stdout, "   -h, --help\n");
	fprintf(stdout, "       Display command usage info.\n");
	fprintf(stdout, "   -v, --verbose\n");
	fprintf(stdout, "       Increase amount of output.\n");
	fprintf(stdout, "   -d, --dump-keys\n");
	fprintf(stdout, "       Try to recover unknown keys.\n");
	fprintf(stdout, "   -D, --dump-data\n");
	fprintf(stdout, "       Dump entire card when done.\n");
    fprintf(stdout, "   -s, --skip-default\n");
	fprintf(stdout, "       Do not try to use default keys.\n");
	fprintf(stdout, "   -k, --key KEY\n");
	fprintf(stdout, "       Try using 6 byte key (12 hex chars).\n");
    fprintf(stdout, "   -K, --keyfile FILE\n");
	fprintf(stdout, "       Try using an existing card dump.\n");
	fprintf(stdout, "   -o, --outfile FILE\n");
	fprintf(stdout, "       Filename to write card data to.\n");
	fprintf(stdout, "\n");
}


