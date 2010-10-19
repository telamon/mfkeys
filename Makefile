all: 
	gcc -g -o mfkeys mfkeys.c crypto1.c crapto1.c mfcrack.c nfc-helper.c mifare.c -lnfc
	

