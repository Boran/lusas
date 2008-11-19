/*
 * ssh-privkey-crack, just another SSH private key cracker
 *
 * Copyright (c) 2005-2006, anonymous <anonymous@echo.or.id>
 *    All rights reserved.
 *
 * modified by michu / neophob.com 2007 - www.neophob.com
 *  added command line switches
 *  added benchmark
 *  added windows text file support
 *  added some openssl routines in this file to increase performance
 *
 * compile: 
 *  $ gcc -Wall -O2 -o ssh-privkey-crack ssh-privkey-crack.c -lssl -lcrypto
 *
 * info: this works with cygwin, but its slower than linux
 * I computed arround 7500 key/s with an p4, 2ghz, sse2 (4000 bogo mips) 
 * and john 1.7.2 sse enabled
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
		 
#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#define VERSION "0.3"
#define CHAR_LENGTH 1024

time_t tim2,tim;    
int verbose=0;


void weFoundIt(char * pw, EVP_PKEY *pk, long cnt)
{
	if (pk) {
	    printf( "\n------------------------------------------------------------------------ -- -\n");
	    printf( "Passphrase match: <%s>. Found password after %.f seconds and %li tries.\n", pw,difftime(tim2,tim),cnt); 
	    printf( "-------------------------------------------------------------------------- -- -\n");	    
	    printf( "\n");

	    if (verbose==1) {
    		printf( "additional key information:\n");
		if (pk->type == EVP_PKEY_RSA ) {
		    printf("        Key type: PKEY_RSA\n");
		    RSA_print_fp(stderr, EVP_PKEY_get1_RSA(pk), 8);
		} else
		if (pk->type == EVP_PKEY_DSA ) {
		    printf("        Key type: PKEY_DSA\n");	    
		    DSA_print_fp(stderr, EVP_PKEY_get1_DSA(pk), 8);
		} else {
		    printf("PEM_read_PrivateKey: mismatch or unknown EVP_PKEY save_type %d", pk->save_type);
		}
	    }	    
	    if (pk != NULL) EVP_PKEY_free(pk);
	    
	    exit(0);
	} 
}


int main(int argc, char **argv)
{
    FILE *fp;
    BIO *bio;
    char pw[CHAR_LENGTH];
    int i = 0;
    extern char *__progname;
    double keys;
    long cnt=0;
    int quite=0;
    
    char *nm=NULL;
    const unsigned char *p=NULL;
    unsigned char *data=NULL;
    long len;
    EVP_PKEY *pk2=NULL;


//
    EVP_CIPHER_INFO xxcipher;
    char *xxnm=NULL,*xxheader=NULL;
    unsigned char *xxdata=NULL;
    long xxlen;
    int xxret = 0;
	
    printf( "%s v%s made by anonymous@echo.or.id, enhanced by michu@neophob.com\n", __progname, VERSION);
	       
    if (argc < 2 || argc > 3) {        
	printf( "Usage: %s [DSA or RSA private key file] [-v|-q]\n", __progname);
	printf( "       -v: verbose mode\n");
	printf( "       -q: quite mode\n");	
	printf( "Example:\n");
	printf( " $ john-mmx -stdout -incremental | %s id_dsa\n",__progname);
	printf( " $ %s id_dsa < dictionary\n", __progname);
	printf( "\n");
	exit(1);
    }
    
    if (argc == 3) {
        if (strcmp(argv[2],"-v")==0) {
    	    verbose=1;
	    printf( "verbose mode\n");
	}
        if (strcmp(argv[2],"-q")==0) {
    	    quite=1;
	}
    
    }

    SSL_library_init();
    SSL_load_error_strings();
    
    tim = time (NULL);
    tim2 = time (NULL);    
    
    /*
     * check if file exist
     */
    if ((fp = fopen(argv[1], "r")) == NULL) {
	printf( "Error: Cannot open %s.\n", argv[1]);
	exit(1);
    }
    fclose(fp);

    if ((pk2=EVP_PKEY_new()) == NULL)
    {
	printf("ERROR, failed create bew EVP_PKEY!\n");
	ASN1err(ASN1_F_D2I_PRIVATEKEY,ERR_R_EVP_LIB);
        ERR_print_errors_fp(stderr);
	exit(1);
    }									     
    
    bio = BIO_new( BIO_s_file() );
    BIO_read_filename( bio, argv[1] );			    
    
/////////////////
    for (;;)
    {
        if (!PEM_read_bio(bio,&xxnm,&xxheader,&xxdata,&xxlen)) {
	    if(ERR_GET_REASON(ERR_peek_error()) ==PEM_R_NO_START_LINE) {
		ERR_add_error_data(2, "Expecting: PEM_STRING_EVP_PKEY");
		ERR_print_errors_fp(stderr);
		printf("ERROR, check you private key file, RSA and DSA are supported!\n");		
	    }
	    exit(1);
	    
	}
		
	if (!strcmp(xxnm,PEM_STRING_EVP_PKEY)) break;
	if (!strcmp(xxnm,PEM_STRING_RSA)) break;
	if (!strcmp(xxnm,PEM_STRING_DSA)) break;

	OPENSSL_free(xxnm);
	OPENSSL_free(xxheader);
	OPENSSL_free(xxdata);
    }
    if (!PEM_get_EVP_CIPHER_INFO(xxheader,&xxcipher)) {    
        if (!xxret) OPENSSL_free(xxnm);
        OPENSSL_free(xxheader);
	if (!xxret) OPENSSL_free(xxdata);
	printf("ERROR, failed!!");
	ERR_print_errors_fp(stderr);
	exit(1);
    }
/////////////////

    data=malloc(xxlen);    
    printf("keyheader:\n%s\n",xxheader);
    BIO_free(bio);

/*
 * MAINLOOP
 */    
    while (fgets(pw, CHAR_LENGTH, stdin) != NULL) {
	/*
	 * Scan stdin for "\n" and "\r", delete the first occurence and replace it with "\0"
	 */
	for (i = 0; i < CHAR_LENGTH && pw[i] != 10 && pw[i] != 13; i++);
	pw[i] = 0;
		
	if (verbose==1) printf("\ntry pw: <%s>\n",pw);
//	printf("header:%s\n",xxheader);
//	printf("data [%i]: %s\n",xxlen,xxdata);

	memcpy(data,xxdata,xxlen);
	len=xxlen;

	if (PEM_do_header(&xxcipher,data,&len,NULL,(char *)pw))
        {
	    p = data;
	    nm=xxnm;
	    
	    if (verbose==1) printf("looks good, check key type\n");
	    
	    if (strcmp(nm,PEM_STRING_RSA) == 0) {
	    /*
	     * HANDLE RSA KEY
	     */	    
		if (verbose==1) printf("i think its an rsa key, ");
		pk2->save_type=EVP_PKEY_RSA;
		pk2->type=EVP_PKEY_type(EVP_PKEY_RSA); 
		if (verbose==1) printf("decrypt... ");
		if ((pk2->pkey.rsa=d2i_RSAPrivateKey(NULL, &p,len)) == NULL)
		{
    		    if (verbose==1) printf("failed to read PKEY!\n");
		} else {
		    if (verbose==1) printf("tataaa!\n");
//		    BIO_free(bio);
		    free(data);
		    weFoundIt(pw, pk2, cnt);
		}
	    }		
	    else if (strcmp(nm,PEM_STRING_DSA) == 0) {
	    /*
	     * HANDLE DSA KEY
	     */	    
		if (verbose==1) printf("i think its an dsa key, ");
		pk2->save_type=EVP_PKEY_DSA;
		pk2->type=EVP_PKEY_type(EVP_PKEY_DSA); 
		if (verbose==1) printf("decrypt... ");	
		if ((pk2->pkey.dsa=d2i_DSAPrivateKey(NULL, &p,len)) == NULL)
		{
    		    if (verbose==1) printf("failed to read PKEY!\n");
		} else {
		    if (verbose==1) printf("tataaa!\n");
//		    BIO_free(bio);		    
		    free(data);		    
		    weFoundIt(pw, pk2, cnt);
		}		
	    } else {
		if (verbose==1) printf("ERROR: only RSA and DSA keys are supportet!\n");
	    }
	    
	} else {
	    /*
	     * debug information
	     */
	    if (verbose==1) ERR_print_errors_fp(stderr);
	}

	if ((cnt%1000)==1) {
    	    tim2 = time(NULL);	
	    keys=cnt/difftime(tim2,tim);
	    if (verbose==0 && quite==0) 
		printf("trying %.f keys/s, # of tested keys: %li. \r",keys,cnt);
	}

//	ERR_clear_error();
	cnt++;
    }
//    BIO_free(bio);
    free(data);
    if (pk2 != NULL) EVP_PKEY_free(pk2);
    printf( "\nDamn, I can't find any match.\n");
    printf( "\n");
    return 0;
} 

