/*
 * THC/2003
 *
 * Simple ssh-private key cracker. Tries to brute force (dictionary
 * attack) almost any ssh private key file format.
 *
 * This is just a quick tool from THC. Using OpenSSL is not really
 * fast...
 *
 * COMPILE:
 * gcc -Wall -O2 -o thc-ssh-crack thc-ssh-crack.c -lssl
 *
 * RUN:
 * John is a good password generator. We use it for thc-ssh-crack:
 *
 * $ john -stdout -incremental | nice -19 thc-ssh-crack id_dsa
 *
 * Normal dictionary (without john's permutation engine):
 *
 * $ nice -19 thc-ssh-crack id_dsa <dictionary.txt
 *
 * Enjoy,
 *
 * http://www.thc.org
 */
#include <stdlib.h> 
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>

int
main(int argc, char *argv[])
{
 FILE *fp = fopen(argv[1], "r");
 EVP_PKEY *pk;
 char *ptr;
 char pwd[1024];
 //int cnt = 0; 

 SSL_library_init();
 pwd[0] = '\0';

 /* Catche keys with no passphrase */
 pk = PEM_read_PrivateKey(fp, NULL, NULL, (char *)pwd);
 if (pk)
  {
   printf("The is NO passphrase protection on this key!\n");
   exit(0);
  }

 printf("Trying password: ");
 while (1)
 {
  //if (0 == cnt % atoi(argv[1])) 
  //  printf("Count: %d\n", cnt); 
  if (!fgets(pwd, sizeof pwd, stdin))
  {
   printf("\nKey not cracked.\n");
   exit(0);
  }
  ptr = strchr(pwd, '\n');
  if (ptr)
   *ptr = '\0';
  printf("%s, ", pwd);   /* be verbose: show password */

  pk = PEM_read_PrivateKey(fp, NULL, NULL, (char *)pwd);
  if (pk)
  {
   printf("\n\n----> Keys's Password found: '%s' <-----\n", pwd);
   exit(0);
  }
 }

 return 0;
} 
