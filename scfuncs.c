/* ============================================================================
   Course: CMPT 361
   Nicholas Lefebvre
   lefebvren4@mymacewan.ca
   #1689728
   scfuncs.c
   ============================================================================ */
#include <stdio.h>
#include <unistd.h>
#include <sys/select.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "scfuncs.h"

/* Function creates a struct adderinfo which the user will be able 
   to use the creating a socket */

void addInfo (struct addrinfo **res, char *host, char *port){
  struct addrinfo hints;
  int ec;
  bzero(&hints, sizeof (struct addrinfo));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if (host == NULL)
    hints.ai_flags = AI_PASSIVE;
  if ((ec = getaddrinfo (host,port,&hints,res)) != 0){
    fprintf(stderr, "getaddrinfo failed: %s",gai_strerror(ec));
    exit (1);
  }
}

void encryptMessage (int64_t yourOffset,const char yourOTP[],const byte_t yourString[], byte_t *yourEM, int length){
  FILE *fp; /* file pointer to yourOTP */
  int lengthBuffer,k;
  byte_t *bitsOTP;
  byte_t temp;
  
  fp = fopen (yourOTP,"rb");
  fseek(fp,yourOffset,SEEK_CUR);
  lengthBuffer = length;
  bitsOTP = malloc( sizeof(char) * lengthBuffer);
  if (yourOffset > 0 ){
    fread(bitsOTP,1,lengthBuffer,fp);   
    for (k = 0; k < lengthBuffer; k++){
      temp = yourString[k];
      yourEM[k] = temp ^ bitsOTP[k];
    }
  }
  else {
    fseek(fp,yourOffset - lengthBuffer,SEEK_END);
    fread(bitsOTP,1,lengthBuffer,fp);
    for(k = 0; k < lengthBuffer; k++){
      temp = yourString[k];
      yourEM[k] = temp ^ bitsOTP[k];
    }    
  }
  fclose (fp);
  free(bitsOTP);
}

void decryptMessage (const int64_t yourOffset, const char yourOTP[],const byte_t yourEM[], char *yourDM, uint16_t size){
  FILE *fp;
  int lengthBuffer;
  byte_t *bitsOTP;
  int i;
  byte_t temp;

  fp = fopen (yourOTP,"rb");
  lengthBuffer = size;
  bitsOTP = malloc (sizeof (byte_t) * lengthBuffer);

  if (yourOffset > 0){
    fseek(fp,yourOffset,SEEK_CUR);
    fread(bitsOTP,1,lengthBuffer,fp);
    
    for (i = 0; i < lengthBuffer; i++){
      temp = yourEM[i];
      yourDM[i] = temp ^ bitsOTP[i];
    }
  }
  else {
    fseek(fp,yourOffset - lengthBuffer,SEEK_END);
    fread(bitsOTP,1,lengthBuffer,fp);
    for(i = 0; i < lengthBuffer; i++){
      temp = yourEM[i];
      yourDM[i] = temp ^ bitsOTP[i];
    }
  }
  fclose(fp);
  free(bitsOTP);
}

/* http://sourceforge.net/p/predef/wiki/Endianness/
   provided function to convert little endian to
   big endian with a 64 bit int */


int64_t to_bigE_int64_t(int64_t native_number){
  int64_t result = 0;
  int i;

  for (i = (int)sizeof(result) - 1; i >= 0; i--) {
    ((unsigned char *)&result)[i] = native_number & UCHAR_MAX;
    native_number >>= CHAR_BIT;
  }
  return result;
}
/* http://sourceforge.net/p/predef/wiki/Endianness/
   provided function to convert little endian to
   big endian with a 16 bit int */

uint16_t to_bigE_uint16_t(uint16_t native_number){
  uint16_t result = 0;
  int i;

  for (i = (int)sizeof(result) - 1; i >= 0; i--) {
    ((unsigned char *)&result)[i] = native_number & UCHAR_MAX;
    native_number >>= CHAR_BIT;
  }
  return result;
}


/* http://sourceforge.net/p/predef/wiki/Endianness/
   provided function to convert big endian to 
   little endian with a long 64 bit int */
int64_t to_littleE_int64_t(int64_t net_number)
{
  int64_t result = 0;
  int i;

  for (i = 0; i < (int)sizeof(result); i++) {
    result <<= CHAR_BIT;
    result += (((unsigned char *)&net_number)[i] & UCHAR_MAX);
  }
  return result;
}
/* http://sourceforge.net/p/predef/wiki/Endianness/
   provided function to convert a big endian to
   little endian short 16 bit int */
uint16_t to_littleE_uint16_t(uint16_t net_number)
{
  uint16_t result = 0;
  int i;

  for (i = 0; i < (int)sizeof(result); i++) {
    result <<= CHAR_BIT;
    result += (((unsigned char *)&net_number)[i] & UCHAR_MAX);
  }
  return result;
}
/* http://sourceforge.net/p/predef/wiki/Endianness/ 
   provided the function for detecting endianness at
   run time */
enum {
  ENDIAN_UNKNOWN,
  ENDIAN_BIG,
  ENDIAN_LITTLE,
  ENDIAN_BIG_WORD,   /* Middle-endian, Honeywell 316 style */
  ENDIAN_LITTLE_WORD /* Middle-endian, PDP-11 style */
};
int endianness(void)
{
  uint32_t value;
  uint8_t *buffer = (uint8_t *)&value;

  buffer[0] = 0x00;
  buffer[1] = 0x01;
  buffer[2] = 0x02;
  buffer[3] = 0x03;

  switch (value)
    {
    case UINT32_C(0x00010203): return ENDIAN_BIG;
    case UINT32_C(0x03020100): return ENDIAN_LITTLE;
    case UINT32_C(0x02030001): return ENDIAN_BIG_WORD;
    case UINT32_C(0x01000302): return ENDIAN_LITTLE_WORD;
    default:                   return ENDIAN_UNKNOWN;
    }
}
/* Function checks to see if both the server and client have the same Md5 and Version.
   If both the version and md5 are the same function returns 1
   If the version or md5 are different the function returns 0
*/
int versionMd5Check (byte_t ourMd5[], byte_t theirMd5[],byte_t ourVersion, byte_t theirVersion){
  int i;
  if (ourVersion != theirVersion){
    return 0;
  }
  for (i = 0; i < 16; i++){
    if (ourMd5[i] != theirMd5[i]){
      return 0;
    }
  }
  return 1;
}
