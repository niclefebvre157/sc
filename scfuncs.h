
/* ============================================================================
   CMPT 361
   Nicholas Lefebvre
   Functions that are used in sc.c
   ============================================================================ */
#ifndef _SC_FUNCTS_H
#define _SC_FUNCTS_H

#include "common.h"
#include <stdint.h>

/* This structure holds the protocol or our sc.c program.
   This structure is used to send messages and also to recieve messages */
typedef struct _protocol {
  byte_t version;
  byte_t md5[16];
  int64_t offset;
  uint16_t length;
  byte_t dataField[65536];    
}__attribute__((packed)) protocol;


/* Functions that deal with endianness were adquired from
   http://sourceforge.net/p/predef/wiki/Endianness/*/

   /* ----------------------------------------------------------------------------
   to_littleE_int64_t:
     Takes a int64_t and converts it to little endian

   Return values:
     Function returns an int64_t that is little endian
     ---------------------------------------------------------------------------- */
int64_t to_littleE_int64_t(int64_t net_number);

   /* ----------------------------------------------------------------------------
   to_littleE_uint16_t:
     Takes a uint16_t and converts it to little endian

   Return values:
     Function returns an uint16_t that is little endian
     ---------------------------------------------------------------------------- */
uint16_t to_littleE_uint16_t(uint16_t net_number);


   /* ----------------------------------------------------------------------------
   to_bigE_int64_t:
     Takes a int64_t and converts it to big endian

   Return values:
     Function returns an int64_t that is big endian
     ---------------------------------------------------------------------------- */
int64_t to_bigE_int64_t(int64_t native_number);
   /* ----------------------------------------------------------------------------
   to_bigE_uint16_t:
     Takes a uint16_t and converts it to big endian

   Return values:
     Function returns an uint16_t that is big endian
     ---------------------------------------------------------------------------- */
uint16_t to_bigE_uint16_t(uint16_t native_number);

   /* ----------------------------------------------------------------------------
   endianness:
     Performs a test on the way bytes are stored on the computer to determine
     what type of system we are on

   Return values:
     Function returns an enum for the type of system we are on.
     ---------------------------------------------------------------------------- */
int endianness(void);

   /* ----------------------------------------------------------------------------
   versionMd5Check:
     Is a hand shake between the client and the server. The client and server
     must both have the same version as well as the same MD5 to ensure they can
     sucessfully dectype messages 

   Return values:
     1: the version and md5 are both correct (same on server/client side)
     0: the version of the md5 is incorrect
     ---------------------------------------------------------------------------- */

int versionMd5Check (byte_t ourMd5[], byte_t theirMd5[],byte_t ourVersion, byte_t theirVersion);

   /* ----------------------------------------------------------------------------
   addInfo:
     Takes in a host and port (only port if this is for a server) and creates
     a struct addrinfo that is can be used to create a socket 

   Return values:
     The created struct addrinfo is stored in res
     ---------------------------------------------------------------------------- */
void addInfo (struct addrinfo **res,char *host, char *port);

/* ----------------------------------------------------------------------------
   encryptMessage:
     Takes in offset, a file for a one time pad, an array of chars, an empty buffer,
     and the length of the message.
     By locating the offset of the one time pad this function xors the string against
     the one time pad. A user with the same one time pad and correct offsect can the
     descrtypt this message

   Return values:
     The encrypted message is stored in yourEM
     ---------------------------------------------------------------------------- */

void encryptMessage (int64_t yourOffset,const char yourOTP[],const byte_t yourString[],
 byte_t *yourEM, int length);

   /* ----------------------------------------------------------------------------
   decryptMessage:
     Takes in offset, a file for a one time pad, an array of chars, an empty buffer,
     and the length of the message.
     By locating the offset of the one time pad this function xors the string against
     the one time pad. This will result in a decrypted message

   Return values:
     The decrypted message is stored in yourDM
     ---------------------------------------------------------------------------- */

void decryptMessage (const int64_t yourOffset, const char yourOTP[],const byte_t yourEM[],
 char *yourDM,uint16_t size);

#endif /* _SC_FUNCTS_H */
