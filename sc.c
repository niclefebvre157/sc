/***************************************************************************
 *Nicholas Lefebvre
 *lefebvren4@
 *ID: 1689728
 *October 4th, 2013
 *CMPT-361 f13
 *Notes: I feel my submission is fully functional. When I used my solution
 with the buggy you provided it didn't work very well. Your -v gave me output
 that fseek wasn't working properly. I think maybe we used fseek differently. I
 think I read the description carefully and it stated when a connection is first
 established a header will be sent both ways ( client to server ) ( server to client)
 and md5s will be compared. So my solution sends out a 27 byte header when ever a connection
 is made.I also compared the versions because I felt that is something
 that should also be checked (and version is always 1 anyways). This program runs very
 well with it's self and I'm hoping / thinking the problem we are facing is how we 
 run our fseek.

 *Cited works
    Beejs provided lots of help with creating a server, and how you can use a max fds to go through
    all of your file descriptors. 
    beej.us/guide/bgnet/output/html/multipage/advanced.html
    
    Also used your guide on creating a server that your provided us as a guide line.

    A few functions that we used for endianness were from the website your provided
    http://sourceforge.net/p/predef/wiki/Endianness/
 *Description:
 The sc program creates a server/client were 2 people can chat.
 This chat program uses an  unbreakable encription method with a one time pad. 
 Only the 2 users with the SAME one time pad can understand the messages being 
 sent over across the server. 
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/select.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdint.h> 
#include <limits.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "scfuncs.h"
#include "md5.h"
#include "lib.h"

#define STRUCT_LEN 27 
#define BUF_SIZE 4096
#define MAX_SOCK 50
#define BACK_LOG 10
#define MAX_BYTES 400000


int main (int argc, char *argv[]){


  
  enum {
    ENDIAN_UNKNOWN,
    ENDIAN_BIG,
    ENDIAN_LITTLE,
    ENDIAN_BIG_WORD,   /* Middle-endian, Honeywell 316 style */
    ENDIAN_LITTLE_WORD /* Middle-endian, PDP-11 style */
  };
  typedef struct _protocol {
    byte_t version;
    byte_t md5[16];
    int64_t offset;
    uint16_t length;
    byte_t dataField[65536];    
  }__attribute__((packed)) protocol;
  struct addrinfo *results, *iterator;
  protocol pro, proRecv;
  pro.version = 1; /* version 1 */
  
  int isFull = 0; /* used with Call to md5 */
  int k;
  int i;
  char *client;
  char delim[] = " :";
  char *host;
  char *port;
  struct md5CTX md5Calc;
  byte_t fileInput[BUF_SIZE];
  
  FILE *fileName; /* filename of the one time pad */ 
  size_t returnNumber; /* holds how many bytes returned from fread */ 
  fd_set rfds, wfds, mfds, mwfds;
  int ncfds; /* new connection file descriptor */
  char *sendBuff; /* buffer holds information that is sent */
  char *sendBuffHS; /* buffer only used to hold the header for hand shake*/
  int hLength; /* holds length during endian conversion */
  int hOffset; /* holds offset during endian conversion */
  
  int lsds; /* listening socket descriptory */
  int sockOptVar;
  int cmfds; /* current max file descriptor*/
  
  int isSame; /* Return value from versionMd5Check */
  
  byte_t ourVersion = 1;
  
  int nBytes; /* Number of bytes that sent from send */
  int userB; /* user data in bytes if 0 user has hung up connection */
  byte_t userBuf[100000];
  byte_t EMBuf[65536]; /* holds our encryped message */
  char DMBuf[65536]; /*holds the decrypted message */
  int bytesSendBuf = 0; /* bytes currently in the send buffer*/
  int ourEndian; /* Holds if the system is big endian or little endian */
  
  char *OTP; /* File name of OneTimePad*/
  socklen_t clientAddrLen, serverAddrLen;
  struct sockaddr_storage clientAddr, serverAddr;
  struct _fdstat bufferC,bufferR;
  FDSTAT_RESET(bufferC);
  FDSTAT_RESET(bufferR);
  
  /* sc.c must have exactly 3 arguments to run */
  if(argc != 3){
    fprintf(stderr,"Usage: %s Inorrect amount of arguments.\n", argv[0]);
    exit(1);
  }
  /* Sets the endianness of system */
  ourEndian = endianness();
 
  /* OTP is the user specified one time pad */
  OTP = argv[1];
  if (access(OTP,F_OK == -1)){
    fprintf(stderr,"File doesn't exist.\n");
    exit (0);
  }
  fileName = fopen (OTP,"rb");
  
  /* starts the md5 check sum calculation */
  md5Start(&md5Calc);
  while (!feof(fileName)){
    returnNumber = fread(fileInput,1,BUF_SIZE,fileName);
    isFull = md5Add(&md5Calc,fileInput,returnNumber);
    if (isFull == -1){
      fprintf(stderr,"MD5 Calculation Failed. (Too many bytes)\n");
    }
  }
  /* our md5 checksum has been created and stored in pro.md5 */
  md5End(&md5Calc,pro.md5);
  
  /* if a ':' is in the argument we have a client.
     else we have a server */
  client = strchr(argv[2],':');
  
  /* Creats a server */
  if (client == NULL ){
    pro.offset = -1;
    
    FD_ZERO(&rfds); /* read file descriptor */
    FD_ZERO(&wfds); /* write file descriptor */
    FD_ZERO(&mfds); /* master set for read file descriptors */
    FD_ZERO(&mwfds); /* master set for write file descriptors */
    
    port = argv[2];
    
    /* getaddrinfo function */
    addInfo(&results,NULL,port);
    
    /* Create a server */
    for (iterator = results; iterator != NULL; iterator = iterator->ai_next){
      if(( lsds = socket (iterator->ai_family,
			  iterator->ai_socktype,
			  iterator->ai_protocol )) == -1)
	continue;	
      if (setsockopt(lsds, SOL_SOCKET, SO_REUSEADDR, &sockOptVar, sizeof (int)) != 0){
	fprintf(stderr,"Setsockopt failed.\n");
	exit (1);
      }
      if (iterator->ai_family == AF_INET6){
	if (setsockopt(lsds, IPPROTO_IPV6, IPV6_V6ONLY, &sockOptVar, sizeof(int)) != 0){
	  fprintf(stderr,"Setsockopt failed.\n");
	  exit (1);
	}
      }
      /* binds lsds to a specified port */
      if (bind (lsds,iterator->ai_addr,iterator->ai_addrlen) == -1){
	close (lsds);
	continue;
      }
      /* makes lsds the listening socket for new connections */
      if (listen (lsds, BACK_LOG) == -1){
	close (lsds);
	continue;
      }
      break;
    }
    /* No socket was made */
    if (iterator == NULL){
      fprintf(stderr,"%s: No socket created.\n",argv[0]);
      exit(1);
    }
    /* Listening socket stored in lsds */
    /* No longer need information in results */
    freeaddrinfo (results);
    
    /* Set both our listening socket descriptor and stdin to our master read fds */
    FD_SET(lsds,&mfds);
    FD_SET(0,&mfds);
    /* Only have one socket descriptor, so it currently the max */
    cmfds = lsds;
    
    /* Main loop for server */
    while (1){
      /* Update our read and write fds */
      rfds = mfds;
      wfds = mwfds;
      if (select(cmfds+1,&rfds,&wfds,NULL,NULL) == -1){
	fprintf(stderr,"%s: Select Error. ERRNO %d\n",argv[0],errno);
	exit (1);
      }
      
      /* For loop goes through all the file descriptors up to our
	 cmfds ( current max file descriptor ) */
      for (i = 0; i <= cmfds; i++){
	/* If stdin is set */
	if (FD_ISSET(0,&rfds)){
	  if ( i == 0 ){
	    /* We have a message to send to the client */
	    pro.length = readline (0,pro.dataField,65536,&bufferC);
	    if (pro.length == 0 ){
	      printf("\nClosed connection.\n");
	      free (sendBuff);
	      exit (0);
	    }
	    /* pro.length is greater than 0 we have a message to send */
	    if (pro.length > 0){
	      if (pro.offset == -1){ /* only happens once, first time for malloc */
		/* malloc our sendBuff to be able to hold our header and the message */
		sendBuff = malloc(STRUCT_LEN + pro.length);
		/* number of bytes that are ready to be sent */
		bytesSendBuf = STRUCT_LEN + pro.length;
		/* function encrypts our messsage with OTP */
		encryptMessage(pro.offset,OTP,pro.dataField,EMBuf,pro.length);
		/* Puts the returned encrypted message into our pro (protcol) structure */
		for (k = 0; k < pro.length; k++){
		  pro.dataField[k] = EMBuf [k];
		}
		/* Save our offset and length before converting to big endian
		   if this is a little endian system */
		hOffset = pro.offset;
		hLength = pro.length;
		/* convert our offset / length to big endian if needed */
		if (ourEndian == ENDIAN_LITTLE){
		  pro.offset = to_littleE_int64_t (pro.offset);
		  pro.length = to_littleE_uint16_t (pro.length);
		}
		/* copy our data from our pro strucutre to the sendBuff which will
		   eventually be sent to the client */
		memcpy(sendBuff,&pro,(STRUCT_LEN + hLength));
	      }
	      /* else we have malloc'd sendBuff */
	      else {
		/* everything has been sent from sendBuff*/
		if (bytesSendBuf == 0){
		  /* realloc our send buffer */
		  sendBuff = realloc(sendBuff,(STRUCT_LEN + pro.length));
		  /* number of bytes that are ready to be sent */
		  bytesSendBuf = (STRUCT_LEN + pro.length);
		  encryptMessage(pro.offset,OTP,pro.dataField,EMBuf,pro.length);
		  
		  for (k = 0; k < pro.length; k++){
		    pro.dataField[k] = EMBuf [k];
		  }
		  
		  /* hold both our offset and length before endian conversion*/
		  hOffset = pro.offset;
		  hLength = pro.length;
		  if (ourEndian == ENDIAN_LITTLE){
		    pro.offset = to_littleE_int64_t (pro.offset);
		    pro.length = to_littleE_uint16_t (pro.length);
		  }
		  /* memcpy to start of sendBuf */
		  memcpy(sendBuff,&pro,(STRUCT_LEN + hLength));
		}
		/* there is still bytes that havnet been set in sendBuff. realloc() to new size
		   and add new bytes after the bytes still in sendBuff so we don't overwrite the
		   information */
		else {
		  sendBuff = realloc(sendBuff,(bytesSendBuf + STRUCT_LEN + pro.length));
		  encryptMessage(pro.offset,OTP,pro.dataField,EMBuf,pro.length);
		  
		  for (k = 0; k < pro.length; k++){
		    pro.dataField[k] = EMBuf [k];
		  }		   
		  hOffset = pro.offset;
		  hLength = pro.length;
		  if (ourEndian == ENDIAN_LITTLE){
		    pro.offset = to_littleE_int64_t (pro.offset);
		    pro.length = to_littleE_uint16_t (pro.length);
		  }
		  /* memcpy to sendBuff after previous information in sendBuff */
		  memcpy(sendBuff+bytesSendBuf,&pro,(STRUCT_LEN + hLength));
		  bytesSendBuf += (STRUCT_LEN + hLength);
		}
	      }
	      /* Change offset and length back to native form */
	      pro.offset = hOffset;
	      pro.length = hLength;
	      /* Update the offset */
	      pro.offset -= pro.length;
	      /* we have something to send, set master wfds */
	      FD_SET(cmfds, &mwfds);
	    }
	  }
	}
	else if (FD_ISSET(i,&rfds)){
	  /* accepts a client to the server if i is our listening fds*/
	  if (i == lsds){
	    clientAddrLen = sizeof clientAddr;
	    ncfds = accept(lsds,(struct sockaddr*)&clientAddr,&clientAddrLen);
	    if (ncfds == -1){
	      fprintf(stderr,"%s: Accept Error. ERRNO %d\n",argv[0],errno);
	    }
	    /* accept has a connection on the listening fds */
	    else {
	      /* We have a new connection. We need to send a binary message
		 to the client with our md5 checksum and version. We also need to
		 get accept a md5check sum from the client to make sure we have the
		 same version / md5 */
	      pro.length = 0;
	      hOffset = pro.offset;
	      hLength = pro.length;
	      if (ourEndian == ENDIAN_LITTLE){
		pro.offset = to_littleE_int64_t (pro.offset);
		pro.length = to_littleE_uint16_t (pro.length);
	      }
	      /* we only are sending a header for the hand shake
		 27 bytes = STRUCT_LEN */
	      sendBuffHS = malloc(STRUCT_LEN);
	      memcpy(sendBuffHS,&pro,STRUCT_LEN);
	      /* send the 27 byte header */
	      send(ncfds,sendBuffHS,STRUCT_LEN,0);
	      /* wait until we have recieved 27 byte header from the client */
	      while (userB != STRUCT_LEN){
		userB = readn(ncfds,userBuf,STRUCT_LEN,&bufferR);
	      }
	      memcpy(&proRecv,userBuf,STRUCT_LEN);
	      /* test to see if the md5 and the check sum are equa; */
	      isSame = versionMd5Check(pro.md5,proRecv.md5,ourVersion,proRecv.version);
	      if (isSame == 0){
		fprintf(stderr,"Incorrect MD5 or Version.\n");
		exit(1);
	      }
	      memset(userBuf,0,sizeof(userBuf));
	      free(sendBuffHS);
	      /* set the new connection with the client in the 
		 master read fds */
	      FD_SET(ncfds, &mfds);
	      /* If new connection fds is greater than
		 current max fds, change the current max fds
		 to the new connection fds */
	      if (ncfds > cmfds){
		cmfds = ncfds;
	      }
	      /* No longer need a listening socket, we only need 1 connection
		 with a client for this sc.c program */
	      FD_CLR(lsds,&mfds);
	    }
	  }
	  /* we have a message from the user that we need to read */
	  else {
	    /* readn takes in 27 bytes of information (STRUCT_LEN) because the 
	       header is needed to get the rest of the message */
	    if ((userB = readn(i,userBuf,STRUCT_LEN,&bufferR))<= 0){
	      if (userB == -1){
		fprintf(stderr,"%s: recv Error.\n ",argv[0]);
		exit (1);
	      }
	      else {
		printf("User closed connection (Client)\n");
		free(sendBuff);
		exit(0);
	      }
	    }
	    /*user has sent us userB ( 27 ) bytes of infomormation */
	    if (userB > 0){
	      /* copy the buffer (header )into our protocol structure */
	      memcpy(&proRecv,userBuf,STRUCT_LEN);
	      /* if this is a little endian computer, convert to little endian */
	      if (ourEndian == ENDIAN_LITTLE){
		proRecv.offset = to_littleE_int64_t (proRecv.offset);
		proRecv.length = to_littleE_uint16_t (proRecv.length);
	      }
	      /* call to function isSame, makes sure both the md5 and version match
		 between the client and the server */
	      isSame = versionMd5Check(pro.md5,proRecv.md5,ourVersion,proRecv.version);
	      if (isSame == 0){
		fprintf(stderr,"Incorrect MD5 or Version.\n");
		exit(1);
	      }
	      /* clear the userBuf, we have the information we need from it */
	      memset(userBuf,0,sizeof(userBuf));
	      /* readn proRecv.length bytes, length of the encrypted message from the client */
	      userB = readn(i,userBuf,proRecv.length,&bufferR);
	      /* decrypt the message from the client */
	      decryptMessage(proRecv.offset,OTP,userBuf, DMBuf, proRecv.length);
	      /* null terminate the Decrypted Message Buffer */
	      DMBuf[proRecv.length] = '\0';
	      /* print the message from the client */
	      printf("%s",DMBuf);
	      /* clean the contents of userBuf, we no longer need this information */
	      memset(userBuf,0,sizeof(userBuf));	
	    }
	  }  
	}
	/* if i (fds) is set in our write fds we have something to send*/
	else if(FD_ISSET(i,&wfds)){
	  nBytes = send (i,sendBuff,bytesSendBuf,0);
	  /* if send didn't send all its bytes trasfer the data left in sendBuff to the
	     beginning of the buffer, and update the amouts of bytes left in the buffer
	     bytesSendBuf */
	  if (nBytes < bytesSendBuf){
	    memcpy(sendBuff,(sendBuff + nBytes),(bytesSendBuf - nBytes));
	    bytesSendBuf = (bytesSendBuf - nBytes);
	  }
	  /* else send was able to send all of the bytes, set the bytes left in the buffer to
	     0, we can now remove the cmfds ( our client ) from the write fds because there
	     is nothing left to be send */
	  else {
	    bytesSendBuf = 0;
	    FD_CLR(cmfds, &mwfds);
	  }
	}
      }
    }
  }
  else {
    /* A host and a port were specified, we have a client */
    FD_ZERO(&rfds); /* read file descriptor */
    FD_ZERO(&wfds); /* write file descriptor */
    FD_ZERO(&mfds); /* master set for read file descriptors */
    FD_ZERO(&mwfds); /* master set for write file descriptors */
    
    host =  strtok(argv[2],delim);
    port = strtok(NULL,delim);
    /* getAddrInfo function */
    addInfo(&results,host,port);
    
    serverAddrLen  = sizeof serverAddr;
    for (iterator = results; iterator != NULL; iterator = iterator->ai_next){
      if(( lsds = socket (iterator->ai_family, iterator->ai_socktype, iterator->ai_protocol )) == -1)
	continue;
      ncfds = connect(lsds,iterator->ai_addr,iterator->ai_addrlen);
      if (ncfds == -1){
	continue;
      }
      break;
    }
    freeaddrinfo(results);
    
    /* Handshake before communication */
    pro.length = 0;
    hOffset = pro.offset;
    hLength = pro.length;
    if (ourEndian == ENDIAN_LITTLE){
      pro.offset = to_littleE_int64_t (pro.offset);
      pro.length = to_littleE_uint16_t (pro.length);
    }
    /* we only are sending a header for the hand shake
       27 bytes = STRUCT_LEN */
    sendBuffHS = malloc(STRUCT_LEN);
    memcpy(sendBuffHS,&pro,STRUCT_LEN);
    send(lsds,sendBuffHS,STRUCT_LEN,0);

    while (userB != STRUCT_LEN){
      userB = readn(lsds,userBuf,STRUCT_LEN,&bufferR);
    }
    memcpy(&proRecv,userBuf,STRUCT_LEN);
    isSame = versionMd5Check(pro.md5,proRecv.md5,ourVersion,proRecv.version);
    if (isSame == 0){
      fprintf(stderr,"Incorrect MD5 or Version.\n");
      exit(1);
    }
    
    memset(userBuf,0,sizeof(userBuf));
    free(sendBuffHS);
    pro.offset = 1;

    /*not able to connect/make a socket */
    if (iterator == NULL){
      fprintf(stderr,"Couldnt connect to server.\n");
      exit(1);
    }
    FD_SET(lsds,&mfds); /* set lsds (connection to server ) to our master
			   read fds */
    FD_SET(0,&mfds);    /* set stdin to master read fds */
    
    cmfds = lsds; /* current max fds = lsds (only need 1 connection so its
		     our max fds) */
    while (1){
      /* update our read/write fds */
      rfds = mfds;
      wfds = mwfds;
      if (select(cmfds+1,&rfds,&wfds,NULL,NULL) == -1){
	fprintf(stderr,"Select Error.\n");
	exit (1);
      }
      for (i = 0; i <= cmfds; i++){
	if (FD_ISSET(0,&rfds)){
	  if ( i == 0 ){
	    pro.length = readline (0,pro.dataField,65536,&bufferC);
	    if (pro.length == 0 ){
	      printf("\nClosed connection.\n");
	      free(sendBuff);
	      exit (0);
	    }
	    if (pro.length > 0){
	      if (pro.offset == 1){
		/* first malloc for our send buffer */
		sendBuff = malloc(STRUCT_LEN + pro.length);
		/* number of bytes that are ready to be sent */
		bytesSendBuf = STRUCT_LEN + pro.length;
		/* encrype our message */
		encryptMessage(pro.offset,OTP,pro.dataField,EMBuf,pro.length);
		/* store our encrypted message into our datafield */
		for (k = 0; k < pro.length; k++){
		  pro.dataField[k] = EMBuf [k];
		}
		/* hold offset and length of protocol before
		   changing to big endian */
		hOffset = pro.offset;
		hLength = pro.length;
		if (ourEndian == ENDIAN_LITTLE){
		  pro.offset = to_littleE_int64_t (pro.offset);
		  pro.length = to_littleE_uint16_t (pro.length);
		}
		/* copy our structre information to our sendBuff */
		memcpy(sendBuff,&pro,(STRUCT_LEN + hLength));
	      }
	      else {
		/* everything has been sent from sendBuff*/
		if (bytesSendBuf == 0){
		  /* realloc our send buffer */
		  sendBuff = realloc(sendBuff,(STRUCT_LEN + pro.length));
		  /* number of bytes that are ready to be sent */
		  bytesSendBuf = (STRUCT_LEN + pro.length);
		  
		  /* this will enctypt newlines */
		  encryptMessage(pro.offset,OTP,pro.dataField,EMBuf,pro.length);
		  
		  for (k = 0; k < pro.length; k++){
		    pro.dataField[k] = EMBuf [k];
		  }
		  /* hold both our offset and length before endian conversion*/
		  hOffset = pro.offset;
		  hLength = pro.length;
		  if (ourEndian == ENDIAN_LITTLE){
		    pro.offset = to_littleE_int64_t (pro.offset);
		    pro.length = to_littleE_uint16_t (pro.length);
		  }
		  /* memcpy to start of sendBuf */
		  memcpy(sendBuff,&pro,(STRUCT_LEN + hLength));
		}
		/* there is still bytes that have not been sent to the server
		   so we must allocate more space to our sendBuff so we do not
		   overwtite information */
		else {
		  sendBuff = realloc(sendBuff,(bytesSendBuf + STRUCT_LEN + pro.length));
		  encryptMessage(pro.offset,OTP,pro.dataField,EMBuf,pro.length);
		  for (k = 0; k < pro.length; k++){
		    pro.dataField[k] = EMBuf [k];
		  }
		  hOffset = pro.offset;
		  hLength = pro.length;
		  if (ourEndian == ENDIAN_LITTLE){
		    pro.offset = to_littleE_int64_t (pro.offset);
		    pro.length = to_littleE_uint16_t (pro.length);
		  }
		  /* memcpy to sendBuff after previous information still in sendBuff */
		  memcpy(sendBuff+bytesSendBuf,&pro,(STRUCT_LEN + hLength));
		  bytesSendBuf += (STRUCT_LEN + hLength);
		}
	      }
	      pro.offset = hOffset;
	      pro.length = hLength;
	      /* Update the offset */
	      pro.offset += pro.length;
	      /* we have something to send, set master wfds */
	      FD_SET(lsds, &mwfds);
	    }
	  }
	}
	else if (FD_ISSET(i,&rfds)){
	  /* read STRUCT_LEN (27) bytes from the server, this gets our header */
	  if ((userB = readn(i,userBuf,STRUCT_LEN,&bufferR))<= 0){  
	    if (userB == -1){
	      fprintf(stderr,"readn Error.\n");
	      exit (1);
	    }
	    else {
	      printf("User closed connection (Server)\n");
	      free(sendBuff);
	      exit(0);
	    }
	  }
	  /*user has sent us userB bytes of infomormation */
	  if (userB > 0){
	    /* store the header from the server into our recveiving protcol struct */
	    memcpy(&proRecv,userBuf,STRUCT_LEN);
	    /* convert to little endian if needed */
	    if (ourEndian == ENDIAN_LITTLE){
	      proRecv.offset = to_littleE_int64_t (proRecv.offset);
	      proRecv.length = to_littleE_uint16_t (proRecv.length);
	    }
	    /* hand shake, the version and md5 must both match */
	    isSame = versionMd5Check(pro.md5,proRecv.md5,ourVersion,proRecv.version);
	    if (isSame == 0){
	      fprintf(stderr,"Incorrect MD5 or Version.\n");
	      exit(1);
	    }
	    /* no longer need the infomation in userBuf, clear it */
	    memset(userBuf,0,sizeof(userBuf));

	    /* read the rest of the message from the server */
	    userB = readn(i,userBuf,proRecv.length,&bufferR);
	    /* dectype the message from the user using the OTP */
	    decryptMessage(proRecv.offset,OTP,userBuf, DMBuf, proRecv.length);
	    /* Null terminate the string */
	    DMBuf[proRecv.length] = '\0';
	    /* print the message to the user */
	    printf("%s",DMBuf);
	    /* no longer need the information from userBuf, clear it */
	    memset(userBuf,0,sizeof(userBuf));
	  }
	}
	/* we have a message that needs to be sent to the server */
	else if(FD_ISSET(i,&wfds)){ 
	  /* send the user the iformation in the buffer sendBuff*/
	  nBytes = send (i,sendBuff,bytesSendBuf,0);
	  /* if we didn't send all of the bytes, update the count left in the buffer
	     and copy the leftover bytes that need to be sent to the start of the buffer */
	  if (nBytes < bytesSendBuf){
	    memcpy(sendBuff,(sendBuff + nBytes),(bytesSendBuf - nBytes));
	    bytesSendBuf = (bytesSendBuf - nBytes);
	  }
	  /* else we have sent all of the information in sendBuff, update the count
	     left in the buffer to 0. Also remove the server fds (lsds) from the 
	     master write fds because we no longer have anything left to send */
	  else {
	    bytesSendBuf = 0;
	    FD_CLR(lsds, &mwfds);
	  }
	}
      }
    }
  }
  return 0;
}
