/* ============================================================================
   Course: CMPT 361
   Author: Nicholas Boers
   Date: Sept. 2013

   Version: 1.02

   Functions that may prove useful for non-blocking I/O.

   Acknowledgements:
     Parts of 'buffered_read' and 'readline' copied/inspired by readline.c and
     readn.c in UNIX Network Programming.
       http://www.kohala.com/start/unpv12e.html
============================================================================ */

#ifndef _LIB_H
#define _LIB_H

#define READ_BUF_SZ	65537	/* internal buffer size; use 16 bits + 1 (for
				   the NUL terminator) */

/* This structure maintains state between calls to readline/readn.  For each
   file descriptor that you use with this library, you must create one of
   these structures.  Before using this structure, you must pass it to
   FDSTAT_RESET. */
typedef struct _fdstat {
    /* used by buffered_read */
    int read_cnt;
    char *read_ptr;
    char read_buf[READ_BUF_SZ];
    /* used by readline */
    int n;
    size_t maxlen;
    /* used by readn */
    size_t nleft;
    ssize_t nread;
    /* used by readn and readline */
    char *ptr;
} fdstat;

/* This macro prepares a new fdstat structure for use with readline/readn. */
#define FDSTAT_RESET(st)	do {					\
	st.read_cnt = 0;						\
	st.read_ptr = NULL;						\
	st.read_buf[0] = '\0';						\
	st.n = 0;							\
	st.maxlen = 0;							\
	st.nleft = 0;							\
	st.nread = 0;							\
	st.ptr = NULL;							\
    } while (0)

/* ----------------------------------------------------------------------------
   readline:
     Read a single line from the file descriptor, up to the maximum length.
     The buffer must be allocated in advance, and it won't be NUL terminated.
   Arguments:
     int	file descriptor
     void *	buffer for storing the bytes
     size_t	maximum length
     fdstat *	state to maintain between calls
   Return values:
     -2		incomplete; would have blocked
     -1		error (see errno)
      0		EOF
     >0		bytes read (does not return partial lines)
---------------------------------------------------------------------------- */
ssize_t readline (int, void *, size_t, fdstat *);

/* ----------------------------------------------------------------------------
   readn:
     Read a block of bytes from the file descriptor.  The buffer must be
     allocated in advance, and it won't be NUL terminated.
   Arguments:
     int	file descriptor
     void *	buffer for storing the bytes
     size_t	maximum length
     fdstat *	state to maintain between calls
   Return values:
     -2		incomplete; would have blocked
     -1		error (see errno)
      0		EOF
     >0		bytes read (maximum length)
---------------------------------------------------------------------------- */
ssize_t readn (int, void *, size_t, fdstat *);

#endif /* _LIB_H */
