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

#include <stdio.h>
#include <unistd.h>
#include <sys/select.h>
#include <errno.h>

#ifdef __DEMO__
#include <stdlib.h>
#include <stdint.h>

#define BUF_SZ	20
#endif /* __DEMO__ */

#include "lib.h"

/* type used internally for calls to is_ready */
typedef enum _io_type_t {
    TEST_READ,
    TEST_WRITE,
    TEST_EXCEPTION
} io_type_t;

/* ----------------------------------------------------------------------------
   is_ready:
     Determine whether a file descriptor is ready for the indicated operation,
     i.e., it won't block for the operation.
   Arguments:
     int	file descriptor to check
     io_type_t	type of test: TEST_READ, TEST_WRITE, or TEST_EXCEPTION
   Return values:
     -1		error (see errno)
      0		file descriptor is not ready for reading
      1		file descriptor is ready for reading
---------------------------------------------------------------------------- */
static int is_ready (int fd, io_type_t type)
{
    struct timeval tv = { 0, 0 };	/* use a timeout of 0 */
    fd_set fds;
    int rdy;

Retry:
    FD_ZERO (&fds);
    FD_SET (fd, &fds);
    rdy = select (fd + 1,
		  type == TEST_READ      ? &fds : NULL,
		  type == TEST_WRITE     ? &fds : NULL,
		  type == TEST_EXCEPTION ? &fds : NULL,
		  &tv);
    if (rdy == -1) {
	if (errno == EINTR)
	    goto Retry;
	return -1;
    }

    return rdy;
}

/* ----------------------------------------------------------------------------
   buffered_read:
     Obtain the next byte from a file descriptor, using a buffer to improve
     the performance.
   Arguments:
     fd		file descriptor to read
     ptr	location to save single character
     st		state used with this file descriptor
   Return values:
     -2		would have blocked
     -1		error (see errno)
      0		EOF
      1		byte saved at ptr
---------------------------------------------------------------------------- */
static ssize_t buffered_read(int fd, char *ptr, fdstat *st)
{
    /* if we do not have buffered data... */
    if (st->read_cnt <= 0) {
	/* check whether the descriptor will block for a read */
	switch (is_ready (fd, TEST_READ)) {
	case -1:
	    return -1; /* error */
	case 0:
	    return -2; /* try later */
	}

	/* read the data (will *not* block) */
Retry:
	if ((st->read_cnt = read (fd, st->read_buf,
				  sizeof (st->read_buf))) < 0) {
	    if (errno == EINTR)
		goto Retry;
	    /* error */
	    return -1;
	} else if (st->read_cnt == 0) {
	    /* EOF */
	    return 0;
	}

	/* update our pointer */
	st->read_ptr = st->read_buf;
    }

    /* provide a byte of buffered data */
    st->read_cnt--;
    *ptr = *(st->read_ptr)++;

    return 1;
}

/* ----------------------------------------------------------------------------
   readline
---------------------------------------------------------------------------- */
ssize_t readline (int fd, void *vptr, size_t maxlen, fdstat *st)
{
    int rc, n;
    char c;

    if (st->ptr == NULL) {
	/* set the pointer, which we'll iterate through the string, only
	   on the first call */
	st->ptr = vptr;
	st->maxlen = maxlen;
	st->n = 1;
    }
    for (; st->n < st->maxlen; (st->n)++) {
	if ((rc = buffered_read (fd, &c, st)) == 1) {
	    /* obtained one byte */
	    *(st->ptr)++ = c;
	    if (c == '\n')
		break; /* newline is stored, like fgets() */
	} else if (rc == 0) {
	    /* EOF */
	    return 0;
	} else if (rc == -2) {
	    /* would block */
	    return -2;
	} else
	    /* error, errno set by read() */
	    return -1;
    }

    /* null terminate like fgets() */
    *(st->ptr) = '\0';

    n = st->ptr - (char *)vptr;

    /* setting st->ptr to NULL will cause next call to reset
       the necessary state variables */
    st->ptr = NULL;

    return (n);
}

/* ----------------------------------------------------------------------------
   readn
---------------------------------------------------------------------------- */
ssize_t readn (int fd, void *vptr, size_t n, fdstat *st)
{
    /* if the first call -- or first call after reading a block... */
    if (st->nleft == 0) {
	st->ptr = vptr;
	st->nleft = n;
    }

    while (st->nleft > 0) {
	switch (is_ready (fd, TEST_READ)) {
	case -1:
	    return -1; /* error */
	case 0:
	    return -2; /* not ready; try later */
	}

Retry:
	if ((st->nread = read (fd, st->ptr, st->nleft)) < 0) {
	    if (errno == EINTR)
		goto Retry; /* and call read() again */
	    /* error */
	    return -1;
	} else if (st->nread == 0) {
	    /* EOF */
	    return 0;
	}

	/* advance buffer and reduce remaining */
	st->nleft -= st->nread;
	st->ptr += st->nread;
    }

    return n;
}

/* ========================================================================= */

#ifdef __DEMO__
int main (int argc, char *argv[])
{
    fdstat stdin_state;
    fd_set rfds;
    int rdy, type;

    /* check usage */
    if (argc != 2) {
	fprintf (stderr, "Usage: %s type\n"
		 "  type   0 for lines, 1 for blocks\n", argv[0]);
	exit (1);
    }

    type = atoi (argv[1]);

    /* reset the state structure that we'll use for standard input */
    FDSTAT_RESET (stdin_state);

    while (1) {
	FD_ZERO (&rfds);
	FD_SET (fileno (stdin), &rfds);

Retry:
	fprintf (stderr, "\nselect (call)\n");
	if ((rdy = select (fileno (stdin) + 1, &rfds, NULL, NULL, NULL)) == -1) {
	    if (errno == EINTR)
		goto Retry;
	    perror ("select");
	    exit (1);
	}
	fprintf (stderr, "select returned\n");

	if (FD_ISSET (fileno (stdin), &rfds)) {
	    uint8_t buf[BUF_SZ];
	    int count;

	    if (type == 0) {
		count = readline (fileno (stdin), buf, BUF_SZ - 1, &stdin_state);
		fprintf (stderr, "readline returned %d\n", count);
	    } else {
		count = readn (fileno (stdin), buf, BUF_SZ - 1, &stdin_state);
		fprintf (stderr, "readn returned %d\n", count);
	    }

	    if (count == -1) {
		perror ("read");
		exit (1);
	    } else if (count == 0) {
		/* EOF */
		break;
	    } else if (count > 0) {
		/* add NUL terminator and print */
		buf[count] = '\0';
		printf ("[%s]\n", buf);
	    }
	}
    }

    return 0;
}
#endif /* __DEMO__ */
