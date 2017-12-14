/*
 * virus.h
 *
 * Description:	Basic definitions and Function prototypes
 *
 */

#ifndef _VIRUS_H
#define _VIRUS_H 1

#ifndef MAXLINE
    #define MAXLINE	4096
#endif

#define RECV_TIMEOUT	60
#define SEND_TIMEOUT	60

int clamd_check (const char *filename, char *report, const char *clamsock);

/* clamd_check return codes */
#define CLAMD_ERROR	-1	// ClamAV returns error message
#define CLAMD_OK	0	// No viruses found
#define CLAMD_FOUND	1	// Virus found
#define CLAMD_MALFORMED	2	// Malformed message from clamav, possible
				// message format has changed

#endif /* VIRUS */
