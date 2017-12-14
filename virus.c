/*
 * virus.c
 *
 * Description:  SMC support for ClamAV
 * Copyright (c) 2003-2008 Aleksander Djuric.
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include "smc-milter.h"
#include "virus.h"

inline void
close_sock (int sock) {
	while (close(sock) == -1 && errno == EINTR);
}

int
set_sock_conn (const char *sockpath) {
	int sock;
	struct sockaddr_un us;

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		syslog(LOG_ERR, "can't create socket: %s", strerror(errno));
		return -1;
	}

	memset(&us, 0, sizeof(struct sockaddr));
	us.sun_family = AF_UNIX;
	strncpy(us.sun_path, sockpath, sizeof(us.sun_path) - 1);
	us.sun_path[sizeof(us.sun_path) - 1] = '\0';

	if (connect(sock, (struct sockaddr*) &us, sizeof(us.sun_family) + strlen(us.sun_path) + 1) != 0)  {
		syslog(LOG_ERR, "can't connect to clamd daemon socket: %s", strerror(errno));
		close_sock(sock);
		return -1;
	}
	
	return sock;
}

int
clamd_send (int fd, const char *buffer, int count) {
	fd_set wfds;
	struct timeval tv;
	int ret;

	tv.tv_sec = SEND_TIMEOUT;
	tv.tv_usec = 0;

	FD_ZERO(&wfds);
	FD_SET(fd, &wfds);

	do {
		ret = select(fd + 1, 0, &wfds, 0, &tv);
	} while (ret < 0 && errno == EINTR);
	if (ret <= 0 || !FD_ISSET(fd, &wfds)) return -1;

	do {
		ret = send(fd, buffer, count, MSG_NOSIGNAL);
	} while (ret < 0 && errno == EINTR);
	if (ret <= 0) return -1;

	return ret;
}

int
clamd_recv (int fd, char *buffer, int count) {
	fd_set rfds;
	struct timeval tv;
	int ret;

	tv.tv_sec = RECV_TIMEOUT;
	tv.tv_usec = 0;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	do {
		ret = select(fd + 1, &rfds, 0, 0, &tv);
	} while (ret < 0 && errno == EINTR);
	if (ret <= 0 || !FD_ISSET(fd, &rfds)) return -1;

	do {
		ret = recv(fd, buffer, count, MSG_NOSIGNAL);
	} while (ret < 0 && errno == EINTR);
	if (ret <= 0) return -1;

	buffer[ret] = '\0';
	return ret;
}


int
clamd_check (const char *filename, char *report, const char *clamsock) {
	char buffer[MAXLINE];
	int sock, ret;
	char *p, *q;
	
	/* check for required data presented */
	if (!filename || !report) return -1;

	/* clean up the report */
	*report = '\0';

	if ((sock = set_sock_conn(clamsock)) == -1)
		return CLAMD_ERROR;

	if ((ret = snprintf(buffer, MAXLINE, "nSCAN %s\n", filename)) < 0) {
		syslog(LOG_ERR, "can't fill the enquiry buffer");
		close_sock(sock);
		return CLAMD_ERROR;
	}

	/* Checking file for viruses */
	if (clamd_send(sock, buffer, ret) < 0) {
		syslog(LOG_ERR, "unable to send message to clamd: %s", strerror(errno));
		close_sock(sock);
		return CLAMD_ERROR;
	}

	ret = clamd_recv(sock, buffer, MAXLINE - 1);
	close_sock(sock);

	if (ret <= 0 || ret > MAXLINE) {
		syslog(LOG_ERR, "can't read from clamd: %s", strerror(errno));
		return CLAMD_ERROR;
	}

	if ((p = strrchr(buffer, ' '))) {
		*p = '\0'; p++;
	} else 	p = buffer;

	if (!strncmp(p, "OK", 2))
		return CLAMD_OK;

	if (!strncmp(p, "ERROR", 5)) {
		syslog(LOG_ERR, "clamd: error '%s'", buffer);
		return CLAMD_ERROR;
	}
	if (!strncmp(p, "FOUND", 5)) {
		if ((q = strrchr(buffer, ' ')))
			snprintf(report, MAXLINE - 1, "clamd: virus found '%s'", q + 1);
		return CLAMD_FOUND;
	}

	syslog(LOG_ERR, "clamd: unrecognized response: '%s'", p);
	return CLAMD_MALFORMED;
}

/* eof */
