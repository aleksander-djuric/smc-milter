/*
 * autospf.c
 *
 * Description:  AutoSPF support
 * Copyright (c) 2003-2008 Aleksander Djuric.
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include <sysexits.h>
#include <openssl/md5.h>
#include <pthread.h>
#include <pwd.h>
#include "smc-milter.h"
#include "autospf.h"
#include "utils.h"

#define MAXPACKET	8192
#define PWD_SIZE	256
#define MAXPREF		66000
#define MAXHOSTS	8

#ifndef MAXLINE
	#define MAXLINE	4096
#endif

typedef union {
	HEADER hdr;
	u_char buf[MAXPACKET];
} querybuf;

int
get_addr_list (res_state statp, const char *host, u_int32_t *addr) {
	querybuf answer;
	register u_char *cp, *eom;
	int count, type, dlen, ret, ac;

	ret = res_nquery(statp, host, C_IN, T_A,
	    (u_char *) &answer, sizeof(answer));

	if (ret < 0) return ret;

	eom = answer.buf + ret;
	cp = answer.buf + sizeof(HEADER);
	cp += dn_skipname(cp, eom) + QFIXEDSZ;
	count = ntohs(answer.hdr.ancount);
	ac = 0;

	while (--count >= 0 && cp < eom) {
	    int n = dn_skipname(cp, eom);

	    cp += n;
	    if (n < 0 || cp + 3 * INT16SZ + INT32SZ > eom)
		break;

	    GETSHORT(type, cp);
	    cp += (INT16SZ + INT32SZ);
	    GETSHORT(dlen, cp);

	    if (type == T_A) {
		if (ac >= MAXADDR-1 || cp + INADDRSZ > eom) break;
		*addr++ = ((struct in_addr*)cp)->s_addr;
		ac++;
		cp += INADDRSZ;
	    } else cp += dlen;
	}

	return ac;
}

int
_autospf_check (const char *client_addr, const char *domain_name, res_state statp) {
	querybuf answer;
	uint32_t host_addr;
	char host_name[MAXDNAME];
	char client_name[MAXDNAME];
	register u_char *cp, *eom;
	int count, type, dlen, pref, ret;
	char nsaddr_list[MAXHOSTS][MAXDNAME];
	int nscount = 0, found = 0;
	int i, d1, d2, d3, d4, ac;
	u_int32_t addrs[MAXADDR];

	/* AutoSPF algorithm:

	DNS-based Sender Policy. Make conclusion about mail domain relation
	to given connection address using available DNS data.

	Copyright (c) 2003-2008 Aleksander Djuric. All rights reserved.
	Please see the file COPYING in this directory for full copyright
	information. */

	/* STAGE 1: Look up MX records for the given domain name.
	Compare connection address with each of the mx host ip ipaddress(es).
	Connection address is related to the given mail domain if found */
	ret = res_nquery(statp, domain_name, C_IN, T_MX,
	    (u_char *) &answer, sizeof(answer));

	if (ret < 0) {
	    switch (statp->res_h_errno) {
	    case NETDB_INTERNAL:
		syslog(LOG_MAIL|LOG_ERR, "%s: resolver error: %d",
		    __func__, statp->res_h_errno);
		return AUTOSPF_INTERNAL;
	    case TRY_AGAIN:
		return AUTOSPF_TEMP;
	    default:
		return AUTOSPF_NONE;
	    }
	}

	eom = answer.buf + ret;
	cp = answer.buf + sizeof(HEADER);
	cp += dn_skipname(cp, eom) + QFIXEDSZ;
	count = ntohs(answer.hdr.ancount);
	host_addr = inet_addr(client_addr);

	while (--count >= 0 && cp < eom) {
	    int n = dn_skipname(cp, eom);

	    cp += n;
	    if (n < 0 || cp + 3 * INT16SZ + INT32SZ > eom)
		break;

	    GETSHORT(type, cp);
	    cp += (INT16SZ + INT32SZ);
	    GETSHORT(dlen, cp);

	    if (type == T_MX) {
		if (cp + INT16SZ > eom) break;

		GETSHORT(pref, cp);
		if ((ret = dn_expand(answer.buf, eom,
		    cp, host_name, MAXDNAME-1)) < 0) {
		    return AUTOSPF_INTERNAL;
		}
		cp += ret;

		ac = get_addr_list(statp, host_name, addrs);
		if (ac < 0) {
		    if (statp->res_h_errno == NETDB_INTERNAL) {
			syslog(LOG_MAIL|LOG_ERR, "%s: resolver error: %d",
			    __func__, statp->res_h_errno);
			return AUTOSPF_INTERNAL;
		    }
		    continue;
		}

		for (--ac; ac >= 0; ac--)
		    if (host_addr == addrs[ac])
			return AUTOSPF_PASS;
	    } else cp += dlen;
	}

	/* STAGE 2: Look up NS records for the given domain name. Make reverse
	PTR record for connection address. Look up NS records for the connection
	address PTR record. Compare each of NS host of the connection address
	PTR record with each of NS hosts of the mail domain name. Connection
	address is related to the given mail domain if found. */
	ret = res_nquery(statp, domain_name, C_IN, T_NS,
	    (u_char *) &answer, sizeof(answer));

	if (ret < 0) {
	    switch (statp->res_h_errno) {
	    case NETDB_INTERNAL:
		syslog(LOG_MAIL|LOG_ERR, "%s: resolver error: %d",
		    __func__, statp->res_h_errno);
		return AUTOSPF_INTERNAL;
	    case TRY_AGAIN:
		return AUTOSPF_TEMP;
	    default:
		return AUTOSPF_NONE;
	    }
	}

	eom = answer.buf + ret;
	cp = answer.buf + sizeof(HEADER);
	cp += dn_skipname(cp, eom) + QFIXEDSZ;
	count = ntohs(answer.hdr.ancount);

	while (--count >= 0 && cp < eom) {
	    int n = dn_skipname(cp, eom);

	    cp += n;
	    if (n < 0 || cp + 3 * INT16SZ + INT32SZ > eom)
		break;

	    GETSHORT(type, cp);
	    cp += (INT16SZ + INT32SZ);
	    GETSHORT(dlen, cp);

	    if (type == T_NS) {
		if (nscount >= MAXHOSTS-1) break;
		if ((ret = dn_expand(answer.buf, eom,
		    cp, host_name, MAXDNAME-1)) < 0)
		    return AUTOSPF_INTERNAL;
		cp += ret;
		strcpy(nsaddr_list[nscount++], host_name);
	    } else cp += dlen;
	}

	if (sscanf(client_addr, "%3d.%3d.%3d.%3d", &d1, &d2, &d3, &d4) == 4)
	    sprintf(client_name, "%d.%d.%d.%d.in-addr.arpa", d4, d3, d2, d1);
	else return AUTOSPF_INTERNAL;

	ret = res_nquery(statp, client_name, C_IN, T_PTR,
	    (u_char *) &answer, sizeof(answer));

	if (ret < 0) {
	    switch (statp->res_h_errno) {
	    case NETDB_INTERNAL:
		syslog(LOG_MAIL|LOG_ERR, "%s: resolver error: %d",
		    __func__, statp->res_h_errno);
		return AUTOSPF_INTERNAL;
	    case TRY_AGAIN:
		return AUTOSPF_TEMP;
	    default:
		return AUTOSPF_NONE;
	    }
	}

	eom = answer.buf + ret;
	cp = answer.buf + sizeof(HEADER);
	cp += dn_skipname(cp, eom) + QFIXEDSZ;
	count = ntohs(answer.hdr.ancount) + ntohs(answer.hdr.nscount);

	while (--count >= 0 && cp < eom) {
	    int n = dn_skipname(cp, eom);

	    cp += n;
	    if (n < 0 || cp + 3 * INT16SZ + INT32SZ > eom)
		break;

	    GETSHORT(type, cp);
	    cp += (INT16SZ + INT32SZ);
	    GETSHORT(dlen, cp);

	    if (type == T_PTR && !found) {
		if ((ret = dn_expand(answer.buf, eom,
		    cp, client_name, MAXDNAME-1)) < 0)
		    return AUTOSPF_INTERNAL;
		cp += ret;
		found = 1;
	    } else if (type == T_NS) {
		if ((ret = dn_expand(answer.buf, eom,
		    cp, host_name, MAXDNAME-1)) < 0)
		    return AUTOSPF_INTERNAL;
		cp += ret;

		for (i = 0; i < nscount; i++)
		    if (strcasecmp(nsaddr_list[i], host_name) == 0)
			return AUTOSPF_PASS;
	    } else cp += dlen;
	}

	if (!found) return AUTOSPF_FAIL;

	/* STAGE 3: Look up NS records for the resolved hostname of
	the connection address. Compare each of NS host of the hostname,
	resolved from connection address, with each of NS hosts of the
	mail domain name. Connection address is related to the given
	mail domain if found */
	ret = res_nquery(statp, client_name, C_IN, T_ANY,
	    (u_char *) &answer, sizeof(answer));

	if (ret < 0) {
	    switch (statp->res_h_errno) {
	    case NETDB_INTERNAL:
		syslog(LOG_MAIL|LOG_ERR, "%s: resolver error: %d",
		    __func__, statp->res_h_errno);
		return AUTOSPF_INTERNAL;
	    case TRY_AGAIN:
		return AUTOSPF_TEMP;
	    default:
		return AUTOSPF_NONE;
	    }
	}

	eom = answer.buf + ret;
	cp = answer.buf + sizeof(HEADER);
	cp += dn_skipname(cp, eom) + QFIXEDSZ;
	count = ntohs(answer.hdr.ancount) +
		ntohs(answer.hdr.nscount);

	while (--count >= 0 && cp < eom) {
	    int n = dn_skipname(cp, eom);

	    cp += n;
	    if (n < 0 || cp + 3 * INT16SZ + INT32SZ > eom)
		break;

	    GETSHORT(type, cp);
	    cp += (INT16SZ + INT32SZ);
	    GETSHORT(dlen, cp);

	    if (type == T_NS) {
		if ((ret = dn_expand(answer.buf, eom,
		    cp, host_name, MAXDNAME-1)) < 0)
		    return AUTOSPF_INTERNAL;
		cp += ret;

		for (i = 0; i < nscount; i++)
		    if (strcasecmp(nsaddr_list[i], host_name) == 0)
			return AUTOSPF_PASS;
	    } else cp += dlen;
	}

	return AUTOSPF_FAIL;
}

int
autospf_check (const char *client_addr, const char *domain_name,
	int cache_time, res_state statp) {
	char md_sign[MD5_STRING_LENGTH + 1];
	rec value;
	time_t t;
    	int ret;
	
	t = time(NULL);

	md5sign("autospf", domain_name, client_addr, md_sign);

	if (get_record(HASH_AUTOSPF_DB, md_sign, &value)) {
	    if ((t - value.time1 < cache_time)) return value.data;
	    else del_record(HASH_AUTOSPF_DB, md_sign);
	}

	ret = _autospf_check(client_addr, domain_name, statp);

	if (ret != AUTOSPF_INTERNAL &&
	    ret != AUTOSPF_TEMP) {
	    value.time1 = t;
	    value.time2 = t;
	    value.data = ret;
	    add_record(HASH_AUTOSPF_DB, md_sign, &value, cache_time);
	}

	return ret;
}

int
autospf_resolver_init (res_state statp) {
	if (res_ninit(statp) < 0)
	    return -1;

	statp->options &= ~(RES_DEFNAMES|RES_DNSRCH);
	statp->options |= (RES_STAYOPEN|RES_USEVC);
	statp->retrans = DNS_RETRANS;
	statp->retry = DNS_RETRY;

	return 0;
}

void
autospf_resolver_close (res_state statp) {
	if (statp->options & RES_INIT)
	    res_nclose(statp);
}

/* eof */
