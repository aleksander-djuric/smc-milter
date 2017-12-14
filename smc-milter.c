/*
 * smc-milter.c
 *
 * Description:	 SMC anti-spam e-mail filter
 * Copyright (c) 2003-2008 Aleksander Djuric.
 * All rights reserved.
 *
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Please see the file COPYING in this directory for full copyright
 * information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <pwd.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/md5.h>
#include "libmilter/mfapi.h"
#include "smc-milter.h"
#include "utils.h"
#include "autospf.h"
#include "spf.h"
#include "config.h"
#include "virus.h"

#if !defined O_SYNC && defined O_FSYNC
#define O_SYNC O_FSYNC
#endif

#ifndef bool
#define bool   int
#define TRUE   1
#define FALSE  0
#endif /* ! bool */

/* Static variables for config defaults, etc. */
static int  runmode    = 0;
static int  terminate  = 0;
static int  nochild    = 0;
static int  action     = DEFAULT_ACTION;
static char *domain    = NULL;
static char *smfisock  = NULL;
static char *smfiuser  = NULL;
static char *pidfile   = NULL;
static char *database  = NULL;
static int  timeout    = 0;
static int  lifetime   = ACCESS_LIFETIME;
static int  cachetime  = CACHE_LIFETIME;
static int  maxcount   = MQUEUE_LIMIT;
static int  maxdelay   = MQUEUE_LIFETIME;
static int  classicspf = 1;
static int  autospf    = 1;
static int  autoswl    = 1;
static int  clamcheck  = 0;
static char *clamsock  = NULL;

struct mlfiPriv {
	unsigned long status;
	char helo_host[MAXLINE];
	char conn_addr[INET_ADDRSTRLEN];
	char conn_host[MAXLINE];
	char from_addr[MAXLINE];
	char messageid[MAXLINE];
	char report[MAXLINE];
	char temp_file[MAXLINE];
	res_state statp;
};

#define MLFIPRIV ((struct mlfiPriv *) smfi_getpriv(ctx))

sfsistat mlfi_cleanup (SMFICTX *ctx, sfsistat rc, bool ok);

void
strtolower (char *str) {

	/* check for required data presented */
	if (!str) return;

	for (; *str; str++) *str = tolower (*str);
}

int
find_user (const char *usersfile, const char *name) {
	FILE *fh;
	char buffer[MAXLINE];
	int found = 0;

	/* check for required data presented */
	if (!name || *name == '\0') return 0;

	if (!(fh = fopen(usersfile, "r"))) return 0;

	while (fgets(buffer, MAXLINE, fh)) {
	    if (*buffer == '\r' || *buffer == '\n' ||
		*buffer == '#' || *buffer == ' ') continue;

	    if (strncasecmp(buffer, name, strlen(name)) == 0) {
		found = 1;
		break;
	    }
	}

	fclose(fh);

	return found;
}

int
check_relay (const char *conn, const char *hosts_file) {
	FILE *fh;
	char buffer[MAXLINE];
	uint32_t addr, network, netmask;
	int d1, d2, d3, d4, m1, m2, m3, m4;
	int found = 0;
	int ret;

	/* check for required data presented */
	if (!conn || *conn == '\0') return 0;
	
	addr = ntohl(inet_addr(conn));

	if ((addr & 0xffffff00) == 0xc0000200     /* 192.0.2.0/24    test network   */
	    ||  (addr & 0xffffff00) == 0xc0586300 /* 192.88.99.0/24  RFC 3068       */
	    ||  (addr & 0xffff0000) == 0xa9fe0000 /* 169.254.0.0/16  link local     */
	    ||  (addr & 0xffff0000) == 0xc0a80000 /* 192.168.0.0/16  private use    */
	    ||  (addr & 0xfffe0000) == 0xc6120000 /* 198.18.0.0/15   RFC 2544       */
	    ||  (addr & 0xfff00000) == 0xac100000 /* 172.16.0.0/12   private use    */
	    ||  (addr & 0xff000000) == 0x00000000 /* 0.0.0.0/8       "this" network */
	    ||  (addr & 0xff000000) == 0x7f000000 /* 127.0.0.0/8     loopback       */
	    ||  (addr & 0xff000000) == 0x0a000000 /* 10.0.0.0/8      private use    */
	    ||  (addr & 0xf0000000) == 0xe0000000 /* 224.0.0.0/4     RFC 3171       */
	    ) return 1;
	
	if (!(fh  = fopen(hosts_file, "r"))) {
	    syslog(LOG_ERR, "failed to open %s: ", hosts_file);
	    return -1;
	}

	while (fgets(buffer, MAXLINE, fh)) {
	    if (*buffer == '\r' || *buffer == '\n' ||
		*buffer == '#' || *buffer == ' ') continue;

	    d1 = d2 = d3 = d4 = 0;
	    m1 = m2 = m3 = m4 = 0;
	    network = netmask = 0;

	    ret = sscanf(buffer, "%3d.%3d.%3d.%3d/%3d.%3d.%3d.%3d",
		&d1, &d2, &d3, &d4, &m1, &m2, &m3, &m4);
	    switch (ret) {
	    case 1: /* 80.80.80 */
	    case 2:
	    case 3:
	    case 4:
		netmask  = (d1|d2|d3|d4) ? 0xff000000 : 0;
		netmask |= (d2|d3|d4) ? 0x00ff0000 : 0;
		netmask |= (d3|d4) ? 0x0000ff00 : 0;
		netmask |= (d4) ? 0x000000ff : 0;
		break;
	    case 5: /* 80.80.80.0/8 */
		if (m1 < 0 || m1 > 32) continue;
		netmask = (0xffffffff & (0xffffffff << (32 - m1)));
		break;
	    case 8: /* 80.80.80.0/255.255.255.0 */
		netmask = (m4 << 24) + ((m3 & 0xff) << 16) + ((m2 & 0xff) << 8) + (m1 & 0xff);
		break;
	    default:
		continue;
	    }

	    network = (d1 << 24) + ((d2 & 0xff) << 16) + ((d3 & 0xff) << 8) + (d4 & 0xff);
	    if ((addr & netmask) == (network & netmask)) {
		found = 1;
		break;
	    }
	}
		
	fclose (fh);
	return found;
}

sfsistat
mlfi_connect (SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr) {
	struct mlfiPriv *priv = MLFIPRIV;
	struct sockaddr_in *conn;

	/* check for private data presented */
	if (priv) return SMFIS_TEMPFAIL;

	/* allocate memory for private data */
	if (!(priv = calloc(1, sizeof(struct mlfiPriv)))) {
	    syslog(LOG_ERR, "%s", strerror(errno));
	    return SMFIS_TEMPFAIL;
	}

	if (!(priv->statp = calloc(1, sizeof *(priv->statp)))) {
	    syslog(LOG_ERR, "%s", strerror(errno));
	    free(priv);
	    return SMFIS_TEMPFAIL;
	}

	/* set private data pointer */
	if (smfi_setpriv(ctx, priv) != MI_SUCCESS) {
	    syslog(LOG_ERR, "can't set private data pointer");
	    free(priv->statp);
	    free(priv);
	    return SMFIS_TEMPFAIL;
	}

	/* initialize autospf resolver */
	if (autospf_resolver_init(priv->statp) < 0) {
	    syslog(LOG_ERR, "couldn't initialize resolver");
	    return mlfi_cleanup(ctx, SMFIS_TEMPFAIL, TRUE);
	}

	/* store connection data */
	if (!hostaddr) strcpy(priv->conn_addr, "127.0.0.1");
	else {
	    conn = (struct sockaddr_in *) hostaddr;
	    if (!inet_ntop(AF_INET, &conn->sin_addr.s_addr,
		priv->conn_addr, INET_ADDRSTRLEN)) {
		syslog(LOG_ERR, "can't parse connect address: %s", strerror(errno));
		return mlfi_cleanup(ctx, SMFIS_TEMPFAIL, TRUE);
	    }
	}
	if (!hostname) strcpy(priv->conn_host, "localhost");
	else strncpy(priv->conn_host, hostname, MAXLINE - 1);

	return SMFIS_CONTINUE;
}

sfsistat
mlfi_helo (SMFICTX *ctx, char *helohost) {
	struct mlfiPriv *priv = MLFIPRIV;

	/* check for private data presented */
	if (!priv) return SMFIS_TEMPFAIL;

	/* check for required data presented */
	if (!helohost || *helohost == '\0') {
	    smfi_setreply(ctx, "501", "5.5.2",
		"HELO requires domain address");
	    return SMFIS_REJECT;
	}

	/* store helo hostname */
	strncpy(priv->helo_host, helohost, MAXLINE - 15);

	return SMFIS_CONTINUE;
}

sfsistat
mlfi_envfrom (SMFICTX *ctx, char **envfrom) {
	struct mlfiPriv *priv = MLFIPRIV;
	char *from_addr, *from_host;

	/* check for private data presented */
	if (!priv) return SMFIS_TEMPFAIL;

	/* check for HELO data presented */
	if (*priv->helo_host == '\0') {
	    smfi_setreply(ctx, "503", "5.0.0", "need HELO before MAIL");
	    return SMFIS_REJECT;
	}

	/* get macro data */
	if (!(from_addr = smfi_getsymval(ctx, "{mail_addr}"))) {
	    syslog(LOG_ERR, "mail_macro: {mail_addr} must be available");
	    return mlfi_cleanup(ctx, SMFIS_TEMPFAIL, FALSE);
	}

	/* workaround bogus address in MAIL FROM: <> */
	if (*from_addr == '\0') {
	    snprintf(priv->from_addr, MAXLINE - 1, "postmaster@%s", priv->helo_host);
	    snprintf(priv->report, MAXLINE - 1, "couldn't verify sender");
	    priv->status |= STAT_WARN;
	    return SMFIS_CONTINUE;
	}

	strtolower(from_addr);
	strncpy(priv->from_addr, from_addr, MAXLINE - 1);

	/* get host part of e-mail address */
	if ((from_host = strrchr(from_addr, '@'))) from_host++;
	    else from_host = domain;

	/* accept local relay connections */
	if (check_relay(priv->conn_addr, HOSTS_FILE) > 0) {
	    priv->status |= STAT_RELAY;
	    return SMFIS_CONTINUE;
	}

	/* Is the user authenticated? */
	if (smfi_getsymval(ctx, "{auth_type}")) {
	    priv->status |= STAT_RELAY;
	    return SMFIS_CONTINUE;
	}

	/* load average at which filter will sleep for one
	   second before accepting incoming connections. */
	usleep(999999);

#ifdef HAVE_LIBSPF2
	if (classicspf)
	switch(spf2_check(priv->conn_addr, priv->from_addr, cachetime)) {
	case SPF_PASS:
	    snprintf(priv->report, MAXLINE - 1,
		"spf: pass (%s: %s permitted to send mail)", from_host, priv->conn_addr);
	    priv->status |= STAT_PASS;
	    return SMFIS_CONTINUE;
	case SPF_FAIL:
	    snprintf(priv->report, MAXLINE - 1,
		"spf: fail (%s: %s denied to send mail)", from_host, priv->conn_addr);
	    smfi_setreply(ctx, "550", "5.7.1", priv->report);
	    return SMFIS_REJECT;
	case SPF_NEUTRAL:
	    snprintf(priv->report, MAXLINE - 1,
		"spf: neutral (%s: %s neither permitted not denied to send mail)", from_host, priv->conn_addr);
	    priv->status |= STAT_WARN;
	    break;
	case SPF_SOFTFAIL:
	    snprintf(priv->report, MAXLINE - 1,
		"spf: softfail (%s: %s not permitted to send mail)", from_host, priv->conn_addr);
	    priv->status |= STAT_WARN;
	    break;
	case SPF_NONE:
	    snprintf(priv->report, MAXLINE - 1,
		"spf: none (%s: no SPF record found)", from_host);
	    priv->status |= STAT_WARN;
	    break;
	case SPF_TEMPERROR:
	    snprintf(priv->report, MAXLINE - 1,
		"spf: temp (%s: error retrieving data from DNS)", from_host);
	    priv->status |= STAT_TEMP;
	    break;
	case SPF_PERMERROR:
	    snprintf(priv->report, MAXLINE - 1,
		"spf: perm (%s: unknown mechanism or syntax error)", from_host);
	    priv->status |= STAT_WARN;
	    break;
	case SPF_INVALID:
	    snprintf(priv->report, MAXLINE - 1,
		"spf: invalid (%s: could not find a valid SPF record)", from_host);
	    priv->status |= STAT_WARN;
	    break;
	case SPF_INTERNAL:
	default:
	    return mlfi_cleanup(ctx, SMFIS_TEMPFAIL, FALSE);
	}
#endif /* HAVE_LIBSPF2 */

	/* do default sender policy check */
	if (autospf)
	switch(autospf_check(priv->conn_addr, from_host, cachetime, priv->statp)) {
	case AUTOSPF_PASS:
	    snprintf(priv->report, MAXLINE - 1,
		"autospf: pass (host %s is related to %s)", priv->conn_addr, from_host);
	    priv->status &= ~STAT_WARN;
	    priv->status |= STAT_PASS;
	    break;
	case AUTOSPF_FAIL:
	    snprintf(priv->report, MAXLINE - 1,
		"autospf: fail (host %s is not related to %s)", priv->conn_addr, from_host);
	    priv->status |= STAT_WARN;
	    break;
	case AUTOSPF_TEMP:
	    snprintf(priv->report, MAXLINE - 1,
		"autospf: temp (DNS lookup of %s [%s] failed)", from_host, priv->conn_addr);
	    priv->status |= STAT_TEMP;
	    break;
	case AUTOSPF_NONE:
	    snprintf(priv->report, MAXLINE - 1,
		"autospf: none (DNS lookup of %s [%s] gave no data)", from_host, priv->conn_addr);
	    priv->status |= STAT_WARN;
	    break;
	case AUTOSPF_INTERNAL:
	default:
	    return mlfi_cleanup(ctx, SMFIS_TEMPFAIL, FALSE);
	}

	return SMFIS_CONTINUE;
}
sfsistat
mlfi_envrcpt (SMFICTX *ctx, char **envrcpt) {
	struct mlfiPriv *priv = MLFIPRIV;
	char report[MAXLINE];
	char md_sign[MD5_STRING_LENGTH + 1];
	char *rcpt_addr, *rcpt_host;
	int ret;
	time_t now = (int) time(NULL);
	rec value;

	/* check for private data presented */
	if (!priv) return SMFIS_TEMPFAIL;

	/* get macro data */
	if (!(rcpt_addr = smfi_getsymval(ctx, "{rcpt_addr}"))) {
	    syslog(LOG_ERR, "rcpt_macro: {rcpt_addr} must be available");
	    return SMFIS_TEMPFAIL;
	}

	/* check local user address */
	if (*rcpt_addr == '\0') {
	    smfi_setreply(ctx, "550", "5.1.1", "user unknown");
	    return SMFIS_REJECT;
	}

	/* get receipient data */
	if ((rcpt_host = strrchr(rcpt_addr, '@'))) rcpt_host++;
	    else rcpt_host = domain;

	/* check for recipient is local */
	if (!strchr(rcpt_addr, '@') || *rcpt_host == '\0')
	    priv->status |= STAT_LOCAL;

	/* accept trust recipients mail */
	if (find_user(USERS_FILE, rcpt_addr)) {
	    priv->status |= STAT_PASS;
	    return SMFIS_CONTINUE;
	}

	/* lowercase recipient address */
	strtolower(rcpt_addr);

	/* accept local and outgoing mail now */
	if ((priv->status & STAT_RELAY)) {
	    if (autoswl) {
		if ((priv->status & STAT_LOCAL)) return SMFIS_CONTINUE;

		/* check access database for backward contact */
		md5sign("autoswl", rcpt_addr, priv->from_addr, md_sign);
		ret = get_record(HASH_ACCESS_DB, md_sign, &value);

		/* update contact statistics */
		value.time1 = now;

		if (!ret) {
		    value.flag = 0;
		    add_record(HASH_ACCESS_DB, md_sign, &value, lifetime);
		} else update_record(HASH_ACCESS_DB, md_sign, &value);
	    }

	    return SMFIS_CONTINUE;
	}

	if (autoswl) {
	    /* check access database for forward contact */
	    md5sign("autoswl", priv->from_addr, rcpt_addr, md_sign);
	    if (get_record(HASH_ACCESS_DB, md_sign, &value)) {

		/* whitelist this contact */
		if (value.flag) value.flag = 1;

		/* update this record */
		value.time1 = now;
		update_record(HASH_ACCESS_DB, md_sign, &value);

		/* accept mail from known senders */
		snprintf(priv->report, MAXLINE - 1,
		    "autoswl: whitelisted sender");
		priv->status |= STAT_PASS;

		return SMFIS_CONTINUE;
	    }
	}

	/* accept mail from trusted senders */
	if (!(priv->status & (STAT_TEMP | STAT_WARN)))
	    return SMFIS_CONTINUE;

	/* do default filter action */
	if (action == 0) return SMFIS_CONTINUE;
	if (action == 1) {
	    if (priv->status & STAT_TEMP) {
		snprintf(report, MAXLINE - 1,
		    "%s, try again later", priv->report);
		smfi_setreply(ctx, "451", "4.7.1", report);
		return SMFIS_TEMPFAIL;
	    }
	    snprintf(report, MAXLINE - 1,
		"rejected for policy reasons, %s", priv->report);
	    smfi_setreply(ctx, "550", "5.7.1", report);
	    return SMFIS_REJECT;
	} /* else action == 2 */

	/* calculate connection md5 digits for this contact */
	md5sign("greylist", priv->conn_host, priv->from_addr, md_sign);

	/* check mqueue database for this contact */
	if (!get_record(HASH_MQUEUE_DB, md_sign, &value)) {

	    /* add new contact to queue */
	    value.time1 = now;
	    value.time2 = now;
	    value.data = 0;
	    value.flag = 0;

	    add_record(HASH_MQUEUE_DB, md_sign, &value, lifetime);
	}

	/* greylisting like algorithm */
	if ((now - value.time2) >= MQUEUE_COST) {
	    if ((now - value.time1) <= maxdelay)
		value.data++;
	    if (value.data >= maxcount) {

		/* whitelist this contact */
		if (value.flag) value.flag = 1;

		/* accept delayed mail */
		return SMFIS_CONTINUE;
	    } else {
		value.time2 = now;
		if ((now - value.time1) > maxdelay) {
		    value.time1 = now;
		    value.data = 0;
		}
	    }

	    /* update this record */
	    update_record(HASH_MQUEUE_DB, md_sign, &value);
	}

	snprintf(report, MAXLINE - 1,
	    "transaction delayed (%d), %s", value.data, priv->report);
	smfi_setreply(ctx, "451", "4.7.0", report);

	return SMFIS_TEMPFAIL;
}

sfsistat
mlfi_header (SMFICTX *ctx, char *headerf, char *headerv) {
	struct mlfiPriv *priv = MLFIPRIV;

	/* check for private data presented */
	if (!priv) return SMFIS_TEMPFAIL;

	/* check for required data presented */
	if (!headerf || !headerv)
	    return mlfi_cleanup(ctx, SMFIS_TEMPFAIL, FALSE);

	/* skip null headers */
	if (*headerf == '\0') return SMFIS_CONTINUE;

	/* get message-id if found */
	if (strcasecmp(headerf, "Message-ID") == 0)
	    strncpy(priv->messageid, headerv, MAXLINE - 1);

	return SMFIS_CONTINUE;
}

sfsistat
mlfi_body (SMFICTX *ctx, u_char *bodyp, size_t len) {
	struct mlfiPriv *priv = MLFIPRIV;
	char buffer[MAXLINE];
	int fd, ret;

	/* check for private data presented */
	if (!priv) return SMFIS_TEMPFAIL;

	/* check for required data presented */
	if (!bodyp)
	    return mlfi_cleanup(ctx, SMFIS_TEMPFAIL, FALSE);

	/* skip code if not enabled */
	if (!clamcheck) return SMFIS_CONTINUE;

	/* open message body tempfile */
	if (*priv->temp_file == '\0') {
	    strcpy(priv->temp_file, TMP_FILE);
	    if ((fd = mkstemp(priv->temp_file)) < 0) {
		syslog(LOG_ERR, "can't make message tempfile: %s", strerror(errno));
		return mlfi_cleanup(ctx, SMFIS_TEMPFAIL, FALSE);
	    }
	    fchmod(fd, S_IWUSR|S_IRUSR|S_IRGRP|S_IROTH);

	    /* add message-id header for clamav */
	    ret = snprintf(buffer, MAXLINE - 1,
		"Message-ID: %s\n\n", priv->messageid);
	    if (ret > 0 && write(fd, buffer, ret) < 0)
		syslog(LOG_ERR, "%s", strerror(errno));

	} else {
	    if ((fd = open(priv->temp_file, O_WRONLY|O_APPEND|O_CREAT|O_SYNC, 0644)) < 0) {
		syslog(LOG_ERR, "can't open message tempfile: %s", strerror(errno));
		return mlfi_cleanup(ctx, SMFIS_TEMPFAIL, FALSE);
	    }
	}

	/* append body chunk */
	if (write(fd, bodyp, len) < 0)
	    syslog(LOG_ERR, "%s", strerror(errno));

	close(fd);

	return SMFIS_CONTINUE;
}

sfsistat
mlfi_eom (SMFICTX *ctx) {
	struct mlfiPriv *priv = MLFIPRIV;
	int add_headers = 0;
	char report[MAXLINE];
	int ret;

	/* check for private data presented */
	if (!priv) return SMFIS_TEMPFAIL;

	/* add headers only for incoming mail */
	if (!(priv->status & STAT_RELAY)) add_headers = 1;

	/* add checker headers */
	if (add_headers) {
	    if ((priv->status & STAT_PASS))
		smfi_addheader(ctx, FLAG_HEADER, "PASS");
	    else if ((priv->status & STAT_WARN))
		smfi_addheader(ctx, FLAG_HEADER, "WARN");
	    else smfi_addheader(ctx, FLAG_HEADER, "NO");
	    if (*priv->report)
		smfi_addheader(ctx, REPORT_HEADER, priv->report);
	    smfi_addheader(ctx, CHECKER_HEADER, MILTER " " VERSION);
	}

	if (clamcheck) {
	    ret = clamd_check(priv->temp_file, report, clamsock);
	    switch (ret) {
	    case CLAMD_OK:
		if (add_headers) 
		    smfi_addheader(ctx, CLAMD_HEADER, "ClamAV using " MILTER);
		break;
	    case CLAMD_FOUND:
		smfi_setreply(ctx, "554", "5.6.1", report);
		return mlfi_cleanup(ctx, SMFIS_REJECT, FALSE);
		break;
	    }
	}

	return mlfi_cleanup(ctx, SMFIS_CONTINUE, FALSE);
}

sfsistat
mlfi_cleanup (SMFICTX *ctx, sfsistat rc, bool ok) {
	struct mlfiPriv *priv = MLFIPRIV;

	/* check for private data presented */
	if (!priv) return rc;

	/* unlink temporary file */
	if (*priv->temp_file)
	    unlink(priv->temp_file);
		
	if (ok) {
	    /* close autospf resolver files */
	    autospf_resolver_close(priv->statp);

	    /* release private memory */
	    if (priv->statp)
		free(priv->statp);
	    free(priv);
	    smfi_setpriv(ctx, NULL);

	    return rc;
	}

	/* cleanup per-message data */
	*priv->from_addr = '\0';
	*priv->temp_file = '\0';
	*priv->messageid = '\0';

	return rc;
}

sfsistat
mlfi_abort (SMFICTX *ctx) {
	return mlfi_cleanup(ctx, SMFIS_CONTINUE, FALSE);
}

sfsistat
mlfi_close (SMFICTX *ctx) {
	return mlfi_cleanup(ctx, SMFIS_CONTINUE, TRUE);
}

struct smfiDesc smfilter = {
	MILTER,		/* filter name */
	SMFI_VERSION,	/* version code -- do not change */
	SMFIF_ADDHDRS,
	/* flags */
	mlfi_connect,	/* connection info filter */
	mlfi_helo,	/* SMTP HELO command filter */
	mlfi_envfrom,	/* envelope sender filter */
	mlfi_envrcpt,	/* envelope recipient filter */
	mlfi_header,	/* header filter */
	NULL,		/* end of header */
	mlfi_body,	/* body block filter */
	mlfi_eom,	/* end of message */
	mlfi_abort,	/* message aborted */
	mlfi_close,	/* connection cleanup */
	NULL,		/* unknown SMTP commands */
	NULL,		/* DATA command */
	NULL		/* Once, at the start of each SMTP connection */
};

int
read_config (void) {
	FILE *fh = fopen(CONFIG_FILE, "r");
	char buffer[MAXLINE], value[MAXLINE];

	if (!fh) return -1;
	
	while (fgets(buffer, MAXLINE, fh))
	if (*buffer == '#') {
	    continue;
	} else if (strncasecmp("user", buffer, 4) == 0) {
	    sscanf(buffer, "%*s %s", value);
	    if (!smfiuser) smfiuser = strdup(value);
	    else syslog(LOG_ERR, "config: 'user' value will not be changed");
	} else if (strncasecmp("domain", buffer, 6) == 0) {
	    sscanf(buffer, "%*s %s", value);
	    if (!domain) domain = strdup(value);
	    else syslog(LOG_ERR, "config: 'domain' value will not be changed");
	} else if (strncasecmp("socket", buffer, 6) == 0) {
	    sscanf(buffer, "%*s %s", value);
	    if (!smfisock) smfisock = strdup(value);
	    else syslog(LOG_ERR, "config: 'socket' value will not be changed");
	} else if (strncasecmp("timeout", buffer, 7) == 0) {
	    sscanf(buffer, "%*s %d", &timeout);
	    if (timeout < 0) {
		syslog(LOG_ERR, "negative timeout value '%d', using default\n", timeout);
		timeout = SOCKET_TIMEOUT;
	    }
	} else if (strncasecmp("action", buffer, 6) == 0) {
	    sscanf(buffer, "%*s %d", &action);
	    if (action < 0 || action > 2) {
		syslog(LOG_ERR, "invalid action value '%d', using default", action);
		action = DEFAULT_ACTION;
	    }
	} else if (strncasecmp("classicspf", buffer, 10) == 0) {
	    sscanf(buffer, "%*s %s", value);
	    classicspf = strcasecmp(value, "yes")? 0 : 1;
#ifndef HAVE_LIBSPF2
	    syslog(LOG_ERR, "config: support for 'classicspf' was not built");
#endif
	} else if (strncasecmp("autospf", buffer, 7) == 0) {
	    sscanf(buffer, "%*s %s", value);
	    autospf = strcasecmp(value, "yes")? 0 : 1;
	} else if (strncasecmp("autoswl", buffer, 7) == 0) {
	    sscanf(buffer, "%*s %s", value);
	    autoswl = strcasecmp(value, "yes")? 0 : 1;
	} else if (strncasecmp("clamcheck", buffer, 9) == 0) {
	    sscanf(buffer, "%*s %s", value);
	    clamcheck = strcasecmp(value, "yes")? 0 : 1;
	} else if (strncasecmp("clamsocket", buffer, 10) == 0) {
	    sscanf(buffer, "%*s %s", value);
	    if (!clamsock) clamsock = strdup(value);
	    else syslog(LOG_ERR, "config: 'clamsocket' value will not be changed");
	} else if (strncasecmp("pidfile", buffer, 7) == 0) {
	    sscanf(buffer, "%*s %s", value);
	    if (!pidfile) pidfile = strdup(value);
	    else syslog(LOG_ERR, "config: 'pidfile' value will not be changed");
	} else if (strncasecmp("database", buffer, 9) == 0) {
	    sscanf(buffer, "%*s %s", value);
	    if (!database) database = strdup(value);
	    else syslog(LOG_ERR, "config: 'database' value will not be changed");
	}else if (strncasecmp("lifetime", buffer, 8) == 0) {
	    sscanf(buffer, "%*s %d", &lifetime);
	} else if (strncasecmp("cachetime", buffer, 9) == 0) {
	    sscanf(buffer, "%*s %d", &cachetime);
	} else if (strncasecmp("maxdelay", buffer, 8) == 0) {
	    sscanf(buffer, "%*s %d", &maxdelay);
	} else if (strncasecmp("maxcount", buffer, 8) == 0) {
	    sscanf(buffer, "%*s %d", &maxcount);
	    if (maxcount > 255) {
		syslog(LOG_ERR, "maxcount is too big '%d', using default\n", maxcount);
		maxcount = MQUEUE_LIMIT;
	    }
	}

	if (!domain)   domain   = strdup(DEFAULT_DOMAIN);
	if (!smfiuser) smfiuser = strdup(DEFAULT_USER);
	if (!smfisock) smfisock = strdup(SOCKET_FILE);
	if (!pidfile)  pidfile  = strdup(PID_FILE);
	if (!database) database = strdup(CACHE_FILE);
	if (!timeout)  timeout  = SOCKET_TIMEOUT;
	if (!clamsock) clamsock = strdup(CLAMD_SOCKET_FILE);

	fclose(fh);
	return 0;
}

void
usage () {
	printf("Usage:\t" PACKAGE "\t[-fhv]\n\n");
}

void
version () {
	printf(PROJECT_NAME " version " VERSION "\n" COPYRIGHT "\n\n");
}

void
help () {
	version();
	usage();
	printf("\t-f\t\t\tRun milter in the foreground.\n");
	printf("\t-v\t\t\tShow program version.\n");
	printf("\t-h\t\t\tShow this help.\n\n");
	printf("Program recognises the following config file options:\n\n");
	printf("\t[user username]\t\tSpecifies the user the milter should\n");
	printf("\t\t\t\trun as after it initializes.\n");
	printf("\t[domain name]\t\tSMTP domain name.\n");
	printf("\t[action value]\t\tDefault filter action in numeric context:\n");
	printf("\t\t\t\t0 if 'accept'; 1 if 'reject' and 2 if 'greylist' the\n");
	printf("\t\t\t\tmail which has not passed the filter checks.\n");
	printf("\t[socket path]\t\tPath to create socket.\n");
	printf("\t[pidfile path]\t\tPath to pid file.\n");
	printf("\t[database path]\t\tPath to database file.\n");
	printf("\t[timeout seconds]\tSocket connection timeout.\n");
	printf("\t[classicspf (yes|no)]\tEnable or disable classic SPF checks.\n");
	printf("\t[autospf (yes|no)]\tEnable or disable AutoSPF checks.\n");
	printf("\t[autoswl (yes|no)]\tEnable or disable AutoSWL feature.\n");
	printf("\t[clamcheck (yes|no)]\tEnable or disable mail checks\n");
	printf("\t\t\t\tusing ClamAV antivirus.\n");
	printf("\t[clamsocket path]\tPath to ClamAV socket.\n");
	printf("\t[lifetime time]\t\tDatabase records lifetime.\n");
	printf("\t[cachetime time]\tCache records lifetime.\n");
	printf("\t[maxdelay time]\t\tConnect counter lifetime.\n");
	printf("\t[maxcount count]\tConnect counter limit.\n\n");

	printf("Program settings:\n\n");
	printf("\tuser\t\t\t[%s]\n", smfiuser);
	printf("\tdomain\t\t\t[%s]\n", domain);
	printf("\taction\t\t\t[%d]\n", action);
	printf("\tsocket\t\t\t[%s]\n", smfisock);
	printf("\tpidfile\t\t\t[%s]\n", pidfile);
	printf("\tdatabase\t\t[%s]\n", database);
	printf("\ttimeout\t\t\t[%d]\n", timeout);
	printf("\tclassicspf\t\t[%s]\n", (classicspf) ? "yes" : "no");
	printf("\tautospf\t\t\t[%s]\n", (autospf) ? "yes" : "no");
	printf("\tautoswl\t\t\t[%s]\n", (autoswl) ? "yes" : "no");
	printf("\tclamcheck\t\t[%s]\n", (clamcheck) ? "yes" : "no");
	printf("\tclamsocket\t\t[%s]\n", clamsock);
	printf("\tlifetime\t\t[%d]\n", lifetime);
	printf("\tcachetime\t\t[%d]\n", cachetime);
	printf("\tmaxdelay\t\t[%d]\n", maxdelay);
	printf("\tmaxcount\t\t[%d]\n\n", maxcount);
	printf("Default location of files:\n\n");
	printf("\tConfig file:\t\t%s\n", CONFIG_FILE);
	printf("\tHosts file:\t\t%s\n", HOSTS_FILE);
	printf("\tUsers file:\t\t%s\n", USERS_FILE);
	printf("\tDatabase file:\t\t%s\n", CACHE_FILE);
	printf("\tSocket file:\t\t%s\n", SOCKET_FILE);
	printf("\tPID file:\t\t%s\n", PID_FILE);
	printf("\tTemporary file:\t\t%s\n", TMP_FILE);
	printf("\tClamAV socket file:\t%s\n\n", CLAMD_SOCKET_FILE);

	printf("%s\n\n", DEVELOPERS);
}

void 
signal_handler (int sig) {
	switch (sig) {
	case SIGINT:
	case SIGTERM:
	    terminate = 1;
	    break;
	case SIGCHLD:
	    nochild = 1;
	    break;
	}
}

void
signal_setup (void) {
	signal(SIGCHLD, signal_handler);
	signal(SIGINT,  signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGHUP,  SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	nochild = 0;
}

int
create_pid (const char *pidfile, pid_t pid) {
	char buffer[16];
	pid_t spid;
	int fd;

	if (access(pidfile, R_OK) == 0) {
	    if ((fd = open(pidfile, O_RDONLY)) < 0)
		return -1;

	    if (read(fd, buffer, sizeof(buffer)) < 0) {
		close(fd);
		return -1;
	    }

	    close(fd);
	    sscanf(buffer, "%d", &spid);

	    if (spid == pid) return 0;
	    if ((kill(spid, 0) < 0) && errno == ESRCH)
		unlink(pidfile);
	    else return 1;
	}

	if (!pid) return 0;

	if ((fd = open(pidfile, O_RDWR|O_TRUNC|O_CREAT, 0644)) < 0)
	    return -1;

	/* put my pid in it */
	sprintf(buffer, "%d", pid);
	if (write(fd, buffer, strlen(buffer)) < 0)
	    syslog(LOG_ERR, "%s", strerror(errno));
	
	close(fd);

	return 0;
}

void 
start_phoenix (void) {
	int i;
	pid_t pid;

start:
	/* remove old socket if found */
	unlink(smfisock);

	/* setup signals */
	signal_setup();

	/* specify the socket to use */
	if (smfi_setconn(smfisock) == MI_FAILURE) return;

	/* set socket timeout */
	if (smfi_settimeout(timeout) == MI_FAILURE) return;

	/* register the filter */
	if (smfi_register(smfilter) == MI_FAILURE) return;

	switch ((pid = fork())) {
	case -1:
	    syslog(LOG_ERR, "could not fork new process: %s",
		strerror(errno));
	    return;
	case 0:
	  if (init_db(database) < 0)
		exit(EX_UNAVAILABLE);

	    /* open syslog */
	    openlog(PACKAGE, 0, LOG_DAEMON);

	    /* set file creation mask */
	    umask(S_IXUSR|S_IXGRP|S_IXOTH);

	    /* ignore signals */
	    signal(SIGTTOU, SIG_IGN);
	    signal(SIGTTIN, SIG_IGN);
	    signal(SIGTSTP, SIG_IGN);
	    signal(SIGHUP,  SIG_IGN);
	    signal(SIGPIPE, SIG_IGN);

	    /* hand control to libmilter */
	    if (smfi_main() != MI_SUCCESS) {
		syslog(LOG_ERR, "shutdown abnormally");
		exit(EX_UNAVAILABLE);
	    }

	    closelog();
	    close_db ();

	    exit(EX_OK);
	}

	while (!terminate && !nochild) sleep(1);

	if (terminate) {
	    syslog(LOG_INFO, "stopping..");
	    kill(0, SIGTERM);
	    waitpid(0, NULL, 0);
	    return;
	}

	/* terminate processes */
	for (i = 0; i < 4; i++) {
	    if (kill(-pid, SIGTERM) < 0) {
		waitpid(-pid, NULL, 0);
		if (kill(pid, SIGTERM) < 0) {
		    waitpid(pid, NULL, 0);
		    sleep(1);
		    break;
		}
		usleep(999999);
	    }
	}

	/* rip threads */
	kill(-pid, SIGKILL);
	waitpid(-pid, NULL, 0);

	/* rip child */
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);

	/* reload configuration */
	syslog(LOG_INFO, "Reload configuration");

	if (read_config() < 0)
	    syslog(LOG_ERR, "Can't read config file: %s", CONFIG_FILE);

	goto start;
}

int
main (int argc, char **argv) {
	int c;
	extern int optind;
	struct passwd *pw;
	pid_t pid;

	/* get configuration file options */
	if (read_config() < 0) {
	    fprintf(stderr, "Can't read config file: %s\n", CONFIG_FILE);
	    exit(EXIT_FAILURE);
	}

	/* process command line options */
	while ((c = getopt(argc, argv, "fhv:")) != -1) {
	    switch (c) {
	    case 'f':
		runmode = 1;
		break;
	    case 'h':
		help();
		exit(EX_OK);
	    case 'v':
		version();
		exit(EX_OK);
	    default:
		usage();
		exit(EX_USAGE);
	    }
	}

	if ((pw = getpwnam(smfiuser)) == NULL) {
	    fprintf(stderr, "%s: user '%s' not found\n", PACKAGE, smfiuser);
	    exit(EX_USAGE);
	}

	/* avoid running as root user and/or group */
	if (getuid() == 0 && pw->pw_uid != 0 && pw->pw_gid != 0) {
	    if (setgid(pw->pw_gid) || setuid(pw->pw_uid)) {
		fprintf(stderr, "%s: setgid or setuid failed\n", PACKAGE);
		exit(EXIT_FAILURE);
	    }
	}
	
	/* check pid file */
	switch (create_pid(pidfile, 0)) {
	case -1:
	    fprintf(stderr, "%s: can't create pid file: %s\n", PACKAGE, pidfile);
	    exit(EXIT_FAILURE);
	    break;
	case 1:
	    fprintf(stderr, "%s: filter is already running..\n", PACKAGE);
	    exit(EX_OK);
	    break;
	}

	if (runmode == 0) {
	    /* ignore signals */
	    signal(SIGTTOU, SIG_IGN);
	    signal(SIGTTIN, SIG_IGN);
	    signal(SIGTSTP, SIG_IGN);
	    signal(SIGHUP,  SIG_IGN);
	    signal(SIGPIPE, SIG_IGN);

	    /* run in background */
	    if ((pid = daemon(0, 0)) < 0) {
		fprintf(stderr, "%s: could not run filter in background, %s",
		    PACKAGE, strerror(errno));
		exit(EX_OSERR);
	    }
	    if (pid != 0) exit(EX_OK);
	}

	/* open syslog */
	openlog(PACKAGE, 0, LOG_USER | LOG_DAEMON);

	/* get new pid */
	pid = getpid();

	/* create pid file */
	if (create_pid(pidfile, pid)) {
	    syslog(LOG_ERR, "can't create pid file %s", pidfile);
	    exit(EX_UNAVAILABLE);
	}

	syslog(LOG_INFO, "running in %s as user '%s'",
	    (runmode) ? "foreground" : "background", pw->pw_name);

	/* start the filter */
	start_phoenix();

	if (domain)   free(domain);
	if (smfiuser) free(smfiuser);
	if (smfisock) free(smfisock);
	if (clamsock) free(clamsock);
	if (pidfile)  free(pidfile);
	if (database) free(database);

	closelog();
	exit(EX_OK);
}

/* eof */
