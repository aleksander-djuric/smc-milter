/*
 * smc-milter.h
 *
 * Description: Basic configuration
 *
 */

#ifndef _SMC_H
#define _SMC_H 1

#define MILTER		"SMC-milter"
#define PROJECT_NAME	"SMC ANTI-SPAM E-MAIL FILTER."
#define COPYRIGHT	"Copyright (c) 2003-2008 Aleksander Djuric. All rights reserved."
#define DEVELOPERS	"Developed by:\n\n \
	Aleksander Djuric <ald@true-audio.com>\n \
	Pavel Zhilin <pzh@true-audio.com>\n \
	Stanislav Ivankin <stas@concat.info>"

#define STAT_LOCAL	1
#define STAT_RELAY	2
#define STAT_WARN	4
#define STAT_TEMP	8
#define STAT_PASS	16

#define MAILER_HEADER	"X-Mailer"
#define FLAG_HEADER	"X-Spam-Flag"
#define REPORT_HEADER	"X-Spam-Report"
#define CHECKER_HEADER	"X-Spam-Checker-Version"
#define CLAMD_HEADER	"X-Virus-Scanned"
#define DEFAULT_USER	"root"
#define DEFAULT_DOMAIN  "localhost"

#define DEFAULT_ACTION	0
#define SOCKET_TIMEOUT	1800
#define MQUEUE_COST	300
#define MQUEUE_LIMIT	2
#define MQUEUE_LIFETIME 3600
#define ACCESS_LIFETIME 604800
#define CACHE_LIFETIME  86400

#define MAXMX		8
#define MAXLINE		4096
#define HEADER_SIZE	MAXLINE
#define HEX_DIGEST	"0123456789ABCDEF"
#define MD5_STRING_LENGTH (MD5_DIGEST_LENGTH * 2)

#endif /* SMC */
