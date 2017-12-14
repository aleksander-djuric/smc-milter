/*
 * autospf.h
 *
 * Description:	Basic definitions and Function prototypes
 *
 */

#ifndef _AUTOSPF_H
#define _AUTOSPF_H 1

/* autospf return codes */
enum {
    AUTOSPF_INTERNAL = -1,	/* Internal error */
    AUTOSPF_PASS,		/* Connection address is related to given mail domain */
    AUTOSPF_FAIL,		/* Connection address is not related to given mail domain */
    AUTOSPF_TEMP,		/* DNS lookup gave temporary error */
    AUTOSPF_NONE		/* DNS lookup gave no data */
};

#define DNS_RETRANS	2
#define DNS_RETRY	2
#define MAXADDR		32

int autospf_resolver_init (res_state res_local);
void autospf_resolver_close (res_state res_local);

int autospf_check (const char *client_addr, const char *domain_name,
    int cache_time, res_state res_local);

#endif /* AUTOSPF */
