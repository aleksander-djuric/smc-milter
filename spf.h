#ifndef _SPF_H
#define _SPF_H 1

/* spf return codes */
enum {
	SPF_INTERNAL = -1,	/* Internal error */
	SPF_INVALID,		/* Could not find a valid SPF record? */
	SPF_NEUTRAL,		/* Exactly like the "None" result */
	SPF_PASS,		/* Client is authorized */
	SPF_FAIL,		/* Client is not authorized */
	SPF_SOFTFAIL,		/* Somewhere between a "Fail" and a "Neutral" */
	SPF_NONE,		/* No records were published by the domain */
	SPF_TEMPERROR,		/* A transient error has occured */
	SPF_PERMERROR		/* A permanent error has occured
				    (eg. badly formatted SPF record) */
};

int spf2_check (char *conn_addr, char *from_addr, int cache_time);

#endif /* SPF */
