#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/md5.h>
#include "smc-milter.h"
#include "config.h"
#include "utils.h"

#ifdef HAVE_LIBSPF2

#include <spf2/spf.h>
#include "spf.h"

#define SPF_RESULT_INTERNAL -1

int
_spf2_check (char *conn_addr, char *from_addr)
{
	SPF_server_t *spf_server = NULL;
	SPF_request_t *spf_request = NULL;
	SPF_response_t *spf_response = NULL;
	int ret = SPF_RESULT_INTERNAL;

	spf_server = SPF_server_new(SPF_DNS_CACHE, 0);
	if (!spf_server) {
		syslog(LOG_ERR, "%s: SPF engine init failed", __func__);
		goto spffail;
	}

	spf_request = SPF_request_new(spf_server);
	if (!spf_request) {
		syslog(LOG_ERR, "%s: can't create SPF request", __func__);
		goto spferr;
	}

	SPF_request_set_ipv4_str(spf_request, conn_addr);
	SPF_request_set_env_from(spf_request, from_addr);

	SPF_request_query_mailfrom(spf_request, &spf_response);
	if (!spf_response) {
		syslog(LOG_ERR, "%s: no SPF response", __func__);
		goto spferr;
	}

	ret = SPF_response_result(spf_response);
	if (spf_response) SPF_response_free(spf_response);

spferr:
	if (spf_request) SPF_request_free(spf_request);
	SPF_server_free(spf_server);
	
spffail:
	return ret;
}

int
spf2_check (char *conn_addr, char *from_addr, int cache_time)
{
	char md_sign[MD5_STRING_LENGTH + 1];
	rec value;
	time_t t;
    	int ret = SPF_INTERNAL;

	t = time(NULL);

	md5sign("spf2", conn_addr, from_addr, md_sign);

	if (get_record(HASH_SPF2_DB, md_sign, &value)) {
	    if ((t - value.time1 < cache_time))
		return value.data;
	    else del_record(HASH_SPF2_DB, md_sign);
	}

	/* Need to translate SPF response */
	switch (_spf2_check(conn_addr, from_addr)) {
	case SPF_RESULT_INVALID: ret = SPF_INVALID; break;
	case SPF_RESULT_NEUTRAL: ret = SPF_NEUTRAL; break;
	case SPF_RESULT_PASS: ret = SPF_PASS; break;
	case SPF_RESULT_FAIL: ret = SPF_FAIL; break;
	case SPF_RESULT_SOFTFAIL: ret = SPF_SOFTFAIL; break;
	case SPF_RESULT_NONE: ret = SPF_NONE; break;
	case SPF_RESULT_TEMPERROR: ret = SPF_TEMPERROR; break;
	case SPF_RESULT_PERMERROR: ret = SPF_PERMERROR; break;
	}

	if (ret != SPF_INTERNAL &&
	    ret != SPF_TEMPERROR) {
	    value.time1 = t;
	    value.time2 = t;
	    value.data = ret;
	    add_record(HASH_SPF2_DB, md_sign, &value, cache_time);
	}

	return ret;
}

#endif /* HAVE_LIBSPF2 */
