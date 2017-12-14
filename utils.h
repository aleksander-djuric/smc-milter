/*
 * utils.h
 *
 * Description:	Basic definitions and Function prototypes
 *
 */

#ifndef _UTILS_H
#define _UTILS_H 1

#define HASH_ACCESS_DB	0
#define HASH_MQUEUE_DB	1
#define HASH_AUTOSPF_DB	2
#define HASH_SPF2_DB	3

typedef struct {
	time_t time1;
	time_t time2;
	u_int16_t data;
	u_int16_t flag;
} rec;

void md5sign (const char *s1, const char *s2, const char *s3, char *sign);
void add_record (int db_id, const char *rkey, const rec *rdata, int lifetime);
int del_record (int db_id, const char *rkey);
int get_record (int db_id, const char *rkey, rec *rdata);
int update_record (int db_id, const char *rkey, const rec *rdata);
int init_db (const char *database);
void close_db();

#endif /* UTILS */
