/*
 * utils.c
 *
 * Description:  SMC cache utilities
 * Copyright (c) 2003-2008 Aleksander Djuric.
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <pthread.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <limits.h>
#include <openssl/md5.h>
#include "smc-milter.h"
#include "utils.h"
#include "config.h"

#if !defined O_SYNC && defined O_FSYNC
	#define O_SYNC O_FSYNC
#endif

#ifndef MAXLINE
	#define MAXLINE	4096
#endif

#define HASH_SIZE 65535

typedef struct {
	char key[MD5_STRING_LENGTH + 1];
	rec value;
} pair;

typedef struct {
	pair *items;
	pthread_mutex_t lock;
} db_rec;

static db_rec db_list[5];

#define DBCOUNT (sizeof (db_list) / sizeof(db_rec))

int stfd;
void *stbuf;

void
md5sign (const char *s1, const char *s2, const char *s3, char *sign) {
	unsigned char md[MD5_DIGEST_LENGTH];
	MD5_CTX ctx;
	int i;

	MD5_Init(&ctx);
	if (s1) MD5_Update(&ctx, s1, strlen(s1));
	if (s2) MD5_Update(&ctx, s2, strlen(s2));
	if (s3) MD5_Update(&ctx, s3, strlen(s3));
	MD5_Final(md, &ctx);

	for(i = 0; i < MD5_DIGEST_LENGTH; i++) {
	    sign[i*2] = HEX_DIGEST[*(md + i) >> 4];
	    sign[i*2+1] = HEX_DIGEST[*(md + i) % 16];
	}

	sign[MD5_STRING_LENGTH] = '\0';
}

void
insert_item (db_rec *dbr, const char *key, const rec *value) {
	int i, oldest = 0;
	time_t t;
	
	t = time(NULL) + 1;

	for (i = 0; i < HASH_SIZE; i++) {
	    if (*(dbr->items[i].key) == 0) {
		memcpy(dbr->items[i].key, key, MD5_STRING_LENGTH + 1);
		memcpy(&dbr->items[i].value, value, sizeof(*value));
		msync(dbr->items + i, sizeof(pair), MS_ASYNC);
		return;
	    } else if (dbr->items[i].value.time1 < t) {
		t = dbr->items[i].value.time1;
		oldest = i;
	    }
	}

	memcpy(dbr->items[oldest].key, key, MD5_STRING_LENGTH + 1);
	memcpy(&dbr->items[oldest].value, value, sizeof(*value));
	msync(dbr->items + oldest, sizeof(pair), MS_ASYNC);
}

int
update_item (db_rec *dbr, const char *key, const rec *value) {
	int i;

	for (i = 0; i < HASH_SIZE; i++) {
	    if (memcmp(key, dbr->items[i].key, MD5_STRING_LENGTH) == 0) {
		memcpy(dbr->items[i].key, key, MD5_STRING_LENGTH + 1);
		memcpy(&dbr->items[i].value, value, sizeof(*value));
		msync(dbr->items + i, sizeof(pair), MS_ASYNC);
		return 1;
	    }
	}

	return 0;
}

rec *
find_item (const db_rec *dbr, const char *key) {
	int i;

	for (i = 0; i < HASH_SIZE; i++) {
	    if (memcmp(key, dbr->items[i].key, MD5_STRING_LENGTH) == 0) {
		return &dbr->items[i].value;
	    }
	}	

	return NULL;
}

int
delete_item (db_rec *dbr, const char *key) {
	int i;

	for (i = 0; i < HASH_SIZE; i++) {
	    if (memcmp(key, dbr->items[i].key, MD5_STRING_LENGTH) == 0) {
		*(dbr->items[i].key) = 0;
		msync(dbr->items + i, sizeof(pair), MS_ASYNC);
		return 1;
	    }
	}

	return 0;
}

void
purge_db (db_rec *dbr, int timeout) {
	int i, updated = 0;
	time_t t;

	t = time(NULL) - timeout;

	for (i = 0; i < HASH_SIZE; i++)
	    if (dbr->items[i].value.time1 < t &&
		dbr->items[i].value.flag == 0) {
		*(dbr->items[i].key) = 0;
		updated = 1;
	    }

	if (updated)
	    msync(dbr->items, HASH_SIZE * sizeof(pair), MS_ASYNC);
}

int
init_db (const char *database) {
    	unsigned int i;

	if (access(database, F_OK)) {
	    pair p;
	    memset(&p, 0, sizeof(p));

	    if ((stfd = open(database, O_CREAT|O_RDWR, S_IREAD|S_IWRITE)) == -1) {
			syslog(LOG_ERR, "can't create data file: %s", database);
			return -1;
	    }
	    for (i = 0; i < DBCOUNT * HASH_SIZE; i++)
			if (write(stfd, &p, sizeof(p)) < 0)
				syslog(LOG_ERR, "%s", strerror(errno));
	    lseek(stfd, 0, SEEK_SET);
	} else {
	    if ((stfd = open(database, O_RDWR)) == -1) {
		syslog(LOG_ERR, "can't open data file");
		return -1;
	    }
	}

	if ((stbuf = mmap(NULL, DBCOUNT * HASH_SIZE * sizeof(pair), 
		PROT_READ|PROT_WRITE, MAP_SHARED, stfd, 0)) == NULL) {
	    syslog(LOG_ERR, "can't map data file");
	    return -1;
	}
	
	for (i = 0; i < DBCOUNT; i++) {
	  db_list[i].items = (pair *)(stbuf + (i * HASH_SIZE * sizeof(pair)));
	    pthread_mutex_init(&db_list[i].lock, NULL);
	}

	return 0;
}

void
close_db () {
    	unsigned int i;

	for (i = 0; i < sizeof(db_list) / sizeof(db_rec); i++) {
	    db_list[i].items = NULL;
	    pthread_mutex_destroy(&db_list[i].lock);
	}

	munmap(stbuf, DBCOUNT * HASH_SIZE * sizeof (pair));
	close(stfd);
}

void
add_record (int db_id, const char *rkey, const rec *rdata, int lifetime) {
	pthread_mutex_lock(&db_list[db_id].lock);
	purge_db(db_list + db_id, lifetime);
	insert_item(db_list + db_id, rkey, rdata);
	pthread_mutex_unlock(&db_list[db_id].lock);
}

int
update_record (int db_id, const char *rkey, const rec *rdata) {
	int ret = 0;

	pthread_mutex_lock(&db_list[db_id].lock);
	ret = update_item(db_list + db_id, rkey, rdata);
	pthread_mutex_unlock(&db_list[db_id].lock);

	return ret;
}

int
del_record (int db_id, const char *rkey) {
	int ret = 0;

	pthread_mutex_lock(&db_list[db_id].lock);
	ret = delete_item(db_list + db_id, rkey);
	pthread_mutex_unlock(&db_list[db_id].lock);

	return ret;
}

int
get_record (int db_id, const char *rkey, rec *rdata) {
	rec *data; 
	int ret = 0;

	pthread_mutex_lock(&db_list[db_id].lock);
	if ((data = find_item(db_list + db_id, rkey))) {
	    memcpy(rdata, data, sizeof(rec));
	    ret = 1;
	}
	pthread_mutex_unlock(&db_list[db_id].lock);

	return ret;
}

/* eof */
