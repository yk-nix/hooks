/*
 * hooks.c
 *
 *  Created on: 2023年3月22日
 *      Author: yui
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <libconfig.h>
#include <sys/types.h>
#include <mqueue.h>

#include "vsftpd/logging.h"
#include "vsftpd/session.h"

#define MQ_CONFIG_FILE "/etc/mq/mq.conf"

typedef struct MQ {
	char *name;
	int priority;
} MQ;

typedef struct MQs {
	MQ *peccancy;
	MQ *log;
	MQ *alert;
	MQ *plate;
	MQ *oplog;
} MQs;

static MQs vsf_mqs = { 0 };

static void inline mq_init(MQ **mq, const char *name, int priority) {
	MQ *_mq = NULL;
	if (*mq == NULL) {
		_mq = malloc(sizeof(MQ));
		*mq = _mq;
	}
	else {
		_mq = *mq;
	}
	_mq->name = strdup(name);
	_mq->priority = priority;
}

static void mq_free(MQ **mq) {
	if (*mq) {
		if ((*mq)->name)
			free((*mq)->name);
		free(*mq);
		*mq = NULL;
	}
}

static void load_module_config_file(const char *config_file) {
	if (access(config_file, R_OK))
		return;
	config_t config = { 0 };
	config_init(&config);
	if (config_read_file(&config, config_file) != CONFIG_TRUE)
		return;
	config_setting_t *mqs = config_lookup(&config,"mqs");
	if (mqs == NULL)
		return;
	int idx = 0;
	config_setting_t *elem = NULL;
	while ((elem = config_setting_get_elem(mqs, idx++))) {
		const char *name = NULL;
		int size = 0, priority = 0;
		if (config_setting_lookup_string(elem, "name", &name) != CONFIG_TRUE)
			continue;
		if (config_setting_lookup_int(elem, "size", &size) != CONFIG_TRUE)
			continue;
		config_setting_lookup_int(elem, "priority", &priority);
		if (size <= 0)
			continue;
		if (strcmp(name, "/peccancy") == 0)
			mq_init(&vsf_mqs.peccancy, name, priority);
		else if (strcmp(name, "/alert") == 0)
			mq_init(&vsf_mqs.alert, name, priority);
		else if (strcmp(name, "/plate") == 0)
			mq_init(&vsf_mqs.plate, name, priority);
		else if (strcmp(name, "/log") == 0)
			mq_init(&vsf_mqs.log, name, priority);
		else if (strcmp(name, "/oplog") == 0)
			mq_init(&vsf_mqs.oplog, name, priority);
	}
	config_destroy(&config);
}

static int file_append_line(const char *path, const char *txt) {
	int ret = -1;
	FILE *fp = fopen(path, "a+");
	if (fp == NULL)
		return ret;
	ret = fprintf(fp, "%s\n", txt);
	fclose(fp);
	return ret;
}

static void mq_write(const char *msg, int len,  MQ *ctx) {
//	char buf[256] = { 0 };
//	const char *log = "/tmp/hooks.list";
	mqd_t mq = mq_open(ctx->name, O_WRONLY, 0, NULL);
//	sprintf(buf, "msg:%s len:%d name:%s prio:%d  mqd:%d mq_open: %s", msg, len, ctx->name, ctx->priority, mq, strerror(errno));
//	file_append_line(log, buf);
	if (mq == -1) {
		return;
	}
	mq_send(mq, msg, len, ctx->priority);
	mq_close(mq);
}

void *vsf_hook_module_init(const char *config_file) {
	if (config_file != NULL) {
		load_module_config_file(config_file);
	}
	return &vsf_mqs;
}

void vsf_hook_module_release(void *module_ctx) {
	MQs *mqs = module_ctx;
	if (mqs->alert)
		mq_free(&mqs->alert);
	if (mqs->peccancy)
		mq_free(&mqs->peccancy);
	if (mqs->log)
		mq_free(&mqs->log);
	if (mqs->oplog)
		mq_free(&mqs->oplog);
	if (mqs->plate)
		mq_free(&mqs->plate);
}

void vsf_hook_rnto_ok (void *opaque) {
	struct vsf_session *sess = (struct vsf_session *)opaque;
	//char name[64] = { 0 };
	char *name = sess->ftp_arg_str.PRIVATE_HANDS_OFF_p_buf;
	int ext_start_posi = sess->ftp_arg_str.PRIVATE_HANDS_OFF_len - 4;
	if (ext_start_posi < 10)
		return;
	MQs *mqs = (MQs*)sess->hook_module_context;
	char *ext = name + ext_start_posi;
	if (ext[0] == '.') {
		if ((ext[1] == 'x' || ext[1] == 'X') &&
			(ext[2] == 'm' || ext[2] == 'M') &&
			(ext[3] == 'l' || ext[3] == 'L')) {
			if (name[0] == 'A' && name[1] == 'L' && mqs->alert) {
				mq_write(sess->ftp_arg_str.PRIVATE_HANDS_OFF_p_buf, sess->ftp_arg_str.PRIVATE_HANDS_OFF_len, mqs->alert);
			}
			else if (name[0] == 'L' && name[1] == 'O' && name[2] == 'G' && mqs->log) {
				mq_write(sess->ftp_arg_str.PRIVATE_HANDS_OFF_p_buf, sess->ftp_arg_str.PRIVATE_HANDS_OFF_len, mqs->log);
			}
			else if (name[0] == 'O' && name[1] == 'P' && name[2] == 'L' &&
				name[3] == 'O' && name[4] == 'G' && mqs->oplog) {
				mq_write(sess->ftp_arg_str.PRIVATE_HANDS_OFF_p_buf, sess->ftp_arg_str.PRIVATE_HANDS_OFF_len, mqs->oplog);
			}
			else if (name[1] == '_' && mqs->peccancy) {
				mq_write(sess->ftp_arg_str.PRIVATE_HANDS_OFF_p_buf, sess->ftp_arg_str.PRIVATE_HANDS_OFF_len, mqs->peccancy);
			}
		}
	}
}
