/**
 * Note : Code is released under the GNU LGPL
 *
 * Copyright (C) 2008 WebStart.fr
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * $Id: mod_sqlalias.c,v 1.23 2011/02/11 21:28:44 adoy Exp $
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "apr_strings.h"
#include "http_request.h"
#include "mod_sqlalias.h"

/* Module declaration */
module AP_MODULE_DECLARE_DATA sqlalias_module;

#ifdef SQLALIAS_USE_PCONNECT
static MYSQL *sqlalias_db_handler = NULL;
static apr_thread_mutex_t *sqlalias_mutex = NULL;
#endif /* SQLALIAS_USE_PCONNECT */

#ifdef SQLALIAS_DEBUG
#define DEBUG_MSG(s, msg, ...) ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, msg, ##__VA_ARGS__ )
#else 
#define DEBUG_MSG(s, msg, ...)
#endif /* SQLALIAS_DEBUG */

static const char *set_sqlalias_query(cmd_parms *cmd, void *mconfig, const char *arg)
{
	server_rec *s = cmd->server;
	sqlalias_conf_t *s_cfg = (sqlalias_conf_t *) ap_get_module_config(s->module_config, &sqlalias_module);
	s_cfg->db_query = (char *) arg;
	return NULL;
}

static const char *set_sqlalias_filter(cmd_parms *cmd, void *mconfig, const char *arg)
{
	ap_regex_t *regexp = NULL;

	server_rec *s = cmd->server;
	sqlalias_conf_t *s_cfg = (sqlalias_conf_t *) ap_get_module_config(s->module_config, &sqlalias_module);

	sqlalias_filter_entry *filter;

	filter = (sqlalias_filter_entry *) apr_array_push(s_cfg->filters);
	filter->pattern = apr_pstrdup(cmd->pool, (char *) arg);

	if ((regexp = (ap_regex_t *)ap_pregcomp(cmd->pool, filter->pattern, 0)) == NULL) {
		return apr_pstrcat(cmd->pool, "SQLAliasFilter: cannot compile regular expression '", filter->pattern , "'", NULL);
	}

	filter->regexp = regexp;
	return NULL;
}


static const char *set_sqlalias_dbparam(cmd_parms *cmd, void *struct_ptr, const char *key, const char *val)
{
	server_rec *s = cmd->server;
	sqlalias_conf_t *s_cfg = (sqlalias_conf_t *) ap_get_module_config(s->module_config, &sqlalias_module);

	if (!s_cfg->parms) {
		s_cfg->parms = apr_table_make(cmd->pool, 5);
	}

	apr_table_set(s_cfg->parms, key, val);
	return NULL;
}


static const char *set_sqlalias_enable(cmd_parms *cmd, void *in_dconf, int flag)
{
	server_rec *s = cmd->server;
	sqlalias_conf_t *s_cfg = (sqlalias_conf_t *) ap_get_module_config(s->module_config, &sqlalias_module);

	s_cfg->enable = flag;
	return NULL;
}


static MYSQL *sqlalias_dbconnect(server_rec *s, sqlalias_conf_t *s_cfg)
{
#ifdef SQLALIAS_USE_PCONNECT
	MYSQL *dblink;
	apr_thread_mutex_lock(sqlalias_mutex);
	dblink = sqlalias_db_handler;
#else
	MYSQL *dblink = NULL;
#endif /* SQLALIAS_USE_PCONNECT */

	
	if(!dblink) {
		dblink = mysql_init(dblink);
	} else if (!mysql_ping(dblink)) {
		return dblink;
	} else {
		const char *host = apr_table_get(s_cfg->parms, "hostname");
		const char *user = apr_table_get(s_cfg->parms, "username");
		const char *passwd = apr_table_get(s_cfg->parms, "password");
		const char *database = apr_table_get(s_cfg->parms, "database");
		const char *s_tcpport = apr_table_get(s_cfg->parms, "port");
		unsigned int tcpport = (s_tcpport)?atoi(s_tcpport):3306;
		const char *socketfile = apr_table_get(s_cfg->parms, "socketfile");

		if (mysql_real_connect(dblink, host, user, passwd, database, tcpport, socketfile, 0)) {
			DEBUG_MSG(s, "sqlalias: Database connection open on mysql://%s:%s@%s:%d/%s (pid:%d)", user, passwd, host, tcpport, database, getpid());

#ifdef SQLALIAS_USE_PCONNECT
			sqlalias_db_handler = dblink;
#endif /* SQLALIAS_USE_PCONNECT */

			return dblink;
		} else {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "sqlalias: Could not connect to database (%s)", mysql_error(dblink));
			mysql_close(dblink);
#ifdef SQLALIAS_USE_PCONNECT	
			apr_thread_mutex_unlock(sqlalias_mutex);
#endif /* SQLALIAS_USE_PCONNECT */
			return NULL;
		}
	}
}

static sqlalias_filter_ret sqlalias_filter(request_rec *r, apr_array_header_t *filters)
{
	int i;
	sqlalias_filter_entry *entries;
	entries = (sqlalias_filter_entry *) filters->elts;

	for (i = 0; i < filters->nelts; i++) {
		sqlalias_filter_entry *filter = &entries[i];

		if(!ap_regexec((ap_regex_t *)filter->regexp, r->uri, 0, NULL, 0)) {
			DEBUG_MSG(r->server, "sqlalias: %s ignored as defined by SQLAliasFilter rule (%s)", r->uri, filter->pattern); 
			return FILTERED_URI;
		}
	}

	return VALID_URI;
}

static int sqlalias_init_handler(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	ap_add_version_component(pconf, MODULE_NAME "/" MODULE_VERSION);
	return OK;
}

/**
 * This function was taken from mod_rewrite
 */
static unsigned is_absolute_uri(char *uri)
{
	/* fast exit */
	if (*uri == '/' || strlen(uri) <= 5) {
		return 0;
	}

	switch (*uri++) {
		case 'f':
		case 'F':
			if (!strncasecmp(uri, "tp://", 5)) {    /* ftp://    */
				return 6;
			}
			break;

		case 'g':
		case 'G':
			if (!strncasecmp(uri, "opher://", 8)) {     /* gopher:// */
				return 9;
			}
			break;

		case 'h':
		case 'H':
			if (!strncasecmp(uri, "ttp://", 6)) {       /* http://   */
				return 7;
			}
			else if (!strncasecmp(uri, "ttps://", 7)) { /* https://  */
				return 8;
			}
			break;
		case 'l': 
		case 'L': 
			if (!strncasecmp(uri, "dap://", 6)) {       /* ldap://   */ 
				return 7; 
			} 
			break; 

		case 'm': 
		case 'M': 
			if (!strncasecmp(uri, "ailto:", 6)) {       /* mailto:   */ 
				return 7; 
			} 
			break; 

		case 'n': 
		case 'N': 
			if (!strncasecmp(uri, "ews:", 4)) {     /* news:     */ 
				return 5; 
			} 
			else if (!strncasecmp(uri, "ntp://", 6)) {  /* nntp://   */ 
				return 7; 
			} 
			break; 
	} 

	return 0; 
} 

static int sqlalias_redir(request_rec *r)
{
	MYSQL *dblink = NULL;

	server_rec *s = r->server;
	sqlalias_conf_t *s_cfg = (sqlalias_conf_t *) ap_get_module_config(s->module_config, &sqlalias_module);

	if (r->uri[0] != '/' && r->uri[0] != '\0') {
		return DECLINED;
	} else if(!s_cfg->enable || sqlalias_filter(r, s_cfg->filters) == FILTERED_URI || !(dblink = sqlalias_dbconnect(r->server, s_cfg))) { 
		return DECLINED;
	} else {
		MYSQL_RES *result = NULL;
		MYSQL_ROW row;

		char *query = NULL;
		int found = 0;
		int response = 0;

		const char *ccp;

		int uri_length = strlen(r->uri);
		char *uri = (char *) malloc(sizeof(char) * (uri_length * 2 + 1));
		strcpy(uri, r->uri);

#ifndef SQLALIAS_PERFECT_MATCH
		if (uri_length > 1 && uri[uri_length-1] == '/') {
			uri[uri_length-1] = '\0';
			uri_length--;
		}
#endif /* SQLALIAS_PERFECT_MATCH */

		mysql_real_escape_string(dblink, uri, uri, uri_length);
		query = apr_psprintf(r->pool, s_cfg->db_query, uri);
		free(uri);

		if(mysql_real_query(dblink, query, strlen(query))) {
			ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r->server, "sqlalias: %s.", mysql_error(dblink));
#ifdef SQLALIAS_USE_PCONNECT	
			apr_thread_mutex_unlock(sqlalias_mutex);
#else
			DEBUG_MSG(r->server, "sqlalias: Database connection closed. (pid:%d)", getpid());
			mysql_close(dblink);
#endif /* SQLALIAS_USE_PCONNECT */
			return DECLINED;
		}

		if (!(result = mysql_store_result(dblink))) {
			ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r->server, "sqlalias: %s.", mysql_error(dblink));

#ifdef SQLALIAS_USE_PCONNECT	
			apr_thread_mutex_unlock(sqlalias_mutex);
#else 
			DEBUG_MSG(r->server, "sqlalias: Database connection closed. (pid:%d)", getpid());
			mysql_close(dblink);
#endif /* SQLALIAS_USE_PCONNECT */

			return DECLINED;
		}


		if((row = mysql_fetch_row(result))) {
			found = 1;
			response = (mysql_num_fields(result) > 1) ? atoi(row[1]) : DECLINED ;

			if(ap_is_HTTP_REDIRECT(response) || (is_absolute_uri(row[0]) && (response = HTTP_MOVED_TEMPORARILY))) {
				char *destination = apr_pstrdup(r->pool, row[0]);
				DEBUG_MSG(r->server, "sqlalias: %s redirect to %s (R=%d)", r->uri, destination, response?response:HTTP_OK);
				apr_table_setn(r->headers_out, "Location", destination);
			} else { 
				DEBUG_MSG(r->server, "sqlalias: rewrite %s -> %s", r->uri, row[0]);
				/* the filename must be either an absolute local path or an
				 * absolute local URL.
				 */
				if (*row[0] != '/' && !ap_os_is_path_absolute(r->pool, row[0])) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "sqlalias: Bad redirection for %s (%s)", r->uri, row[0]);
					response = HTTP_BAD_REQUEST;
				} else if ((ccp = ap_document_root(r)) != NULL) {
					char *q = NULL;

					r->uri = apr_pstrdup(r->pool, row[0]);
					q = strchr(r->uri, '?');
					if (q != NULL) {
						char *olduri = NULL;
						olduri = apr_pstrdup(r->pool, r->uri);
						*q++ = '\0';

						if(r->args)
								r->args = apr_pstrcat(r->pool, q, "&", r->args, NULL);
						else
								r->args = apr_pstrdup(r->pool, q);

						if(strlen(r->args) == 0)
								r->args = NULL;
					}
				}
			}
#ifdef SQLALIAS_DEBUG
		} else {
			DEBUG_MSG(r->server, "sqlalias: No entry for %s", r->uri);
#endif /* SQLALIAS_DEBUG */                       
		}

		mysql_free_result(result);

#ifdef SQLALIAS_USE_PCONNECT
		apr_thread_mutex_unlock(sqlalias_mutex);
#else
		DEBUG_MSG(r->server, "sqlalias: Database connection closed. (pid:%d)", getpid());
		mysql_close(dblink);
#endif /* SQLALIAS_USE_PCONNECT */

		if(found && response != 200) return response;
	}

	return DECLINED;
}


static const command_rec sqlalias_cmds[] =
{
	AP_INIT_FLAG("SQLAliasEnable", set_sqlalias_enable, NULL, OR_FILEINFO, "On or Off to enable or disable the sql aliases (default is off)"),
	AP_INIT_TAKE2("SQLAliasDbParam", set_sqlalias_dbparam, NULL, RSRC_CONF, "SQLALIASDBParam [paramname] [paramvalue]"),
	AP_INIT_TAKE1("SQLAliasQuery", set_sqlalias_query, NULL, RSRC_CONF, "SQLAliasQuery (String) where string is the MySQL query"),
	AP_INIT_TAKE1("SQLAliasFilter", set_sqlalias_filter, NULL, RSRC_CONF, "SQLAliasFilter (String) where string is a Regexp filter"),
	{NULL}
};

#ifdef SQLALIAS_USE_PCONNECT
static apr_status_t sqlalias_cleanup(void *p)
{
	if (sqlalias_db_handler) {
#ifdef SQLALIAS_DEBUG        
		server_rec *s = (server_rec *) p;
		DEBUG_MSG(s, "sqlalias: Database connection closed. (pid:%d)", getpid());
#endif /* SQLALIAS_DEBUG */
		mysql_close(sqlalias_db_handler);
		sqlalias_db_handler = NULL;
	}

	if (sqlalias_mutex) {
		apr_thread_mutex_destroy(sqlalias_mutex);
		sqlalias_mutex = NULL;
	}
	mysql_library_end();
	return APR_SUCCESS;
}

static void sqlalias_child_init(apr_pool_t *p, server_rec *s)
{
	apr_pool_cleanup_register(p, s, sqlalias_cleanup, apr_pool_cleanup_null);
}
#endif /* SQLALIAS_USE_PCONNECT */

static void sqlalias_register_hooks(apr_pool_t *p)
{
	static const char * const aszSucc[] = { "mod_rewrite.c", NULL };

	ap_hook_post_config(sqlalias_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_translate_name(sqlalias_redir, NULL, aszSucc, APR_HOOK_FIRST);

#ifdef SQLALIAS_USE_PCONNECT	
	ap_hook_child_init(sqlalias_child_init, NULL, NULL, APR_HOOK_MIDDLE);
	apr_thread_mutex_create(&sqlalias_mutex, APR_THREAD_MUTEX_DEFAULT, p);
#endif
}


static void *create_sqlalias_cfg(apr_pool_t *p, server_rec *s)
{
	sqlalias_conf_t *newcfg;
	newcfg = (sqlalias_conf_t *) apr_pcalloc(p, sizeof(sqlalias_conf_t));
	newcfg->parms = apr_table_make(p, 5);
	newcfg->filters = apr_array_make(p, 2, sizeof(sqlalias_filter_entry));
	newcfg->db_query = NULL;
	newcfg->enable = 0;
	return (void *) newcfg;
}


module AP_MODULE_DECLARE_DATA sqlalias_module =
{
	STANDARD20_MODULE_STUFF,
	NULL,
	NULL,
	create_sqlalias_cfg,
	NULL,
	sqlalias_cmds,
	sqlalias_register_hooks
};
