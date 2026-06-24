
/*
 * Copyright (C) ngx_http_simple_auth_module contributors
 */

#ifndef NGX_HTTP_SIMPLE_AUTH_MODULE_H
#define NGX_HTTP_SIMPLE_AUTH_MODULE_H


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX     "Bearer "
#define NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX_LEN 7

#define NGX_HTTP_SIMPLE_AUTH_VERIFY_URI          "/__ngx_simple_auth_verify__"


typedef struct {
    ngx_flag_t                auth_enable;
    ngx_str_t                 auth_backend;
    ngx_str_t                 token_param_key;
    ngx_str_t                 upstream_schema;
    ngx_str_t                 auth_uri;
    ngx_str_t                 auth_host_header;
    ngx_msec_t                cache_valid;
    ngx_http_upstream_conf_t  upstream;
} ngx_http_simple_auth_loc_conf_t;


typedef struct {
    ngx_uint_t            done;
    ngx_uint_t            status;
    ngx_http_request_t   *request;
    ngx_http_request_t   *subrequest;
} ngx_http_simple_auth_ctx_t;


extern ngx_module_t  ngx_http_simple_auth_module;


/* ngx_http_simple_auth_module.c */
char *ngx_http_simple_auth_parse_backend(ngx_conf_t *cf,
    ngx_http_simple_auth_loc_conf_t *slcf);
void ngx_http_simple_auth_set_host_header(ngx_conf_t *cf, ngx_url_t *u,
    ngx_str_t *host_header);
char *ngx_http_simple_auth_check_loc_conf(ngx_conf_t *cf, void *conf);

ngx_int_t ngx_http_simple_auth_has_bearer(ngx_http_request_t *r);
ngx_int_t ngx_http_simple_auth_get_arg(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value);
ngx_int_t ngx_http_simple_auth_get_bearer_token(ngx_http_request_t *r,
    ngx_str_t *token);
ngx_int_t ngx_http_simple_auth_set_bearer(ngx_http_request_t *r,
    ngx_str_t *token);
ngx_int_t ngx_http_simple_auth_deny(ngx_http_request_t *r, ngx_uint_t status);

ngx_int_t ngx_http_simple_auth_start_verify(ngx_http_request_t *r,
    ngx_http_simple_auth_ctx_t *ctx);

/* ngx_http_simple_auth_upstream.c */
ngx_int_t ngx_http_simple_auth_rewrite_init(ngx_conf_t *cf);
void ngx_http_simple_auth_verify_upstream(ngx_http_request_t *r);
ngx_int_t ngx_http_simple_auth_verify_finalize(ngx_http_request_t *r,
    ngx_uint_t status);

/* ngx_http_simple_auth_cache.c */
char *ngx_http_simple_auth_cache_valid(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_http_simple_auth_cache_lookup(ngx_http_request_t *r,
    ngx_str_t *token, ngx_uint_t *status);
void ngx_http_simple_auth_cache_store(ngx_http_request_t *r, ngx_str_t *token,
    ngx_uint_t status);


#endif /* NGX_HTTP_SIMPLE_AUTH_MODULE_H */
