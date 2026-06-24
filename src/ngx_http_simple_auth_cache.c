
/*
 * Copyright (C) ngx_http_simple_auth_module contributors
 *
 * Auth result cache hooks. Shared-memory cache can be added here later.
 */

#include "ngx_http_simple_auth_module.h"


ngx_int_t
ngx_http_simple_auth_cache_lookup(ngx_http_request_t *r, ngx_str_t *token,
    ngx_uint_t *status)
{
    ngx_http_simple_auth_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_simple_auth_module);

    if (slcf->cache_valid == 0) {
        return NGX_DECLINED;
    }

    (void) token;
    (void) status;

    return NGX_DECLINED;
}


void
ngx_http_simple_auth_cache_store(ngx_http_request_t *r, ngx_str_t *token,
    ngx_uint_t status)
{
    ngx_http_simple_auth_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_simple_auth_module);

    if (slcf->cache_valid == 0) {
        return;
    }

    (void) r;
    (void) token;
    (void) status;
}


char *
ngx_http_simple_auth_cache_valid(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_simple_auth_loc_conf_t  *slcf = conf;
    ngx_str_t                        *value;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        slcf->cache_valid = 0;
        return NGX_CONF_OK;
    }

    slcf->cache_valid = ngx_parse_time(&value[1], 1);
    if (slcf->cache_valid == (ngx_msec_t) NGX_ERROR) {
        return "invalid value";
    }

    return NGX_CONF_OK;
}
