
/*
 * Copyright (C) ngx_http_simple_auth_module contributors
 *
 * Directives, configuration merge, ACCESS phase handler, credentials.
 */

#include "ngx_http_simple_auth_module.h"


static ngx_int_t ngx_http_simple_auth_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_simple_auth_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_simple_auth_preconf(ngx_conf_t *cf);
static ngx_int_t ngx_http_simple_auth_target_backend_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_simple_auth_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_simple_auth_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_simple_auth_auth_backend(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_simple_auth_commands[] = {

    { ngx_string("auth_enable"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_simple_auth_loc_conf_t, auth_enable),
      NULL },

    { ngx_string("auth_backend"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_simple_auth_auth_backend,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("token_param_key"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_simple_auth_loc_conf_t, token_param_key),
      NULL },

    { ngx_string("auth_cache_valid"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_simple_auth_cache_valid,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_simple_auth_module_ctx = {
    ngx_http_simple_auth_preconf,
    ngx_http_simple_auth_init,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_simple_auth_create_loc_conf,
    ngx_http_simple_auth_merge_loc_conf
};


ngx_module_t  ngx_http_simple_auth_module = {
    NGX_MODULE_V1,
    &ngx_http_simple_auth_module_ctx,
    ngx_http_simple_auth_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_simple_auth_vars[] = {

    { ngx_string("target_backend"), NULL,
      ngx_http_simple_auth_target_backend_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE, 0 },

      ngx_http_null_variable
};


static ngx_int_t
ngx_http_simple_auth_preconf(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_simple_auth_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_simple_auth_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_simple_auth_handler;

    if (ngx_http_simple_auth_rewrite_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void *
ngx_http_simple_auth_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_simple_auth_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_simple_auth_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->auth_enable = NGX_CONF_UNSET;
    conf->cache_valid = NGX_CONF_UNSET_MSEC;

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = NGX_CONF_UNSET;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 0;
    conf->upstream.ignore_client_abort = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;

    return conf;
}


static char *
ngx_http_simple_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_simple_auth_loc_conf_t  *prev = parent;
    ngx_http_simple_auth_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->auth_enable, prev->auth_enable, 0);
    ngx_conf_merge_str_value(conf->auth_backend, prev->auth_backend, "");
    ngx_conf_merge_str_value(conf->token_param_key, prev->token_param_key, "token");

    ngx_conf_merge_str_value(conf->upstream_schema, prev->upstream_schema, "");
    ngx_conf_merge_str_value(conf->auth_uri, prev->auth_uri, "");
    ngx_conf_merge_str_value(conf->auth_host_header, prev->auth_host_header, "");
    ngx_conf_merge_msec_value(conf->cache_valid, prev->cache_valid, 0);

    ngx_conf_merge_value(conf->upstream.ignore_client_abort,
                         prev->upstream.ignore_client_abort, 1);
    ngx_conf_merge_value(conf->upstream.socket_keepalive,
                         prev->upstream.socket_keepalive, 0);
    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);
    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);
    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);
    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                                 prev->upstream.next_upstream,
                                 (NGX_CONF_BITMASK_SET
                                  |NGX_HTTP_UPSTREAM_FT_ERROR
                                  |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (conf->auth_backend.len > 0) {
        if (ngx_http_simple_auth_parse_backend(cf, conf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return ngx_http_simple_auth_check_loc_conf(cf, conf);
}


static char *
ngx_http_simple_auth_auth_backend(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_simple_auth_loc_conf_t  *slcf = conf;
    ngx_str_t                        *value, *backend;

    value = cf->args->elts;
    backend = &value[1];

    if (backend->len == 0) {
        return "invalid auth_backend value";
    }

    if (ngx_strncmp(backend->data, (u_char *) "http://", 7) == 0
        || ngx_strncmp(backend->data, (u_char *) "https://", 8) == 0)
    {
        slcf->auth_backend = *backend;
    } else {
        slcf->auth_backend.len = backend->len + sizeof("http://") - 1;
        slcf->auth_backend.data = ngx_pnalloc(cf->pool, slcf->auth_backend.len);
        if (slcf->auth_backend.data == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memcpy(slcf->auth_backend.data, (u_char *) "http://",
                   sizeof("http://") - 1);
        ngx_memcpy(slcf->auth_backend.data + sizeof("http://") - 1,
                   backend->data, backend->len);
    }

    slcf->auth_enable = 1;

    if (ngx_http_simple_auth_parse_backend(cf, slcf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    return ngx_http_simple_auth_check_loc_conf(cf, slcf);
}


void
ngx_http_simple_auth_set_host_header(ngx_conf_t *cf, ngx_url_t *u,
    ngx_str_t *host_header)
{
    if (u->family != AF_UNIX) {

        if (u->no_port || u->port == u->default_port) {
            *host_header = u->host;

        } else {
            host_header->len = u->host.len + 1 + u->port_text.len;
            host_header->data = ngx_pnalloc(cf->pool, host_header->len);
            if (host_header->data == NULL) {
                host_header->len = 0;
                return;
            }

            ngx_memcpy(host_header->data, u->host.data, u->host.len);
            host_header->data[u->host.len] = ':';
            ngx_memcpy(host_header->data + u->host.len + 1,
                       u->port_text.data, u->port_text.len);
        }

    } else {
        ngx_str_set(host_header, "localhost");
    }
}


char *
ngx_http_simple_auth_parse_backend(ngx_conf_t *cf,
    ngx_http_simple_auth_loc_conf_t *slcf)
{
    size_t     add;
    u_short    port;
    ngx_str_t  url;
    ngx_url_t  u;

    url = slcf->auth_backend;

    if (url.len > 7 && ngx_strncasecmp(url.data, (u_char *) "http://", 7) == 0) {
        ngx_str_set(&slcf->upstream_schema, "http");
        add = 7;
        port = 80;

    } else if (url.len > 8
               && ngx_strncasecmp(url.data, (u_char *) "https://", 8) == 0)
    {
#if (NGX_HTTP_SSL)
        ngx_str_set(&slcf->upstream_schema, "https");
        add = 8;
        port = 443;
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "https protocol requires SSL support");
        return NGX_CONF_ERROR;
#endif

    } else {
        return "invalid auth_backend scheme";
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url.len = url.len - add;
    u.url.data = url.data + add;
    u.default_port = port;
    u.uri_part = 1;
    u.no_resolve = 1;

    slcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (slcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    if (u.uri.len) {
        slcf->auth_uri = u.uri;
    } else {
        ngx_str_set(&slcf->auth_uri, "/");
    }

    ngx_http_simple_auth_set_host_header(cf, &u, &slcf->auth_host_header);
    if (slcf->auth_host_header.len == 0) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


char *
ngx_http_simple_auth_check_loc_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_simple_auth_loc_conf_t  *slcf = conf;

    if (slcf->auth_backend.len > 0) {
        slcf->auth_enable = 1;
    }

    if (!slcf->auth_enable) {
        return NGX_CONF_OK;
    }

    if (slcf->auth_backend.len == 0) {
        return "auth_enable is on but \"auth_backend\" is not configured";
    }

    if (slcf->upstream.upstream == NULL) {
        return "invalid auth_backend address";
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_simple_auth_target_backend_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_simple_auth_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_simple_auth_module);

    if (slcf->auth_backend.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = slcf->auth_backend.len;
    v->data = slcf->auth_backend.data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    (void) data;

    return NGX_OK;
}


ngx_int_t
ngx_http_simple_auth_has_bearer(ngx_http_request_t *r)
{
    u_char           *p;
    size_t            len;
    ngx_table_elt_t  *h;

    h = r->headers_in.authorization;
    if (h == NULL || h->value.len == 0) {
        return 0;
    }

    p = h->value.data;
    len = h->value.len;

    if (len <= NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX_LEN) {
        return 0;
    }

    if (ngx_strncasecmp(p, (u_char *) NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX,
                        NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX_LEN)
        != 0)
    {
        return 0;
    }

    p += NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX_LEN;
    len -= NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX_LEN;

    while (len > 0 && (*p == ' ' || *p == '\t')) {
        p++;
        len--;
    }

    return len > 0;
}


ngx_int_t
ngx_http_simple_auth_get_bearer_token(ngx_http_request_t *r, ngx_str_t *token)
{
    u_char           *p, *start;
    size_t            len;
    ngx_table_elt_t  *h;

    h = r->headers_in.authorization;
    if (h == NULL || h->value.len == 0) {
        return NGX_DECLINED;
    }

    p = h->value.data;
    len = h->value.len;

    if (len <= NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX_LEN) {
        return NGX_DECLINED;
    }

    if (ngx_strncasecmp(p, (u_char *) NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX,
                        NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX_LEN)
        != 0)
    {
        return NGX_DECLINED;
    }

    p += NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX_LEN;
    len -= NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX_LEN;

    while (len > 0 && (*p == ' ' || *p == '\t')) {
        p++;
        len--;
    }

    if (len == 0) {
        return NGX_DECLINED;
    }

    start = p;
    while (len > 0 && *p != ' ' && *p != '\t') {
        p++;
        len--;
    }

    token->data = start;
    token->len = p - start;

    return NGX_OK;
}


ngx_int_t
ngx_http_simple_auth_get_arg(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    u_char  *p, *last, *eq, *amp;

    if (r->args.len == 0) {
        return NGX_DECLINED;
    }

    p = r->args.data;
    last = p + r->args.len;

    while (p < last) {
        eq = ngx_strlchr(p, last, '=');
        if (eq == NULL) {
            break;
        }

        if ((size_t) (eq - p) == name->len
            && ngx_strncmp(p, name->data, name->len) == 0)
        {
            u_char  *dst, *src;
            size_t   raw_len;

            amp = ngx_strlchr(eq + 1, last, '&');
            src = eq + 1;
            raw_len = amp ? (size_t) (amp - eq - 1) : (size_t) (last - eq - 1);

            if (raw_len == 0) {
                return NGX_DECLINED;
            }

            dst = ngx_pnalloc(r->pool, raw_len);
            if (dst == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(dst, src, raw_len);

            value->data = dst;
            value->len = raw_len;

            src = dst;
            ngx_unescape_uri(&dst, &src, raw_len, NGX_UNESCAPE_URI);
            value->len = dst - value->data;

            return value->len > 0 ? NGX_OK : NGX_DECLINED;
        }

        amp = ngx_strlchr(eq, last, '&');
        p = amp ? amp + 1 : last;
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_http_simple_auth_set_bearer(ngx_http_request_t *r, ngx_str_t *token)
{
    size_t            len;
    u_char           *p;
    ngx_table_elt_t  *h;

    len = NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX_LEN + token->len;

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX,
               NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX_LEN);
    ngx_memcpy(p + NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX_LEN,
               token->data, token->len);

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "Authorization");
    h->value.len = len;
    h->value.data = p;

    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }
    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    r->headers_in.authorization = h;

    return NGX_OK;
}


ngx_int_t
ngx_http_simple_auth_deny(ngx_http_request_t *r, ngx_uint_t status)
{
    if (ngx_http_discard_request_body(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return status;
}


static ngx_int_t
ngx_http_simple_auth_handler(ngx_http_request_t *r)
{
    ngx_int_t                         rc;
    ngx_str_t                         token;
    ngx_uint_t                        cached_status;
    ngx_http_simple_auth_ctx_t       *ctx;
    ngx_http_simple_auth_loc_conf_t  *slcf;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_simple_auth_module);

    if (!slcf->auth_enable) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_simple_auth_module);

    if (ctx != NULL) {
        if (!ctx->done) {
            return NGX_AGAIN;
        }

        if (ctx->status >= NGX_HTTP_OK
            && ctx->status < NGX_HTTP_SPECIAL_RESPONSE)
        {
            return NGX_OK;
        }

        return ngx_http_simple_auth_deny(r, ctx->status);
    }

    if (ngx_http_simple_auth_has_bearer(r)) {
        /* fall through */
    } else {
        rc = ngx_http_simple_auth_get_arg(r, &slcf->token_param_key, &token);
        if (rc == NGX_OK) {
            if (ngx_http_simple_auth_set_bearer(r, &token) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        } else if (rc == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        } else {
            return ngx_http_simple_auth_deny(r, NGX_HTTP_UNAUTHORIZED);
        }
    }

    if (ngx_http_simple_auth_get_bearer_token(r, &token) == NGX_OK
        && ngx_http_simple_auth_cache_lookup(r, &token, &cached_status)
           == NGX_OK)
    {
        if (cached_status == NGX_HTTP_OK) {
            return NGX_DECLINED;
        }

        return ngx_http_simple_auth_deny(r, cached_status);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_simple_auth_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_simple_auth_module);

    if (ngx_http_simple_auth_start_verify(r, ctx) != NGX_OK) {
        return ngx_http_simple_auth_deny(r, NGX_HTTP_BAD_GATEWAY);
    }

    return NGX_AGAIN;
}
