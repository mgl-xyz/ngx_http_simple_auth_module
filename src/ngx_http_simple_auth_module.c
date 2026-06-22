
/*
 * Copyright (C) ngx_http_simple_auth_module contributors
 *
 * Nginx HTTP module: credential normalization gateway for object storage proxy.
 * Converts URL token query params to Authorization: Bearer headers; does not
 * validate tokens — all auth logic is delegated to the business backend.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX     "Bearer "
#define NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX_LEN 7


typedef struct {
    ngx_flag_t  auth_check;
    ngx_str_t   proxy_backend;
    ngx_str_t   token_arg_name;
} ngx_http_simple_auth_loc_conf_t;


static ngx_int_t ngx_http_simple_auth_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_simple_auth_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_simple_auth_preconf(ngx_conf_t *cf);
static ngx_int_t ngx_http_simple_auth_target_backend_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_simple_auth_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_simple_auth_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_simple_auth_check_loc_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_simple_auth_proxy_backend(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_simple_auth_has_bearer(ngx_http_request_t *r);
static ngx_int_t ngx_http_simple_auth_get_arg(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);
static ngx_int_t ngx_http_simple_auth_set_bearer(ngx_http_request_t *r,
    ngx_str_t *token);
static ngx_int_t ngx_http_simple_auth_unauthorized(ngx_http_request_t *r);


static ngx_command_t ngx_http_simple_auth_commands[] = {

    { ngx_string("auth_check"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_simple_auth_loc_conf_t, auth_check),
      NULL },

    { ngx_string("proxy_backend"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_simple_auth_proxy_backend,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("token_arg_name"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_simple_auth_loc_conf_t, token_arg_name),
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_http_simple_auth_module_ctx = {
    ngx_http_simple_auth_preconf,          /* preconfiguration */
    ngx_http_simple_auth_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* init server configuration */

    ngx_http_simple_auth_create_loc_conf,  /* create location configuration */
    ngx_http_simple_auth_merge_loc_conf    /* merge location configuration */
};


ngx_module_t ngx_http_simple_auth_module = {
    NGX_MODULE_V1,
    &ngx_http_simple_auth_module_ctx,      /* module context */
    ngx_http_simple_auth_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t ngx_http_simple_auth_vars[] = {

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

    conf->auth_check = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_simple_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_simple_auth_loc_conf_t  *prev = parent;
    ngx_http_simple_auth_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->auth_check, prev->auth_check, 0);
    ngx_conf_merge_str_value(conf->proxy_backend, prev->proxy_backend, "");
    ngx_conf_merge_str_value(conf->token_arg_name, prev->token_arg_name, "token");

    return ngx_http_simple_auth_check_loc_conf(cf, conf);
}


static char *
ngx_http_simple_auth_proxy_backend(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_simple_auth_loc_conf_t  *slcf = conf;
    ngx_str_t                        *value, *backend;

    value = cf->args->elts;
    backend = &value[1];

    if (backend->len == 0) {
        return "invalid proxy_backend value";
    }

    if (ngx_strncmp(backend->data, (u_char *) "http://", 7) == 0
        || ngx_strncmp(backend->data, (u_char *) "https://", 8) == 0)
    {
        slcf->proxy_backend = *backend;
        return NGX_CONF_OK;
    }

    slcf->proxy_backend.len = backend->len + sizeof("http://") - 1;
    slcf->proxy_backend.data = ngx_pnalloc(cf->pool, slcf->proxy_backend.len);
    if (slcf->proxy_backend.data == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memcpy(slcf->proxy_backend.data, (u_char *) "http://",
               sizeof("http://") - 1);
    ngx_memcpy(slcf->proxy_backend.data + sizeof("http://") - 1,
               backend->data, backend->len);

    return NGX_CONF_OK;
}


static char *
ngx_http_simple_auth_check_loc_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_simple_auth_loc_conf_t  *slcf = conf;

    if (slcf->auth_check && slcf->proxy_backend.len == 0) {
        return "auth_check is on but \"proxy_backend\" is not configured";
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_simple_auth_target_backend_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_simple_auth_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_simple_auth_module);

    if (slcf->proxy_backend.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = slcf->proxy_backend.len;
    v->data = slcf->proxy_backend.data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
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


static ngx_int_t
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


static ngx_int_t
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


static ngx_int_t
ngx_http_simple_auth_unauthorized(ngx_http_request_t *r)
{
    ngx_int_t    rc;
    ngx_buf_t   *b;
    ngx_chain_t  out;

    static u_char body[] =
        "{\"code\":401,\"msg\":\"缺少访问凭证，需携带Authorization请求头或url token参数\"}";

    if (ngx_http_discard_request_body(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = NGX_HTTP_UNAUTHORIZED;
    ngx_str_set(&r->headers_out.content_type, "application/json; charset=utf-8");
    r->headers_out.content_length_n = sizeof(body) - 1;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = body;
    b->last = body + sizeof(body) - 1;
    b->memory = 1;
    b->last_buf = 1;

    out.buf = b;
    out.next = NULL;

    rc = ngx_http_output_filter(r, &out);
    if (rc == NGX_ERROR) {
        return rc;
    }

    ngx_http_finalize_request(r, NGX_HTTP_UNAUTHORIZED);
    return NGX_HTTP_UNAUTHORIZED;
}


static ngx_int_t
ngx_http_simple_auth_handler(ngx_http_request_t *r)
{
    ngx_int_t                         rc;
    ngx_str_t                         token;
    ngx_http_simple_auth_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_simple_auth_module);

    if (!slcf->auth_check) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "simple auth handler");

    if (ngx_http_simple_auth_has_bearer(r)) {
        return NGX_DECLINED;
    }

    rc = ngx_http_simple_auth_get_arg(r, &slcf->token_arg_name, &token);
    if (rc == NGX_OK) {
        if (ngx_http_simple_auth_set_bearer(r, &token) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return NGX_DECLINED;
    }

    return ngx_http_simple_auth_unauthorized(r);
}
