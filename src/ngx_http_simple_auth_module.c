
/*
 * Copyright (C) ngx_http_simple_auth_module contributors
 *
 * Gateway credential normalization + backend auth verification.
 * Only HTTP 200 from auth_backend allows the request to continue.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX     "Bearer "
#define NGX_HTTP_SIMPLE_AUTH_BEARER_PREFIX_LEN 7

#define NGX_HTTP_SIMPLE_AUTH_VERIFY_URI          "/__ngx_simple_auth_verify__"


typedef struct {
    ngx_flag_t   auth_enable;
    ngx_str_t    auth_backend;
    ngx_str_t    token_param_key;
    ngx_str_t    upstream_schema;
    ngx_str_t    auth_uri;
    ngx_url_t    upstream_url;
} ngx_http_simple_auth_loc_conf_t;


typedef struct {
    ngx_uint_t            done;
    ngx_uint_t            status;
    ngx_http_request_t   *request;
    ngx_http_request_t   *subrequest;
} ngx_http_simple_auth_ctx_t;


typedef struct {
    ngx_addr_t  *addr;
} ngx_http_simple_auth_peer_data_t;


static ngx_int_t ngx_http_simple_auth_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_simple_auth_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_simple_auth_preconf(ngx_conf_t *cf);
static ngx_int_t ngx_http_simple_auth_target_backend_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_simple_auth_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_simple_auth_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_simple_auth_check_loc_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_simple_auth_auth_backend(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_simple_auth_parse_backend(ngx_conf_t *cf,
    ngx_http_simple_auth_loc_conf_t *slcf);

static ngx_int_t ngx_http_simple_auth_has_bearer(ngx_http_request_t *r);
static ngx_int_t ngx_http_simple_auth_get_arg(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);
static ngx_int_t ngx_http_simple_auth_set_bearer(ngx_http_request_t *r,
    ngx_str_t *token);
static ngx_int_t ngx_http_simple_auth_deny(ngx_http_request_t *r,
    ngx_uint_t status);

static ngx_int_t ngx_http_simple_auth_start_verify(ngx_http_request_t *r,
    ngx_http_simple_auth_ctx_t *ctx);
static ngx_int_t ngx_http_simple_auth_verify_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc);
static ngx_int_t ngx_http_simple_auth_verify_handler(ngx_http_request_t *r);
static void ngx_http_simple_auth_verify_input_body(ngx_http_request_t *r);
static void ngx_http_simple_auth_verify_upstream(ngx_http_request_t *r);
static void ngx_http_simple_auth_verify_abort(ngx_http_request_t *r, ngx_int_t rc);
static ngx_int_t ngx_http_simple_auth_verify_get_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_simple_auth_verify_free_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);
static ngx_int_t ngx_http_simple_auth_verify_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_simple_auth_verify_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_simple_auth_verify_finalize(ngx_http_request_t *r,
    ngx_uint_t status);


static ngx_command_t ngx_http_simple_auth_commands[] = {

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

      ngx_null_command
};


static ngx_http_module_t ngx_http_simple_auth_module_ctx = {
    ngx_http_simple_auth_preconf,
    ngx_http_simple_auth_init,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_simple_auth_create_loc_conf,
    ngx_http_simple_auth_merge_loc_conf
};


ngx_module_t ngx_http_simple_auth_module = {
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

    conf->auth_enable = NGX_CONF_UNSET;

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


static char *
ngx_http_simple_auth_parse_backend(ngx_conf_t *cf,
    ngx_http_simple_auth_loc_conf_t *slcf)
{
    ngx_str_t  url, uri;
    u_char    *p, *last;

    url = slcf->auth_backend;

    if (url.len > 7 && ngx_strncasecmp(url.data, (u_char *) "http://", 7) == 0) {
        ngx_str_set(&slcf->upstream_schema, "http");
        url.len -= 7;
        url.data += 7;
    } else if (url.len > 8
               && ngx_strncasecmp(url.data, (u_char *) "https://", 8) == 0)
    {
        ngx_str_set(&slcf->upstream_schema, "https");
        url.len -= 8;
        url.data += 8;
    } else {
        return "invalid auth_backend scheme";
    }

    last = url.data + url.len;
    p = ngx_strlchr(url.data, last, '/');

    if (p != NULL) {
        uri.data = p;
        uri.len = last - p;
        if (uri.len == 0) {
            ngx_str_set(&uri, "/");
        }
        url.len = p - url.data;
    } else {
        ngx_str_set(&uri, "/");
    }

    slcf->auth_uri = uri;

    ngx_memzero(&slcf->upstream_url, sizeof(ngx_url_t));
    slcf->upstream_url.url = url;
    slcf->upstream_url.default_port = (slcf->upstream_schema.len == 5) ? 443 : 80;
    slcf->upstream_url.uri_part = 0;

    if (ngx_parse_url(cf->pool, &slcf->upstream_url) != NGX_OK) {
        if (slcf->upstream_url.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in auth_backend \"%V\"",
                               slcf->upstream_url.err, &slcf->auth_backend);
        }
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
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

    if (slcf->upstream_url.addrs == NULL) {
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
ngx_http_simple_auth_deny(ngx_http_request_t *r, ngx_uint_t status)
{
    if (ngx_http_discard_request_body(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return status;
}


static ngx_int_t
ngx_http_simple_auth_verify_finalize(ngx_http_request_t *r, ngx_uint_t status)
{
    ngx_http_request_t           *pr;
    ngx_http_simple_auth_ctx_t   *ctx;

    pr = r->parent;
    if (pr == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(pr, ngx_http_simple_auth_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->done = 1;
    ctx->status = status;

    r->headers_out.status = status;

    return NGX_OK;
}


static ngx_int_t
ngx_http_simple_auth_verify_done(ngx_http_request_t *r, void *data,
    ngx_int_t rc)
{
    ngx_http_simple_auth_ctx_t  *ctx = data;

    if (!ctx->done) {
        if (r->headers_out.status) {
            ctx->status = r->headers_out.status;
        } else {
            ctx->status = NGX_HTTP_BAD_GATEWAY;
        }
        ctx->done = 1;
    }

    return rc;
}


static ngx_int_t
ngx_http_simple_auth_start_verify(ngx_http_request_t *r,
    ngx_http_simple_auth_ctx_t *ctx)
{
    ngx_http_request_t            *sr;
    ngx_http_post_subrequest_t    *ps;
    ngx_table_elt_t               *h;
    ngx_str_t                      verify_uri;

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_ERROR;
    }

    ps->handler = ngx_http_simple_auth_verify_done;
    ps->data = ctx;

    ngx_str_set(&verify_uri, NGX_HTTP_SIMPLE_AUTH_VERIFY_URI);

    if (ngx_http_subrequest(r, &verify_uri, NULL, &sr, ps,
                            NGX_HTTP_SUBREQUEST_WAITED)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    sr->content_handler = ngx_http_simple_auth_verify_handler;
    sr->header_only = 1;

    if (r->headers_in.authorization) {
        h = ngx_list_push(&sr->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        *h = *r->headers_in.authorization;
        h->next = NULL;
        sr->headers_in.authorization = h;
    }

    ctx->request = r;
    ctx->subrequest = sr;

    return NGX_OK;
}


static ngx_int_t
ngx_http_simple_auth_verify_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    rc = ngx_http_read_client_request_body(r, ngx_http_simple_auth_verify_input_body);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static void
ngx_http_simple_auth_verify_input_body(ngx_http_request_t *r)
{
    ngx_http_simple_auth_verify_upstream(r);
}


static void
ngx_http_simple_auth_verify_upstream(ngx_http_request_t *r)
{
    ngx_http_simple_auth_loc_conf_t   *slcf;
    ngx_http_simple_auth_peer_data_t  *pd;
    ngx_http_upstream_t               *u;

    if (ngx_http_upstream_create(r) != NGX_OK) {
        ngx_http_simple_auth_verify_finalize(r, NGX_HTTP_BAD_GATEWAY);
        ngx_http_finalize_request(r, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    slcf = ngx_http_get_module_loc_conf(r->parent, ngx_http_simple_auth_module);
    u = r->upstream;

    if (slcf->upstream_url.naddrs == 0) {
        ngx_http_simple_auth_verify_finalize(r, NGX_HTTP_BAD_GATEWAY);
        ngx_http_finalize_request(r, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    pd = ngx_palloc(r->pool, sizeof(ngx_http_simple_auth_peer_data_t));
    if (pd == NULL) {
        ngx_http_simple_auth_verify_finalize(r, NGX_HTTP_BAD_GATEWAY);
        ngx_http_finalize_request(r, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    pd->addr = slcf->upstream_url.addrs;

    u->conf = ngx_http_get_module_srv_conf(r, ngx_http_upstream_module);

    u->peer.data = pd;
    u->peer.get = ngx_http_simple_auth_verify_get_peer;
    u->peer.free = ngx_http_simple_auth_verify_free_peer;
    u->peer.name = &slcf->upstream_url.host;
    u->peer.log = r->connection->log;
    u->peer.log_error = NGX_ERROR_ERR;

    u->schema = slcf->upstream_schema;

#if (NGX_HTTP_SSL)
    if (slcf->upstream_schema.len == 5) {
        u->ssl = 1;
    }
#endif

    u->create_request = ngx_http_simple_auth_verify_create_request;
    u->process_header = ngx_http_simple_auth_verify_process_header;
    u->finalize_request = ngx_http_simple_auth_verify_abort;
    u->input_filter_init = ngx_http_upstream_non_buffered_filter_init;
    u->input_filter = ngx_http_upstream_non_buffered_filter;
    u->input_filter_ctx = r;

    ngx_http_upstream_init(r);
}


static ngx_int_t
ngx_http_simple_auth_verify_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_simple_auth_peer_data_t  *pd = data;

    pc->sockaddr = pd->addr->sockaddr;
    pc->socklen = pd->addr->socklen;
    pc->name = &pd->addr->name;
    pc->cached = 0;
    pc->connection = NULL;

    return NGX_OK;
}


static void
ngx_http_simple_auth_verify_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
}


static void
ngx_http_simple_auth_verify_abort(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_request_t         *pr;
    ngx_http_simple_auth_ctx_t *ctx;

    pr = r->parent;
    if (pr == NULL) {
        return;
    }

    ctx = ngx_http_get_module_ctx(pr, ngx_http_simple_auth_module);
    if (ctx == NULL || ctx->done) {
        return;
    }

    ctx->done = 1;
    ctx->status = NGX_HTTP_BAD_GATEWAY;

    (void) rc;
}


static ngx_int_t
ngx_http_simple_auth_verify_create_request(ngx_http_request_t *r)
{
    size_t                            len;
    ngx_buf_t                        *b;
    ngx_chain_t                      *cl;
    ngx_http_request_t               *pr;
    ngx_http_simple_auth_loc_conf_t  *slcf;
    ngx_http_upstream_t              *u;

    pr = r->parent;
    slcf = ngx_http_get_module_loc_conf(pr, ngx_http_simple_auth_module);
    u = r->upstream;

    len = sizeof("GET ") - 1 + slcf->auth_uri.len
          + sizeof(" HTTP/1.1\r\n") - 1
          + sizeof("Host: \r\n") - 1 + slcf->upstream_url.host.len
          + sizeof("X-Original-URI: \r\n") - 1 + pr->uri.len
          + sizeof("Connection: close\r\n\r\n") - 1;

    if (pr->headers_in.authorization) {
        len += sizeof("Authorization: \r\n") - 1
               + pr->headers_in.authorization->value.len;
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char *) "GET ", sizeof("GET ") - 1);
    b->last = ngx_copy(b->last, slcf->auth_uri.data, slcf->auth_uri.len);
    b->last = ngx_cpymem(b->last, (u_char *) " HTTP/1.1\r\n",
                         sizeof(" HTTP/1.1\r\n") - 1);

    b->last = ngx_cpymem(b->last, (u_char *) "Host: ", sizeof("Host: ") - 1);
    b->last = ngx_copy(b->last, slcf->upstream_url.host.data,
                       slcf->upstream_url.host.len);
    *b->last++ = '\r'; *b->last++ = '\n';

    if (pr->headers_in.authorization) {
        b->last = ngx_cpymem(b->last, (u_char *) "Authorization: ",
                             sizeof("Authorization: ") - 1);
        b->last = ngx_copy(b->last, pr->headers_in.authorization->value.data,
                           pr->headers_in.authorization->value.len);
        *b->last++ = '\r'; *b->last++ = '\n';
    }

    b->last = ngx_cpymem(b->last, (u_char *) "X-Original-URI: ",
                         sizeof("X-Original-URI: ") - 1);
    b->last = ngx_copy(b->last, pr->uri.data, pr->uri.len);
    *b->last++ = '\r'; *b->last++ = '\n';

    b->last = ngx_cpymem(b->last, (u_char *) "Connection: close\r\n\r\n",
                         sizeof("Connection: close\r\n\r\n") - 1);

    u->request_bufs = cl;

    return NGX_OK;
}


static ngx_int_t
ngx_http_simple_auth_verify_process_header(ngx_http_request_t *r)
{
    ngx_int_t             rc;
    ngx_http_status_t     status;
    ngx_http_upstream_t  *u;

    u = r->upstream;

    if (u->headers_in.status_n == 0) {
        ngx_memzero(&status, sizeof(ngx_http_status_t));
        r->state = 0;

        rc = ngx_http_parse_status_line(r, &u->buffer, &status);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (rc != NGX_OK) {
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        u->headers_in.status_n = status.code;
    }

    for ( ;; ) {
        rc = ngx_http_parse_header_line(r, &u->buffer, 1);

        if (rc == NGX_OK) {
            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            ngx_http_simple_auth_verify_finalize(r, u->headers_in.status_n);
            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        ngx_http_simple_auth_verify_finalize(r, NGX_HTTP_BAD_GATEWAY);
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}


static ngx_int_t
ngx_http_simple_auth_handler(ngx_http_request_t *r)
{
    ngx_int_t                         rc;
    ngx_str_t                         token;
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

        if (ctx->status == NGX_HTTP_OK) {
            return NGX_DECLINED;
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
