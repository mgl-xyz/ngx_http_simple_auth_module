
/*
 * Copyright (C) ngx_http_simple_auth_module contributors
 *
 * Upstream auth verification (keepalive via upstream { keepalive N; }).
 */

#include "ngx_http_simple_auth_module.h"


static ngx_int_t ngx_http_simple_auth_verify_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_simple_auth_verify_rewrite_handler(ngx_http_request_t *r);
static void ngx_http_simple_auth_verify_input_body(ngx_http_request_t *r);
static void ngx_http_simple_auth_verify_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);
static ngx_int_t ngx_http_simple_auth_verify_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_simple_auth_verify_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_simple_auth_verify_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc);


static ngx_int_t
ngx_http_simple_auth_verify_rewrite_handler(ngx_http_request_t *r)
{
    static ngx_str_t  verify_uri = ngx_string(NGX_HTTP_SIMPLE_AUTH_VERIFY_URI);

    if (r->uri.len == verify_uri.len
        && ngx_strncmp(r->uri.data, verify_uri.data, verify_uri.len) == 0)
    {
        r->content_handler = ngx_http_simple_auth_verify_handler;
        r->header_only = 1;
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_http_simple_auth_rewrite_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_simple_auth_verify_rewrite_handler;

    return NGX_OK;
}


ngx_int_t
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


ngx_int_t
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
ngx_http_simple_auth_verify_done(ngx_http_request_t *r, void *data,
    ngx_int_t rc)
{
    ngx_http_simple_auth_ctx_t       *ctx = data;
    ngx_http_simple_auth_loc_conf_t  *slcf;
    ngx_str_t                         token;

    if (!ctx->done) {
        if (r->headers_out.status) {
            ctx->status = r->headers_out.status;
        } else {
            ctx->status = NGX_HTTP_BAD_GATEWAY;
        }
        ctx->done = 1;
    }

    if (ctx->request != NULL
        && ngx_http_simple_auth_get_bearer_token(ctx->request, &token) == NGX_OK)
    {
        slcf = ngx_http_get_module_loc_conf(ctx->request,
                                            ngx_http_simple_auth_module);
        if (slcf->cache_valid > 0) {
            ngx_http_simple_auth_cache_store(ctx->request, &token, ctx->status);
        }
    }

    return rc;
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


void
ngx_http_simple_auth_verify_upstream(ngx_http_request_t *r)
{
    ngx_http_simple_auth_loc_conf_t  *slcf;
    ngx_http_upstream_t              *u;

    if (ngx_http_upstream_create(r) != NGX_OK) {
        ngx_http_simple_auth_verify_finalize(r, NGX_HTTP_BAD_GATEWAY);
        ngx_http_finalize_request(r, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_simple_auth_module);
    if (slcf->upstream.upstream == NULL && r->parent != NULL) {
        slcf = ngx_http_get_module_loc_conf(r->parent,
                                            ngx_http_simple_auth_module);
    }
    u = r->upstream;

    if (slcf->upstream.upstream == NULL) {
        ngx_http_simple_auth_verify_finalize(r, NGX_HTTP_BAD_GATEWAY);
        ngx_http_finalize_request(r, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    u->conf = &slcf->upstream;
    u->schema = slcf->upstream_schema;

#if (NGX_HTTP_SSL)
    if (slcf->upstream_schema.len == 5) {
        u->ssl = 1;
    }
#endif

    u->create_request = ngx_http_simple_auth_verify_create_request;
    u->process_header = ngx_http_simple_auth_verify_process_header;
    u->finalize_request = ngx_http_simple_auth_verify_finalize_request;
    u->input_filter_init = ngx_http_upstream_non_buffered_filter_init;
    u->input_filter = ngx_http_upstream_non_buffered_filter;
    u->input_filter_ctx = r;

    ngx_http_upstream_init(r);
}


static void
ngx_http_simple_auth_verify_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_request_t         *pr;
    ngx_http_simple_auth_ctx_t *ctx;

    pr = r->parent;
    if (pr == NULL) {
        return;
    }

    ctx = ngx_http_get_module_ctx(pr, ngx_http_simple_auth_module);
    if (ctx == NULL) {
        return;
    }

    if (!ctx->done) {
        if (rc == NGX_OK || rc == NGX_HTTP_OK) {
            ctx->status = r->upstream->headers_in.status_n;
            if (ctx->status == 0) {
                ctx->status = NGX_HTTP_BAD_GATEWAY;
            }
        } else {
            ctx->status = NGX_HTTP_BAD_GATEWAY;
        }

        ctx->done = 1;
        r->headers_out.status = ctx->status;
    }
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

    if (pr->unparsed_uri.len) {
        len = sizeof("GET ") - 1 + slcf->auth_uri.len
              + sizeof(" HTTP/1.1\r\n") - 1
              + sizeof("Host: \r\n") - 1 + slcf->auth_host_header.len
              + sizeof("X-Original-URI: \r\n") - 1 + pr->unparsed_uri.len
              + sizeof("\r\n\r\n") - 1;
    } else {
        len = sizeof("GET ") - 1 + slcf->auth_uri.len
              + sizeof(" HTTP/1.1\r\n") - 1
              + sizeof("Host: \r\n") - 1 + slcf->auth_host_header.len
              + sizeof("X-Original-URI: \r\n") - 1 + pr->uri.len
              + sizeof("\r\n\r\n") - 1;
    }

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
    b->last = ngx_copy(b->last, slcf->auth_host_header.data,
                       slcf->auth_host_header.len);
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
    if (pr->unparsed_uri.len) {
        b->last = ngx_copy(b->last, pr->unparsed_uri.data, pr->unparsed_uri.len);
    } else {
        b->last = ngx_copy(b->last, pr->uri.data, pr->uri.len);
    }
    *b->last++ = '\r'; *b->last++ = '\n';

    b->last = ngx_cpymem(b->last, (u_char *) "\r\n\r\n",
                         sizeof("\r\n\r\n") - 1);

    u->request_bufs = cl;

    return NGX_OK;
}


static ngx_int_t
ngx_http_simple_auth_verify_process_header(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_table_elt_t                *h;
    ngx_http_status_t               status;
    ngx_http_upstream_t            *u;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    u = r->upstream;
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

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

            h = ngx_list_push(&u->headers_in.headers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_pnalloc(r->pool,
                                      h->key.len + 1 + h->value.len + 1
                                      + h->key.len);
            if (h->key.data == NULL) {
                h->hash = 0;
                return NGX_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh) {
                rc = hh->handler(r, h, hh->offset);

                if (rc != NGX_OK) {
                    return rc;
                }
            }

            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            if (!u->headers_in.chunked && u->headers_in.content_length_n <= 0) {
                u->keepalive = !u->headers_in.connection_close;

            } else {
                u->keepalive = 0;
            }

            r->headers_out.status = u->headers_in.status_n;
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
