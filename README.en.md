# ngx_http_simple_auth_module

Native Nginx C module (static or dynamic): credential normalization and auth gateway for object storage proxies. Converts URL `token` query parameters to `Authorization: Bearer` headers and verifies them against `auth_backend`. **Only HTTP 200 from the auth backend** allows the request to proceed to `root`, `proxy_pass`, etc.

中文文档：[README.md](README.md)

## Features

- Pure C Nginx module; supports `--add-module` (static) and `--add-dynamic-module` (dynamic)
- Dual credential channels: Header first, URL parameter fallback
- Auth check against `auth_backend`; **only HTTP 200 passes**
- On failure, returns HTTP status codes; use Nginx `error_page` for unified error pages
- After auth success, downstream handling is entirely user-defined

## Build

### Dynamic module (recommended)

Builds a `.so` loaded via `load_module`. Often no module rebuild when upgrading the nginx binary.

```bash
cd /path/to/nginx-1.30.x
./configure --with-compat \
    --add-dynamic-module=/path/to/ngx_http_simple_auth_module
make && make install
```

In `nginx.conf`:

```nginx
load_module modules/ngx_http_simple_auth_module.so;
```

This repo's Makefile:

```bash
make NGINX_SRC=/path/to/nginx-1.30.x
make install NGINX_SRC=/path/to/nginx-1.30.x NGINX_PREFIX=/usr/local/nginx
```

### Static module

Module is linked into the `nginx` binary. **No** `load_module` directive.

```bash
cd /path/to/nginx-1.30.x
./configure --add-module=/path/to/ngx_http_simple_auth_module
make && make install
```

This repo's Makefile:

```bash
make static NGINX_SRC=/path/to/nginx-1.30.x
make -C /path/to/nginx-1.30.x install NGINX_PREFIX=/usr/local/nginx
```

Do not use `load_module` in `nginx.conf` when built statically.

## Example

```nginx
server {
    # Unified error pages — configure once for all auth-enabled locations
    error_page 401 =401 /errors/401.html;
    error_page 403 =403 /errors/403.html;
    error_page 502 =502 /errors/502.html;

    location /errors/ {
        internal;
        root html;
    }

    location / {
        auth_enable on;
        auth_backend http://127.0.0.1:8080/auth/check;
        token_param_key token;

        root html;
        index index.html;
    }

    location /api/ {
        auth_enable on;
        auth_backend http://127.0.0.1:8080/auth/check;
        proxy_pass http://backend;
    }
}
```

The module only returns status codes. You do **not** need per-location error page config — use standard Nginx `error_page` at `server` or `http` level.

`=401` keeps status 401 when serving the error page (standard Nginx syntax).

## Directives

| Directive | Default | Description |
|-----------|---------|-------------|
| `auth_enable on \| off` | `off` | Enable auth; auto-on when `auth_backend` is set |
| `auth_backend <URL>` | — | Auth endpoint, e.g. `http://127.0.0.1:8080/auth/check` |
| `token_param_key <name>` | `token` | URL query parameter name for token |

## Auth flow

1. No credential → **401**
2. Credential present → GET to `auth_backend` with `Authorization` and `X-Original-URI`
3. Backend **200** → continue to `root` / `proxy_pass`
4. Backend **non-200** → pass through backend status (e.g. 401, 403, 404)
5. Connection failure or parse error → **502**

Nginx then applies `error_page` to show your unified error pages.

## Auth backend contract

```http
GET /auth/check
Authorization: Bearer {token}
X-Original-URI: /path/to/resource
Host: {auth_backend host}
```

- Allow → **200** (empty body is fine)
- Deny → any non-200 status (passed through)

## HTTP status reference

| Scenario | Status | Meaning |
|----------|--------|---------|
| Missing credential | 401 | No Bearer header and no URL token |
| Auth denied | Backend status | Auth backend returned non-200 |
| Auth unavailable | 502 | Cannot reach auth backend, or upstream error |

## Typical cases

| Case | Request | Result |
|------|---------|--------|
| No credential | `GET /` | 401 → `error_page` serves 401 page |
| Invalid token | `GET /?token=x`, backend 403 | 403 → unified 403 page |
| Auth service down | with token | 502 → unified 502 page |
| Auth OK | valid token, backend 200 | resource served |

## License

[MIT](LICENSE)
