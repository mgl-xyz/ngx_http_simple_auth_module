# ngx_http_simple_auth_module

Nginx 原生 C 动态模块：对象存储网关层凭证标准化与鉴权网关。将 URL Query 中的 token 自动转为 `Authorization: Bearer` 请求头，并向 `auth_backend` 发起鉴权；**仅鉴权接口返回 HTTP 200 时**才继续执行 location 内后续配置。

English documentation: [README.en.md](README.en.md)

## 特性

- 纯 C 原生 Nginx 动态模块，不依赖 OpenResty / Lua / JWT 库
- 双通道凭证：Header 优先，URL 参数兜底
- 向 `auth_backend` 鉴权，**只认 HTTP 200**
- 鉴权失败时返回 HTTP 状态码，错误页用 Nginx 原生 `error_page` 统一配置
- 鉴权通过后由用户自行配置 `root` / `proxy_pass` 等

## 编译

```bash
cd /path/to/nginx-1.30.x
./configure --with-compat --add-dynamic-module=/path/to/ngx_http_simple_auth_module
make && make install
```

`nginx.conf` 顶部：

```nginx
load_module modules/ngx_http_simple_auth_module.so;
```

## 配置示例

```nginx
server {
    # 统一错误页：配一次，所有开启 auth_enable 的 location 共用
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

模块只负责返回状态码（401、后端透传码、502 等），**不需要**在每个 location 里单独配错误页。在 `server` 或 `http` 块用标准 `error_page` 即可。

`=401` 表示内部跳转到错误页后仍保留 401 状态码（Nginx 标准写法）。

## 配置指令

| 指令 | 默认值 | 说明 |
|------|--------|------|
| `auth_enable on \| off` | `off` | 启用鉴权；配置 `auth_backend` 时自动视为 `on` |
| `auth_backend <URL>` | — | 鉴权接口地址，如 `http://127.0.0.1:8080/auth/check` |
| `token_param_key <name>` | `token` | URL Query 凭证参数名 |

## 鉴权流程

1. 无凭证 → 返回 **401**
2. 有凭证 → 向 `auth_backend` 发 GET（带 `Authorization`、`X-Original-URI`）
3. 后端 **200** → 继续 `root` / `proxy_pass` 等
4. 后端 **非 200** → 透传后端状态码（如 401、403、404）
5. 连接失败或解析错误 → 返回 **502**

Nginx 收到上述状态码后，按 `error_page` 配置展示统一错误页。

## 后端鉴权接口约定

```http
GET /auth/check
Authorization: Bearer {token}
X-Original-URI: /path/to/resource
Host: {auth_backend主机}
```

- 允许访问 → **200**（body 可空）
- 拒绝 → 任意非 200（模块透传该状态码）

## HTTP 状态码说明

| 场景 | 状态码 | 含义 |
|------|--------|------|
| 缺少凭证 | 401 | 无 `Authorization: Bearer` 且 URL 无 token 参数 |
| 鉴权拒绝 | 后端返回码 | 鉴权后端返回非 200（如 401、403、404） |
| 鉴权不可用 | 502 | 无法连接鉴权后端，或 upstream 异常 |

## 典型场景

| 场景 | 请求 | 结果 |
|------|------|------|
| 无凭证 | `GET /` | 401 → `error_page` 展示 401 页 |
| 假 token | `GET /?token=x`，后端 403 | 403 → 统一 403 页 |
| 鉴权服务未启动 | 有 token | 502 → 统一 502 页 |
| 鉴权通过 | 有效 token，后端 200 | 继续访问资源 |

## License

[MIT](LICENSE)
