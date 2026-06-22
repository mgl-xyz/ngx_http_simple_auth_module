# ngx_http_simple_auth_module

Nginx 原生 C 动态模块：对象存储网关层凭证标准化代理。将 URL Query 中的 token 参数自动转换为 `Authorization: Bearer` 请求头，统一转发至业务后端鉴权；模块本身不解析、不校验 token。

## 背景

前端访问对象存储（RustFS / MinIO / S3 兼容）静态资源时，Ajax 请求可携带 `Authorization` 头，但 `<img>` / `<video>` / `<audio>` 等原生标签无法自定义请求头，只能通过 URL 参数传递凭证。本模块在 Nginx 网关层完成两种凭证形式的兼容适配，业务后端只需读取标准 Bearer 头即可。

## 特性

- 纯 C 原生 Nginx 动态模块，不依赖 OpenResty / Lua / JWT 库
- 双通道凭证兼容：Header 优先，URL 参数兜底
- 无凭证时网关直接返回 401 JSON，不进入业务后端
- 不限制 HTTP 方法（GET/POST/PUT/DELETE 等全部透传）
- 不校验 token 真伪与权限，鉴权逻辑完全由业务后端负责
- 支持直连地址与 upstream 负载均衡两种 `auth_backend` 写法
- 导出 `$target_backend` 变量供 `proxy_pass` 使用

## CI 验证

Push / PR 到 `main`/`master` 或手动触发时，CI 会分别验证 **动态模块**（`--add-dynamic-module`）与 **静态模块**（`--add-module`）两种编译方式，并上传动态 `.so` artifact。

### CI 产物能直接拿来用吗？

**多数情况不能。** Nginx 动态模块与运行中的 Nginx **版本、编译选项、操作系统** 强绑定，CI 在 Ubuntu 上编出来的 `.so` 通常无法直接丢到任意已装 Nginx 的机器上用。

使用前请确认：

| 条件 | 说明 |
|------|------|
| Nginx 版本一致 | `nginx -v` 与 artifact 名称中的版本相同（如 `nginx-1.26.3`） |
| 同为 Linux x86_64 | CI 产物为 Ubuntu/glibc 环境，Alpine、macOS、ARM 等需自行编译 |
| 动态模块支持 | 运行中的 Nginx 须带 `--with-compat` 或 `--add-dynamic-module` 能力 |

**推荐做法：** 在目标机器上用与 `nginx -V` 一致的源码重新编译：

```bash
nginx -v          # 看版本
nginx -V          # 看 configure 参数

# 下载同版本源码，加上本模块后 make modules
```

CI artifact 适合：快速试用（环境恰好匹配）、对照验证编译是否通过，**不能当作通用安装包**。

## 编译（部署环境）

支持两种接入方式，**版本须与运行中 Nginx 一致**：

### 动态模块 `--add-dynamic-module`（推荐）

单独生成 `.so`，通过 `load_module` 加载，无需重编 Nginx 主程序：

```bash
cd /path/to/nginx-1.26.x
./configure --with-compat --add-dynamic-module=/path/to/ngx_http_simple_auth_module
make modules
cp objs/ngx_http_simple_auth_module.so /usr/local/nginx/modules/
```

`nginx.conf` 顶部加载：

```nginx
load_module modules/ngx_http_simple_auth_module.so;
```

### 静态模块 `--add-module`

编译进 Nginx 二进制，**无需** `load_module`，需完整重编并替换 `nginx` 可执行文件：

```bash
cd /path/to/nginx-1.26.x
./configure --add-module=/path/to/ngx_http_simple_auth_module [原有 configure 参数...]
make
make install
```

### Makefile

```bash
make NGINX_SRC=/path/to/nginx-1.26.x              # 动态模块
make static NGINX_SRC=/path/to/nginx-1.26.x       # 静态模块
make install NGINX_SRC=/path/to/nginx-1.26.x NGINX_PREFIX=/usr/local/nginx
```

## 配置指令

| 指令 | 作用域 | 说明 |
|------|--------|------|
| `auth_enable on \| off` | location | 是否启用凭证处理；配置 `auth_backend` 时自动视为 `on`，默认 `off` |
| `auth_backend <URL>` | location | 鉴权接口地址；模块向其发 GET 请求，**仅 HTTP 200 放行** |

### 鉴权流程

1. 无凭证 → 401 JSON，不访问后端  
2. 有凭证 → 模块向 `auth_backend` 发鉴权请求（带 `Authorization` + `X-Original-URI`）  
3. **仅返回 200** → 继续执行 location 内后续配置（`root` / `proxy_pass` 等）  
4. 401/403/404/5xx、连接失败、超时等 **一律拒绝**，不会访问后面内容

### 后端鉴权接口约定

```
GET {auth_backend路径}
Authorization: Bearer {token}
X-Original-URI: {客户端原始URI}
```

- 凭证有效 → 返回 **200**（body 可空）  
- 凭证无效 → 返回 401/403 等（客户端收到 403 JSON）  
- 服务不可用 → 客户端收到 502 JSON

```nginx
location / {
    auth_enable on;
    auth_backend http://127.0.0.1:8080/auth/check;

    root html;              # 鉴权 200 后才生效
    index index.html;
}
```
| `token_param_key <参数名>` | location | URL 凭证参数名，默认 `token` |

完整示例见 [examples/nginx.conf](examples/nginx.conf)。

```nginx
location / {
    auth_enable on;
    auth_backend http://127.0.0.1:8080/auth/check;
    root html;
}
```

也可鉴权通过后 `proxy_pass` 到资源服务：

```nginx
location /res/ {
    auth_enable on;
    auth_backend http://127.0.0.1:8080/auth/check;

    proxy_pass http://127.0.0.1:9000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

## 凭证处理规则

1. **Header 模式（最高优先级）**  
   请求已携带 `Authorization: Bearer {token}` 时，原样透传，忽略 URL 中的 token 参数。

2. **URL 参数模式**  
   无标准 Bearer 头时，从 Query 中读取 `token_param_key` 指定参数，自动生成 `Authorization: Bearer {token}` 头。

3. **无凭证拦截**  
   Header 与 URL 均无有效凭证时，Nginx 直接返回 401 JSON。

4. **鉴权网关**  
   有凭证时向 `auth_backend` 发起鉴权，**只认 HTTP 200**；其余任何情况（含网络错误）均拒绝。

5. **请求方法**  
   不对客户端 HTTP 方法做过滤；鉴权请求固定为 GET。

6. **后续处理**  
   鉴权 200 后，由 location 内用户自行配置的 `root` / `proxy_pass` 等继续处理。

## 典型访问场景

| 场景 | 请求 | 模块行为 |
|------|------|----------|
| Ajax 接口 | `Authorization: Bearer eyJ...` | 透传 Header，转发后端 |
| 媒体标签 | `/res/demo.mp3?token=eyJ...` | 提取 token，补充 Bearer 头 |
| 自定义参数名 | `/res/a.jpg?access_token=eyJ...` | 按 `token_param_key` 识别 |
| 无凭证 | 无 Header、无参数 | 401 JSON，不转发 |

## 架构说明

```
浏览器 → Nginx (本模块: 凭证标准化) → 业务后端 (鉴权) → 对象存储
```

模块职责边界：

- **做**：凭证形式识别与 Header 标准化、无凭证 401 拦截、设置 `$target_backend`
- **不做**：token 解析/校验、过期检查、资源权限判断、HTTP 方法限制

## License

[MIT](LICENSE)
