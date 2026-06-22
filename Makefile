# Build ngx_http_simple_auth_module as a dynamic module.
#
# Usage:
#   make NGINX_SRC=/path/to/nginx-1.26.x
#   make install NGINX_SRC=/path/to/nginx-1.26.x NGINX_PREFIX=/usr/local/nginx

NGINX_SRC   ?= ../nginx
NGINX_PREFIX ?= /usr/local/nginx
MODULE_DIR   = $(abspath .)

.PHONY: all clean install

all:
	test -d "$(NGINX_SRC)" || (echo "Set NGINX_SRC to nginx source tree"; exit 1)
	cd "$(NGINX_SRC)" && ./configure \
		--prefix="$(NGINX_PREFIX)" \
		--with-compat \
		--add-dynamic-module="$(MODULE_DIR)"
	$(MAKE) -C "$(NGINX_SRC)" modules

clean:
	-$(MAKE) -C "$(NGINX_SRC)" clean 2>/dev/null || true

install: all
	install -d "$(NGINX_PREFIX)/modules"
	install -m 644 "$(NGINX_SRC)/objs/ngx_http_simple_auth_module.so" \
		"$(NGINX_PREFIX)/modules/"
