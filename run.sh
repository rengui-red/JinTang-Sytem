#!/bin/sh

echo "🛡️  正在启动金汤 (Jin-Tang) Ultimate..."

# 确保目录存在
mkdir -p /var/log/nginx /var/cache/nginx

# 渲染配置
envsubst '${BACKEND_HOST} ${BACKEND_PORT} ${SERVER_NAME} ${RATE_LIMIT}' \
    < /usr/local/openresty/nginx/conf/nginx.conf \
    > /tmp/nginx.conf.tmp
    
mv /tmp/nginx.conf.tmp /usr/local/openresty/nginx/conf/nginx.conf

echo "✅  配置已加载，WAF 引擎就绪。"

# 启动 OpenResty
exec openresty -g 'daemon off;'