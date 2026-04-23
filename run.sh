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



#!/bin/bash
# run.sh 示例内容

# 启动 nginx，指定配置文件路径
# 如果是 Docker 环境，通常配置在 /etc/nginx/nginx.conf
nginx -c /etc/nginx/nginx.conf

# 如果是本地调试环境，可以使用下面这行（去掉注释）：
# nginx -p . -c nginx.conf
