# 使用 OpenResty 作为底座，支持 Lua 脚本
FROM openresty/openresty:alpine-fat AS builder

# 安装必要的依赖（如果需要额外的 lua 模块可以在这里装）
# RUN opm get ...

# 第二阶段：精简运行环境
FROM openresty/openresty:alpine-fat

LABEL maintainer="JinTang Team"
LABEL description="Jin-Tang Security Gateway - Ultimate Edition"

# 1. 清理默认配置
RUN rm /usr/local/openresty/nginx/conf/nginx.conf
RUN rm /usr/local/openresty/nginx/conf/conf.d/*

# 2. 创建日志目录
RUN mkdir -p /var/log/nginx /var/cache/nginx

# 3. 复制配置文件
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY waf.lua /etc/nginx/lua/waf.lua

# 4. 复制启动脚本
COPY run.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 5. 暴露端口
EXPOSE 80 443

# 6. 设置入口点
ENTRYPOINT ["/entrypoint.sh"]