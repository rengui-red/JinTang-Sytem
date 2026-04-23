# 1. 使用 Alpine Linux 作为基础镜像
# 理由：Alpine 极其轻量（只有几兆），非常适合构建小型、安全的镜像
FROM openresty/openresty:alpine

# 2. 维护者信息（可选）
LABEL maintainer="jintang-waf"

# 3. 移除默认配置，准备放入我们的定制配置
# 这一步是为了确保环境干净，没有默认网站的干扰
RUN rm -rf /usr/local/openresty/nginx/conf/conf.d/*

# 4. 复制项目文件到镜像中
# 将本地的配置文件复制到镜像的标准配置路径
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
# 将 WAF 逻辑脚本复制到指定目录
COPY WAF.lua /usr/local/openresty/nginx/WAF.lua
# 将前端页面文件复制进去
COPY index.html /usr/local/openresty/nginx/html/index.html
COPY LOGO-index.html /usr/local/openresty/nginx/html/LOGO-index.html

# 5. 暴露端口
# 告诉 Docker 容器在运行时会监听 80 端口
EXPOSE 80

# 6. 设置启动命令
# 以前台模式启动 OpenResty (Nginx)，这样容器才不会启动后立马退出
# "daemon off;" 是关键，它让 Nginx 在控制台运行，Docker 才能监控到它的状态
CMD ["sh", "-c", "openresty -g 'daemon off;'"]