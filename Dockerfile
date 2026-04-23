FROM python:3.11-slim

LABEL maintainer="JinTang Security"
LABEL description="金汤智能端点防御与流束识别系统"

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    tcpdump \
    net-tools \
    iptables \
    iproute2 \
    procps \
    libpcap-dev \
    libgl1-mesa-glx \
    libglib2.0-0 \
    alsa-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 复制依赖文件
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制源代码
COPY src/ ./src/
COPY main.py .
COPY config.yaml .

# 创建数据目录
RUN mkdir -p /var/log/jintang /var/lib/jintang

# 暴露端口 (如有需要)
EXPOSE 8080

# 运行
CMD ["python", "main.py"]