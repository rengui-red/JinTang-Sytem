#!/bin/bash

# 金汤防御系统启动脚本

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║     ██╗  ██╗██╗███╗   ██╗████████╗ █████╗ ███╗   ██╗ ██████╗   ║"
echo "║     ██║ ██╔╝██║████╗  ██║╚══██╔══╝██╔══██╗████╗  ██║██╔════╝   ║"
echo "║     █████╔╝ ██║██╔██╗ ██║   ██║   ███████║██╔██╗ ██║██║  ███╗  ║"
echo "║     ██╔═██╗ ██║██║╚██╗██║   ██║   ██╔══██║██║╚██╗██║██║   ██║  ║"
echo "║     ██║  ██╗██║██║ ╚████║   ██║   ██║  ██║██║ ╚████║╚██████╔╝  ║"
echo "║     ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝   ║"
echo "║                                                              ║"
echo "║           智能端点防御与流束识别系统 v1.0.0                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# 检查权限
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}❌ 请使用 root 权限运行 (需要抓包和iptables操作)${NC}"
    echo "   sudo $0"
    exit 1
fi

# 检查依赖
echo -e "${YELLOW}📦 检查依赖...${NC}"

for cmd in python3 tcpdump iptables; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "${RED}❌ 未找到: $cmd${NC}"
        exit 1
    fi
done

echo -e "${GREEN}✅ 依赖检查通过${NC}"

# 安装Python依赖
echo -e "${YELLOW}📦 安装Python依赖...${NC}"
pip3 install -r requirements.txt -q

# 创建必要目录
mkdir -p /var/log/jintang /var/lib/jintang

# 运行参数解析
case "$1" in
    train)
        echo -e "${YELLOW}📊 训练行为基线...${NC}"
        python3 main.py --train
        ;;
    enroll)
        echo -e "${YELLOW}🔐 注册生物特征...${NC}"
        python3 main.py --enroll
        ;;
    status)
        python3 main.py --status
        ;;
    docker)
        echo -e "${YELLOW}🐳 构建并运行 Docker 容器...${NC}"
        docker build -t jintang-waf .
        docker run -it --rm \
            --network host \
            --cap-add=NET_ADMIN \
            --cap-add=NET_RAW \
            -v /var/log/jintang:/var/log/jintang \
            jintang-waf
        ;;
    *)
        echo -e "${GREEN}🚀 启动金汤防御系统...${NC}"
        python3 main.py
        ;;
esac