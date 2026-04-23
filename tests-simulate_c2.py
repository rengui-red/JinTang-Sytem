#!/usr/bin/env python3
"""
C2流量模拟脚本 - 用于测试金汤防御系统
"""

import socket
import time
import threading
import random
import argparse


class C2Simulator:
    """C2流量模拟器"""
    
    def __init__(self, target_ip: str = "127.0.0.1", target_port: int = 8080):
        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
        
    def heartbeat_simulation(self):
        """模拟心跳流量"""
        print("💓 开始模拟心跳流量...")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.target_ip, self.target_port))
        
        # 固定间隔发送固定大小数据包
        interval = 60  # 60秒心跳
        packet_size = 64  # 64字节
        
        while self.running:
            try:
                data = bytes([random.randint(0, 255) for _ in range(packet_size)])
                sock.send(data)
                print(f"  → 发送心跳包: {packet_size} bytes")
                time.sleep(interval)
            except Exception as e:
                print(f"  ✗ 心跳错误: {e}")
                break
                
        sock.close()
        
    def dns_tunnel_simulation(self):
        """模拟DNS隧道"""
        print("🌐 开始模拟DNS隧道流量...")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        while self.running:
            try:
                # 长域名编码数据
                domain = f"{random.randint(100000, 999999)}.c2-server.example.com"
                sock.sendto(domain.encode(), (self.target_ip, 53))
                print(f"  → DNS查询: {domain[:50]}...")
                time.sleep(1)
            except Exception as e:
                print(f"  ✗ DNS错误: {e}")
                break
                
        sock.close()
        
    def command_response_simulation(self):
        """模拟命令响应模式"""
        print("📡 开始模拟命令响应流量...")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.target_ip, self.target_port))
        
        commands = ["whoami", "ipconfig", "ps aux", "netstat -an", "ls -la"]
        
        while self.running:
            try:
                # 模拟接收命令
                cmd = random.choice(commands)
                # 模拟执行结果
                result = f"Executed: {cmd}\nResult: OK\n"
                sock.send(result.encode())
                print(f"  → 命令响应: {len(result)} bytes")
                time.sleep(random.randint(5, 15))
            except Exception as e:
                print(f"  ✗ 命令错误: {e}")
                break
                
        sock.close()
        
    def start(self, mode: str = "all"):
        """启动模拟"""
        self.running = True
        
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    🎯 C2 流量模拟器                          ║
╠══════════════════════════════════════════════════════════════╣
║  目标: {self.target_ip}:{self.target_port}
║  模式: {mode}
╚══════════════════════════════════════════════════════════════╝
        """)
        
        threads = []
        
        if mode in ["heartbeat", "all"]:
            t = threading.Thread(target=self.heartbeat_simulation)
            t.start()
            threads.append(t)
            
        if mode in ["dns", "all"]:
            t = threading.Thread(target=self.dns_tunnel_simulation)
            t.start()
            threads.append(t)
            
        if mode in ["command", "all"]:
            t = threading.Thread(target=self.command_response_simulation)
            t.start()
            threads.append(t)
            
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
            
    def stop(self):
        """停止模拟"""
        self.running = False
        print("\n🛑 C2模拟已停止")


def main():
    parser = argparse.ArgumentParser(description='C2流量模拟器')
    parser.add_argument('-t', '--target', default='127.0.0.1', help='目标IP')
    parser.add_argument('-p', '--port', type=int, default=8080, help='目标端口')
    parser.add_argument('-m', '--mode', choices=['heartbeat', 'dns', 'command', 'all'], 
                       default='all', help='模拟模式')
    
    args = parser.parse_args()
    
    sim = C2Simulator(args.target, args.port)
    sim.start(args.mode)


if __name__ == "__main__":
    main()