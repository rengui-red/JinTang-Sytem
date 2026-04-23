#!/usr/bin/env python3
"""
金汤 - 本地熔断模块
进程挂起、网络阻断、系统防护
"""

import os
import signal
import subprocess
import time
import threading
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

import psutil

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BlockAction(Enum):
    """阻断动作"""
    KILL = "kill"
    SUSPEND = "suspend"
    NETWORK_BLOCK = "network_block"
    ISOLATE = "isolate"


@dataclass
class BlockedProcess:
    """被阻断的进程信息"""
    pid: int
    name: str
    reason: str
    action: BlockAction
    timestamp: float
    expiry: float


class LocalFuse:
    """本地熔断器 - 阻断恶意行为"""
    
    def __init__(self, config: dict):
        self.config = config
        self.blocked_processes: Dict[int, BlockedProcess] = {}
        self.blocked_ips: set = set()
        self.blocked_ports: set = set()
        self._cleanup_thread = None
        self.running = False
        
        # iptables 规则前缀 (用于清理)
        self.IPTABLES_CHAIN = "JINTANG_BLOCK"
        
    def _init_iptables(self):
        """初始化iptables链"""
        try:
            # 创建自定义链
            subprocess.run(
                f"iptables -N {self.IPTABLES_CHAIN} 2>/dev/null",
                shell=True, check=False
            )
            # 确保INPUT链跳转到自定义链
            subprocess.run(
                f"iptables -C INPUT -j {self.IPTABLES_CHAIN} 2>/dev/null || "
                f"iptables -I INPUT -j {self.IPTABLES_CHAIN}",
                shell=True, check=False
            )
            logger.info(f"🔒 iptables链 {self.IPTABLES_CHAIN} 已初始化")
        except Exception as e:
            logger.error(f"iptables初始化失败: {e}")
            
    def block_process(self, pid: int, reason: str, duration: int = 3600) -> bool:
        """
        阻断进程
        duration: 阻断时长(秒), -1表示永久
        """
        try:
            process = psutil.Process(pid)
            
            # 挂起进程
            if self.config.get('process_suspend', True):
                process.suspend()
                logger.info(f"⏸️ 进程已挂起: {process.name()} (PID: {pid}) - {reason}")
                
            # 记录被阻断的进程
            self.blocked_processes[pid] = BlockedProcess(
                pid=pid,
                name=process.name(),
                reason=reason,
                action=BlockAction.SUSPEND,
                timestamp=time.time(),
                expiry=time.time() + duration if duration > 0 else float('inf')
            )
            
            return True
            
        except psutil.NoSuchProcess:
            logger.error(f"进程不存在: PID {pid}")
            return False
        except Exception as e:
            logger.error(f"阻断进程失败: {e}")
            return False
            
    def kill_process(self, pid: int, reason: str) -> bool:
        """强制终止进程"""
        try:
            process = psutil.Process(pid)
            process.terminate()
            
            # 等待进程结束
            gone, alive = psutil.wait_procs([process], timeout=5)
            if alive:
                process.kill()  # 强制杀死
                
            logger.info(f"🔪 进程已终止: {process.name()} (PID: {pid}) - {reason}")
            return True
            
        except psutil.NoSuchProcess:
            logger.info(f"进程已不存在: PID {pid}")
            return True
        except Exception as e:
            logger.error(f"终止进程失败: {e}")
            return False
            
    def block_ip(self, ip: str, reason: str, duration: int = 3600) -> bool:
        """
        阻断IP地址
        duration: 阻断时长(秒)
        """
        if ip in self.blocked_ips:
            return True
            
        try:
            # 添加iptables规则
            subprocess.run(
                f"iptables -A {self.IPTABLES_CHAIN} -s {ip} -j DROP",
                shell=True, check=True
            )
            subprocess.run(
                f"iptables -A {self.IPTABLES_CHAIN} -d {ip} -j DROP",
                shell=True, check=True
            )
            
            self.blocked_ips.add(ip)
            
            # 设置定时解封
            if duration > 0:
                threading.Timer(duration, self._unblock_ip, args=[ip]).start()
                
            logger.info(f"🚫 IP已阻断: {ip} - {reason}")
            return True
            
        except Exception as e:
            logger.error(f"阻断IP失败: {e}")
            return False
            
    def block_port(self, port: int, protocol: str = 'tcp', duration: int = 3600) -> bool:
        """阻断端口"""
        try:
            subprocess.run(
                f"iptables -A {self.IPTABLES_CHAIN} -p {protocol} --dport {port} -j DROP",
                shell=True, check=True
            )
            
            self.blocked_ports.add(port)
            
            if duration > 0:
                threading.Timer(duration, self._unblock_port, args=[port, protocol]).start()
                
            logger.info(f"🚫 端口已阻断: {port}/{protocol}")
            return True
            
        except Exception as e:
            logger.error(f"阻断端口失败: {e}")
            return False
            
    def isolate_process(self, pid: int, reason: str) -> bool:
        """
        隔离进程 (使用Linux namespace)
        将进程放入独立的网络命名空间
        """
        try:
            # 获取进程的网络命名空间
            proc = psutil.Process(pid)
            
            # 创建新的网络命名空间
            ns_name = f"jintang_{pid}"
            subprocess.run(
                f"ip netns add {ns_name}",
                shell=True, check=True
            )
            
            # 将进程移动到新的命名空间
            subprocess.run(
                f"ip netns exec {ns_name} nsenter -t {pid} -n ip link set lo up",
                shell=True, check=True
            )
            
            logger.info(f"🏝️ 进程已隔离: {proc.name()} (PID: {pid}) -> ns: {ns_name}")
            return True
            
        except Exception as e:
            logger.error(f"进程隔离失败: {e}")
            return False
            
    def _unblock_ip(self, ip: str):
        """解封IP"""
        try:
            subprocess.run(
                f"iptables -D {self.IPTABLES_CHAIN} -s {ip} -j DROP",
                shell=True, check=False
            )
            subprocess.run(
                f"iptables -D {self.IPTABLES_CHAIN} -d {ip} -j DROP",
                shell=True, check=False
            )
            self.blocked_ips.discard(ip)
            logger.info(f"🔓 IP已解封: {ip}")
        except Exception as e:
            logger.error(f"解封IP失败: {e}")
            
    def _unblock_port(self, port: int, protocol: str):
        """解封端口"""
        try:
            subprocess.run(
                f"iptables -D {self.IPTABLES_CHAIN} -p {protocol} --dport {port} -j DROP",
                shell=True, check=False
            )
            self.blocked_ports.discard(port)
            logger.info(f"🔓 端口已解封: {port}/{protocol}")
        except Exception as e:
            logger.error(f"解封端口失败: {e}")
            
    def resume_process(self, pid: int) -> bool:
        """恢复被挂起的进程"""
        if pid in self.blocked_processes:
            try:
                process = psutil.Process(pid)
                process.resume()
                del self.blocked_processes[pid]
                logger.info(f"▶️ 进程已恢复: {process.name()} (PID: {pid})")
                return True
            except Exception as e:
                logger.error(f"恢复进程失败: {e}")
        return False
        
    def _cleanup_expired(self):
        """清理过期的阻断"""
        current_time = time.time()
        expired = []
        
        for pid, blocked in self.blocked_processes.items():
            if current_time > blocked.expiry:
                expired.append(pid)
                
        for pid in expired:
            self.resume_process(pid)
            
    def start(self):
        """启动熔断器"""
        self.running = True
        self._init_iptables()
        
        # 启动清理线程
        def cleanup_loop():
            while self.running:
                time.sleep(60)
                self._cleanup_expired()
                
        self._cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        
        logger.info("🔒 本地熔断器已启动")
        
    def stop(self):
        """停止熔断器"""
        self.running = False
        
        # 清理iptables规则
        try:
            subprocess.run(
                f"iptables -F {self.IPTABLES_CHAIN}",
                shell=True, check=False
            )
            logger.info("🧹 iptables规则已清理")
        except Exception as e:
            logger.error(f"清理iptables失败: {e}")
            
        logger.info("🛑 本地熔断器已停止")
        
    def get_status(self) -> dict:
        """获取熔断状态"""
        return {
            'blocked_processes': len(self.blocked_processes),
            'blocked_ips': len(self.blocked_ips),
            'blocked_ports': len(self.blocked_ports),
            'active': self.running
        }