#!/usr/bin/env python3
"""
金汤 - 流束识别模块
识别C2心跳、DNS隧道、流量不对称等恶意特征
"""

import time
import threading
import queue
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import logging

import scapy.all as scapy
import psutil
import numpy as np

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class FlowRecord:
    """流记录数据结构"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets: List = field(default_factory=list)
    packet_times: List = field(default_factory=list)
    packet_sizes: List = field(default_factory=list)
    total_bytes: int = 0
    start_time: float = 0
    last_seen: float = 0
    
    @property
    def duration(self) -> float:
        return self.last_seen - self.start_time if self.start_time else 0
    
    @property
    def packet_rate(self) -> float:
        """包速率 (包/秒)"""
        return len(self.packets) / self.duration if self.duration > 0 else 0
    
    @property
    def byte_rate(self) -> float:
        """字节速率 (字节/秒)"""
        return self.total_bytes / self.duration if self.duration > 0 else 0
    
    @property
    def avg_packet_size(self) -> float:
        return np.mean(self.packet_sizes) if self.packet_sizes else 0
    
    @property
    def interval_jitter(self) -> float:
        """包间隔抖动 (标准差)"""
        if len(self.packet_times) < 2:
            return 0
        intervals = np.diff(self.packet_times)
        return np.std(intervals)


class FlowMonitor:
    """流束监控器 - 识别C2通信特征"""
    
    # C2特征阈值
    HEARTBEAT_JITTER_THRESHOLD = 0.1      # 心跳抖动阈值(秒)
    HEARTBEAT_SIZE_CV_THRESHOLD = 0.05    # 包大小变异系数阈值
    DNS_TUNNEL_QUERY_LEN_THRESHOLD = 50   # DNS隧道查询长度阈值
    
    def __init__(self, config: dict):
        self.config = config
        self.flows: Dict[str, FlowRecord] = {}
        self.suspicious_flows: Dict[str, dict] = {}
        self.alert_queue = queue.Queue()
        self.running = False
        self._sniffer = None
        
        # 统计特征
        self.global_stats = {
            'total_flows': 0,
            'suspicious_flows': 0,
            'blocked_connections': 0
        }
        
    def _get_flow_key(self, packet) -> str:
        """生成流唯一标识"""
        if scapy.IP in packet:
            ip_layer = packet[scapy.IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            if scapy.TCP in packet:
                proto = 'TCP'
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
            elif scapy.UDP in packet:
                proto = 'UDP'
                src_port = packet[scapy.UDP].sport
                dst_port = packet[scapy.UDP].dport
            else:
                proto = 'OTHER'
                src_port = dst_port = 0
                
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
        return None
    
    def _analyze_heartbeat(self, flow: FlowRecord) -> Tuple[bool, float]:
        """
        检测心跳特征
        返回: (是否心跳, 置信度)
        """
        if len(flow.packet_times) < 3:
            return False, 0.0
            
        intervals = np.diff(flow.packet_times)
        interval_std = np.std(intervals)
        interval_mean = np.mean(intervals)
        
        # 心跳特征1: 间隔稳定 (标准差小)
        cv = interval_std / interval_mean if interval_mean > 0 else 1
        
        # 心跳特征2: 包大小稳定
        size_cv = np.std(flow.packet_sizes) / np.mean(flow.packet_sizes) if flow.packet_sizes else 1
        
        # 心跳特征3: 固定间隔 (常见C2心跳: 30s, 60s, 120s)
        common_intervals = [30, 60, 120, 5, 10, 20]
        interval_match = any(abs(interval_mean - ci) < 2 for ci in common_intervals)
        
        confidence = 0.0
        if cv < self.HEARTBEAT_JITTER_THRESHOLD:
            confidence += 0.4
        if size_cv < self.HEARTBEAT_SIZE_CV_THRESHOLD:
            confidence += 0.3
        if interval_match:
            confidence += 0.3
            
        return confidence > 0.6, confidence
    
    def _analyze_asymmetry(self, flow: FlowRecord) -> float:
        """
        检测流量不对称性 (C2特征: 下行远大于上行)
        返回: 不对称比率 (down/up)
        """
        # 简化实现: 需要双向流统计
        return 1.0
    
    def _analyze_dns_tunnel(self, packet) -> bool:
        """检测DNS隧道"""
        if scapy.DNSQR in packet:
            dns_query = packet[scapy.DNSQR].qname.decode('utf-8', errors='ignore')
            # DNS隧道特征: 长域名、高熵值
            if len(dns_query) > self.DNS_TUNNEL_QUERY_LEN_THRESHOLD:
                return True
                
            # 熵值检测 (随机域名)
            import math
            entropy = 0
            for c in set(dns_query):
                p = dns_query.count(c) / len(dns_query)
                entropy -= p * math.log2(p)
            if entropy > 4.5:  # 高熵值表示随机性
                return True
        return False
    
    def _process_packet(self, packet):
        """处理捕获的数据包"""
        if not self.running:
            return
            
        flow_key = self._get_flow_key(packet)
        if not flow_key:
            return
            
        current_time = time.time()
        packet_size = len(packet)
        
        if flow_key not in self.flows:
            # 新流
            self.flows[flow_key] = FlowRecord(
                src_ip=packet[scapy.IP].src if scapy.IP in packet else "unknown",
                dst_ip=packet[scapy.IP].dst if scapy.IP in packet else "unknown",
                src_port=packet[scapy.TCP].sport if scapy.TCP in packet else 0,
                dst_port=packet[scapy.TCP].dport if scapy.TCP in packet else 0,
                protocol='TCP' if scapy.TCP in packet else 'UDP' if scapy.UDP in packet else 'OTHER',
                start_time=current_time
            )
            self.global_stats['total_flows'] += 1
            
        flow = self.flows[flow_key]
        flow.packets.append(packet)
        flow.packet_times.append(current_time)
        flow.packet_sizes.append(packet_size)
        flow.total_bytes += packet_size
        flow.last_seen = current_time
        
        # 周期性分析 (每10个包分析一次)
        if len(flow.packets) % 10 == 0:
            self._analyze_flow(flow_key, flow)
            
        # DNS隧道检测
        if self._analyze_dns_tunnel(packet):
            self._report_suspicious(flow_key, "DNS_TUNNEL", 0.85)
            
    def _analyze_flow(self, flow_key: str, flow: FlowRecord):
        """分析流特征"""
        is_heartbeat, hb_confidence = self._analyze_heartbeat(flow)
        
        if is_heartbeat:
            self._report_suspicious(flow_key, "HEARTBEAT_C2", hb_confidence)
            
        # 检测极低速率的长连接 (保持连接特征)
        if flow.duration > 300 and flow.packet_rate < 0.5:
            self._report_suspicious(flow_key, "LOW_RATE_PERSISTENT", 0.7)
            
    def _report_suspicious(self, flow_key: str, reason: str, confidence: float):
        """上报可疑流"""
        if flow_key in self.suspicious_flows:
            return
            
        alert = {
            'flow_key': flow_key,
            'reason': reason,
            'confidence': confidence,
            'timestamp': time.time(),
            'flow_details': self.flows.get(flow_key)
        }
        
        self.suspicious_flows[flow_key] = alert
        self.alert_queue.put(alert)
        self.global_stats['suspicious_flows'] += 1
        
        logger.warning(f"⚠️ 检测到可疑流束: {reason} (置信度: {confidence:.2%})")
        
    def start(self):
        """启动流量监控"""
        self.running = True
        logger.info("🚀 金汤流束监控已启动")
        
        def capture():
            scapy.sniff(
                iface=self.config.get('interface', 'eth0'),
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )
            
        self._sniffer = threading.Thread(target=capture, daemon=True)
        self._sniffer.start()
        
    def stop(self):
        """停止监控"""
        self.running = False
        logger.info("🛑 金汤流束监控已停止")
        
    def get_alerts(self) -> List[dict]:
        """获取所有告警"""
        alerts = []
        while not self.alert_queue.empty():
            alerts.append(self.alert_queue.get_nowait())
        return alerts
        
    def get_stats(self) -> dict:
        """获取统计信息"""
        return {
            **self.global_stats,
            'active_flows': len(self.flows),
            'suspicious_count': len(self.suspicious_flows)
        }