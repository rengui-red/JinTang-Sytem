#!/usr/bin/env python3
"""
金汤 - 云端联动模块
威胁上报、黑名单同步、全网免疫
"""

import hashlib
import json
import time
import threading
import queue
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
import logging

import requests
import redis

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ThreatIntel:
    """威胁情报数据结构"""
    hash: str
    ip: str
    port: int
    domain: str
    threat_type: str
    confidence: float
    first_seen: float
    last_seen: float
    sample_data: str


class CloudClient:
    """云端联动客户端"""
    
    def __init__(self, config: dict):
        self.config = config
        self.endpoint = config.get('endpoint', 'https://api.jintang.security')
        self.api_key = config.get('api_key', '')
        self.timeout = config.get('timeout', 5)
        
        # 本地缓存
        self.blacklist_ips = set()
        self.blacklist_domains = set()
        self.blacklist_hashes = set()
        
        # 上报队列
        self.report_queue = queue.Queue()
        self.running = False
        
        # Redis连接 (用于分布式同步)
        self.redis_client = None
        if config.get('redis_url'):
            try:
                self.redis_client = redis.from_url(config['redis_url'])
                logger.info("✅ Redis连接成功，已启用分布式同步")
            except Exception as e:
                logger.warning(f"Redis连接失败: {e}")
                
    def _generate_threat_hash(self, threat: dict) -> str:
        """生成威胁指纹"""
        data = f"{threat.get('ip', '')}:{threat.get('port', '')}:{threat.get('domain', '')}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
        
    def upload_threat(self, threat: dict) -> bool:
        """
        上传威胁情报到云端
        """
        if not self.api_key:
            logger.warning("未配置API Key，跳过上报")
            return False
            
        threat_hash = self._generate_threat_hash(threat)
        
        payload = {
            'hash': threat_hash,
            'timestamp': time.time(),
            'api_key': self.api_key,
            'threat': threat
        }
        
        try:
            response = requests.post(
                f"{self.endpoint}/v1/threats",
                json=payload,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                logger.info(f"☁️ 威胁已上报: {threat_hash}")
                return True
            else:
                logger.error(f"上报失败: {response.status_code}")
                return False
                
        except requests.exceptions.Timeout:
            logger.error("云端上报超时，加入重试队列")
            self.report_queue.put(threat)
            return False
        except Exception as e:
            logger.error(f"上报异常: {e}")
            return False
            
    def sync_blacklist(self) -> bool:
        """
        同步云端黑名单
        """
        try:
            response = requests.get(
                f"{self.endpoint}/v1/blacklist",
                headers={'X-API-Key': self.api_key},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                
                self.blacklist_ips = set(data.get('ips', []))
                self.blacklist_domains = set(data.get('domains', []))
                self.blacklist_hashes = set(data.get('hashes', []))
                
                logger.info(f"☁️ 黑名单已同步: {len(self.blacklist_ips)} IP, "
                          f"{len(self.blacklist_domains)} 域名")
                return True
            else:
                logger.error(f"同步失败: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"同步异常: {e}")
            return False
            
    def check_threat(self, ip: str = None, domain: str = None, file_hash: str = None) -> dict:
        """
        查询威胁情报
        """
        # 先查本地缓存
        if ip and ip in self.blacklist_ips:
            return {'is_malicious': True, 'source': 'local', 'type': 'ip'}
        if domain and domain in self.blacklist_domains:
            return {'is_malicious': True, 'source': 'local', 'type': 'domain'}
        if file_hash and file_hash in self.blacklist_hashes:
            return {'is_malicious': True, 'source': 'local', 'type': 'hash'}
            
        # 查询云端
        try:
            params = {}
            if ip:
                params['ip'] = ip
            if domain:
                params['domain'] = domain
            if file_hash:
                params['hash'] = file_hash
                
            response = requests.get(
                f"{self.endpoint}/v1/check",
                params=params,
                headers={'X-API-Key': self.api_key},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'is_malicious': False, 'source': 'unknown'}
                
        except Exception as e:
            logger.error(f"查询异常: {e}")
            return {'is_malicious': False, 'source': 'error'}
            
    def subscribe_alerts(self, callback):
        """
        订阅云端告警 (使用Redis Pub/Sub或WebSocket)
        """
        if self.redis_client:
            def sub_loop():
                pubsub = self.redis_client.pubsub()
                pubsub.subscribe('jintang:alerts')
                for message in pubsub.listen():
                    if message['type'] == 'message':
                        try:
                            alert = json.loads(message['data'])
                            callback(alert)
                        except Exception as e:
                            logger.error(f"处理告警失败: {e}")
                            
            thread = threading.Thread(target=sub_loop, daemon=True)
            thread.start()
            logger.info("📡 已订阅云端告警通道")
        else:
            logger.warning("未配置Redis，无法订阅云端告警")
            
    def start(self):
        """启动云端客户端"""
        self.running = True
        
        # 启动同步线程
        def sync_loop():
            while self.running:
                time.sleep(self.config.get('upload_interval', 300))
                self.sync_blacklist()
                
                # 处理重试队列
                while not self.report_queue.empty():
                    threat = self.report_queue.get()
                    self.upload_threat(threat)
                    
        self._sync_thread = threading.Thread(target=sync_loop, daemon=True)
        self._sync_thread.start()
        
        # 立即同步一次
        self.sync_blacklist()
        
        logger.info("☁️ 云端联动客户端已启动")
        
    def stop(self):
        """停止云端客户端"""
        self.running = False
        logger.info("🛑 云端联动客户端已停止")
        
    def get_stats(self) -> dict:
        """获取统计信息"""
        return {
            'blacklist_ips': len(self.blacklist_ips),
            'blacklist_domains': len(self.blacklist_domains),
            'pending_reports': self.report_queue.qsize(),
            'connected': self.redis_client is not None
        }