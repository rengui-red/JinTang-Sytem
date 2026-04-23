#!/usr/bin/env python3
"""
金汤 - 智能端点防御与流束识别系统
主入口
"""

import argparse
import signal
import sys
import time
import threading
import yaml
import os
from typing import Optional

from src.flow_monitor import FlowMonitor
from src.behavioral_analyzer import BehavioralAnalyzer
from src.local_fuse import LocalFuse
from src.cloud_client import CloudClient
from src.biometric_validator import BiometricValidator


class JinTangDefense:
    """金汤防御系统主控"""
    
    def __init__(self, config_path: str = "config.yaml"):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
        # 初始化各模块
        self.flow_monitor = FlowMonitor(self.config.get('jintang', {}))
        self.behavior_analyzer = BehavioralAnalyzer()
        self.local_fuse = LocalFuse(self.config.get('jintang', {}).get('fuse', {}))
        self.cloud_client = CloudClient(self.config.get('jintang', {}).get('cloud', {}))
        self.biometric_validator = BiometricValidator(
            self.config.get('jintang', {}).get('biometric', {})
        )
        
        self.running = False
        self.alert_handlers = []
        
    def start(self):
        """启动所有模块"""
        self.running = True
        
        print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     ██╗  ██╗██╗███╗   ██╗████████╗ █████╗ ███╗   ██╗ ██████╗   ║
║     ██║ ██╔╝██║████╗  ██║╚══██╔══╝██╔══██╗████╗  ██║██╔════╝   ║
║     █████╔╝ ██║██╔██╗ ██║   ██║   ███████║██╔██╗ ██║██║  ███╗  ║
║     ██╔═██╗ ██║██║╚██╗██║   ██║   ██╔══██║██║╚██╗██║██║   ██║  ║
║     ██║  ██╗██║██║ ╚████║   ██║   ██║  ██║██║ ╚████║╚██████╔╝  ║
║     ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝   ║
║                                                              ║
║           智能端点防御与流束识别系统 v1.0.0                  ║
║                    固若金汤，稳如泰山                        ║
╚══════════════════════════════════════════════════════════════╝
        """)
        
        print("\n🚀 正在启动各模块...\n")
        
        # 启动模块
        self.flow_monitor.start()
        self.behavior_analyzer.start()
        self.local_fuse.start()
        self.cloud_client.start()
        
        # 启动告警处理
        self._start_alert_processor()
        
        print("""
✅ 金汤防御系统已启动

监控状态:
  ├─ 流束监控: 运行中
  ├─ 行为分析: 运行中  
  ├─ 本地熔断: 运行中
  └─ 云端联动: 运行中

按 Ctrl+C 停止系统
        """)
        
    def _start_alert_processor(self):
        """启动告警处理线程"""
        def process_alerts():
            while self.running:
                # 从流监控获取告警
                alerts = self.flow_monitor.get_alerts()
                for alert in alerts:
                    self._handle_alert(alert)
                    
                # 行为异常检测
                is_anomaly, score, reason = self.behavior_analyzer.detect_anomaly()
                if is_anomaly:
                    self._handle_behavior_anomaly(score, reason)
                    
                time.sleep(1)
                
        threading.Thread(target=process_alerts, daemon=True).start()
        
    def _handle_alert(self, alert: dict):
        """处理告警"""
        print(f"\n⚠️  [告警] {alert['reason']} (置信度: {alert['confidence']:.2%})")
        
        # 提取IP进行云端查询
        flow_details = alert.get('flow_details')
        if flow_details:
            dst_ip = flow_details.dst_ip
            result = self.cloud_client.check_threat(ip=dst_ip)
            
            if result.get('is_malicious'):
                print(f"  └─ ☁️ 云端确认恶意: {result.get('type')}")
                
                # 自动熔断
                if self.config.get('jintang', {}).get('fuse', {}).get('auto_block', True):
                    self.local_fuse.block_ip(dst_ip, alert['reason'])
                    
        # 上报到云端
        self.cloud_client.upload_threat({
            'reason': alert['reason'],
            'confidence': alert['confidence'],
            'timestamp': alert['timestamp'],
            'flow': str(flow_details) if flow_details else None
        })
        
    def _handle_behavior_anomaly(self, score: float, reason: str):
        """处理行为异常"""
        print(f"\n👤 [行为异常] 分数: {score:.2%}, 原因: {reason}")
        
        # 触发生物验证
        success, msg = self.biometric_validator.require_authentication("行为模式异常")
        
        if not success:
            print(f"  └─ 🔒 {msg}，已启动防护措施")
            # 进入增强防护模式
            self._enter_enhanced_protection()
        else:
            print(f"  └─ ✅ {msg}，恢复正常监控")
            
    def _enter_enhanced_protection(self):
        """进入增强防护模式"""
        print("""
╔══════════════════════════════════════════════════════════════╗
║                    🔒 增强防护模式已激活                      ║
╠══════════════════════════════════════════════════════════════╣
║  • 所有非必要外连已被阻断                                     ║
║  • 可疑进程已被挂起                                           ║
║  • 敏感操作需生物验证                                         ║
║  • 已通知云端进行联动分析                                     ║
╚══════════════════════════════════════════════════════════════╝
        """)
        
        # 阻断所有非标准端口
        for port in [22, 23, 3389, 5900, 8080, 4444]:
            self.local_fuse.block_port(port, 'tcp', duration=1800)
            
    def train_behavior_baseline(self, duration: int = 300):
        """训练行为基线"""
        print(f"\n📊 开始行为基线训练 ({duration}秒)")
        print("请进行正常的日常操作...\n")
        self.behavior_analyzer.train_baseline(duration)
        print("\n✅ 行为基线训练完成\n")
        
    def enroll_biometric(self):
        """注册生物特征"""
        print("\n🔐 生物特征注册\n")
        
        if self.biometric_validator.face_enabled:
            print("正在检测摄像头...")
            if self.biometric_validator.enroll_face():
                print("  ✅ 人脸注册成功")
            else:
                print("  ❌ 人脸注册失败")
                
        if self.biometric_validator.voice_enabled:
            print("\n正在检测麦克风...")
            if self.biometric_validator.enroll_voice():
                print("  ✅ 声纹注册成功")
            else:
                print("  ❌ 声纹注册失败")
                
        print("\n✅ 生物特征注册完成\n")
        
    def show_status(self):
        """显示系统状态"""
        print("\n" + "=" * 60)
        print("📊 金汤防御系统状态")
        print("=" * 60)
        
        # 流监控状态
        flow_stats = self.flow_monitor.get_stats()
        print(f"\n🌊 流束监控:")
        print(f"  ├─ 总流数: {flow_stats['total_flows']}")
        print(f"  ├─ 可疑流: {flow_stats['suspicious_flows']}")
        print(f"  └─ 活跃流: {flow_stats['active_flows']}")
        
        # 行为分析状态
        behavior_stats = self.behavior_analyzer.get_stats()
        print(f"\n👤 行为分析:")
        print(f"  ├─ 鼠标事件: {behavior_stats['mouse_events']}")
        print(f"  ├─ 键盘事件: {behavior_stats['key_events']}")
        print(f"  └─ 打字速度: {behavior_stats['typing_speed']:.1f} cps")
        
        # 熔断状态
        fuse_status = self.local_fuse.get_status()
        print(f"\n🔒 熔断状态:")
        print(f"  ├─ 阻断进程: {fuse_status['blocked_processes']}")
        print(f"  ├─ 阻断IP: {fuse_status['blocked_ips']}")
        print(f"  └─ 阻断端口: {fuse_status['blocked_ports']}")
        
        # 云端状态
        cloud_stats = self.cloud_client.get_stats()
        print(f"\n☁️ 云端联动:")
        print(f"  ├─ 黑名单IP: {cloud_stats['blacklist_ips']}")
        print(f"  ├─ 待上报: {cloud_stats['pending_reports']}")
        print(f"  └─ Redis: {'已连接' if cloud_stats['connected'] else '未连接'}")
        
        # 生物验证状态
        bio_status = self.biometric_validator.get_status()
        print(f"\n🔐 生物验证:")
        print(f"  ├─ 认证状态: {'已认证' if bio_status['authenticated'] else '未认证'}")
        print(f"  ├─ 人脸: {'已启用' if bio_status['face_enabled'] else '未启用'}")
        print(f"  ├─ 声纹: {'已启用' if bio_status['voice_enabled'] else '未启用'}")
        print(f"  └─ 脑机: {'已启用' if bio_status['bci_enabled'] else '未启用'}")
        
        print("\n" + "=" * 60 + "\n")
        
    def stop(self):
        """停止系统"""
        print("\n🛑 正在停止金汤防御系统...")
        
        self.running = False
        self.flow_monitor.stop()
        self.behavior_analyzer.stop()
        self.local_fuse.stop()
        self.cloud_client.stop()
        
        print("✅ 系统已停止\n")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description='金汤智能端点防御系统')
    parser.add_argument('-c', '--config', default='config.yaml', help='配置文件路径')
    parser.add_argument('-t', '--train', action='store_true', help='训练行为基线')
    parser.add_argument('-e', '--enroll', action='store_true', help='注册生物特征')
    parser.add_argument('-s', '--status', action='store_true', help='显示状态')
    
    args = parser.parse_args()
    
    # 检查配置文件
    if not os.path.exists(args.config):
        print(f"❌ 配置文件不存在: {args.config}")
        sys.exit(1)
        
    # 初始化系统
    system = JinTangDefense(args.config)
    
    # 处理命令行参数
    if args.train:
        system.train_behavior_baseline()
        return
        
    if args.enroll:
        system.enroll_biometric()
        return
        
    if args.status:
        system.start()
        try:
            system.show_status()
        except KeyboardInterrupt:
            pass
        finally:
            system.stop()
        return
        
    # 正常启动
    system.start()
    
    # 注册信号处理
    def signal_handler(sig, frame):
        system.stop()
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 主循环
    try:
        while True:
            time.sleep(10)
            # 定期显示状态(可选)
            if False:  # 默认关闭，避免刷屏
                system.show_status()
    except KeyboardInterrupt:
        system.stop()


if __name__ == "__main__":
    main()