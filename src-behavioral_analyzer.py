#!/usr/bin/env python3
"""
金汤 - 行为基线分析模块
建立用户操作习惯模型，区分真人与自动化脚本
"""

import time
import threading
import json
import os
from collections import deque
from dataclasses import dataclass, field
from typing import List, Tuple, Optional
import logging

import numpy as np
from pynput import mouse, keyboard

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class MouseEvent:
    timestamp: float
    x: int
    y: int
    event_type: str  # 'move', 'click', 'scroll'


@dataclass
class KeyboardEvent:
    timestamp: float
    key: str
    event_type: str  # 'press', 'release'


@dataclass
class BehavioralProfile:
    """用户行为画像"""
    # 鼠标特征
    avg_speed: float = 0.0           # 平均移动速度 (像素/秒)
    speed_std: float = 0.0           # 速度标准差
    click_duration_mean: float = 0.0 # 平均点击持续时间
    click_duration_std: float = 0.0
    trajectory_curvature: float = 0.0 # 轨迹曲率
    
    # 键盘特征
    typing_speed: float = 0.0        # 打字速度 (字符/秒)
    dwell_time_mean: float = 0.0     # 按键停留时间
    flight_time_mean: float = 0.0    # 按键间隔时间
    backspace_rate: float = 0.0      # 退格率
    
    # 统计信息
    total_events: int = 0
    sample_duration: float = 0.0


class BehavioralAnalyzer:
    """行为分析器 - 区分真人与自动化"""
    
    def __init__(self, profile_path: str = "user_profile.json"):
        self.profile_path = profile_path
        self.profile: BehavioralProfile = BehavioralProfile()
        self.baseline: Optional[BehavioralProfile] = None
        
        # 实时数据缓存
        self.mouse_events: deque = deque(maxlen=10000)
        self.key_events: deque = deque(maxlen=10000)
        
        # 鼠标轨迹分析
        self.last_mouse_pos = None
        self.last_mouse_time = None
        self.mouse_speeds: List[float] = []
        
        # 键盘分析
        self.key_press_times: dict = {}
        self.key_durations: List[float] = []
        self.key_intervals: List[float] = []
        self.last_key_time = None
        self.backspace_count = 0
        self.total_keystrokes = 0
        
        self.running = False
        self.mouse_listener = None
        self.keyboard_listener = None
        
        # 加载已有基线
        self.load_baseline()
        
    def _on_mouse_move(self, x: int, y: int):
        """鼠标移动回调"""
        current_time = time.time()
        
        if self.last_mouse_pos is not None and self.last_mouse_time is not None:
            dx = x - self.last_mouse_pos[0]
            dy = y - self.last_mouse_pos[1]
            dt = current_time - self.last_mouse_time
            
            if dt > 0:
                speed = np.sqrt(dx**2 + dy**2) / dt
                self.mouse_speeds.append(speed)
                
        self.last_mouse_pos = (x, y)
        self.last_mouse_time = current_time
        
        self.mouse_events.append(MouseEvent(
            timestamp=current_time,
            x=x, y=y,
            event_type='move'
        ))
        
    def _on_mouse_click(self, x: int, y: int, button, pressed: bool):
        """鼠标点击回调"""
        self.mouse_events.append(MouseEvent(
            timestamp=time.time(),
            x=x, y=y,
            event_type='click' if pressed else 'release'
        ))
        
    def _on_key_press(self, key):
        """键盘按下回调"""
        current_time = time.time()
        key_str = str(key)
        
        self.key_press_times[key_str] = current_time
        self.total_keystrokes += 1
        
        if key_str == 'Key.backspace':
            self.backspace_count += 1
            
        # 计算按键间隔
        if self.last_key_time is not None:
            interval = current_time - self.last_key_time
            self.key_intervals.append(interval)
        self.last_key_time = current_time
        
        self.key_events.append(KeyboardEvent(
            timestamp=current_time,
            key=key_str,
            event_type='press'
        ))
        
    def _on_key_release(self, key):
        """键盘释放回调"""
        current_time = time.time()
        key_str = str(key)
        
        if key_str in self.key_press_times:
            duration = current_time - self.key_press_times[key_str]
            self.key_durations.append(duration)
            del self.key_press_times[key_str]
            
        self.key_events.append(KeyboardEvent(
            timestamp=current_time,
            key=key_str,
            event_type='release'
        ))
        
    def compute_profile(self) -> BehavioralProfile:
        """计算当前行为画像"""
        profile = BehavioralProfile()
        
        # 鼠标特征
        if self.mouse_speeds:
            profile.avg_speed = np.mean(self.mouse_speeds)
            profile.speed_std = np.std(self.mouse_speeds)
            
        # 点击特征
        click_events = [e for e in self.mouse_events if e.event_type == 'click']
        # 简化: 使用采样数据
        
        # 键盘特征
        if self.key_durations:
            profile.dwell_time_mean = np.mean(self.key_durations)
            profile.dwell_time_std = np.std(self.key_durations)
            
        if self.key_intervals:
            profile.flight_time_mean = np.mean(self.key_intervals)
            
        if self.total_keystrokes > 0:
            profile.backspace_rate = self.backspace_count / self.total_keystrokes
            
        # 打字速度
        if len(self.key_events) > 0:
            duration = self.key_events[-1].timestamp - self.key_events[0].timestamp
            if duration > 0:
                profile.typing_speed = self.total_keystrokes / duration
                
        profile.total_events = len(self.mouse_events) + len(self.key_events)
        
        # 估算采样时长
        all_events = list(self.mouse_events) + list(self.key_events)
        if all_events:
            profile.sample_duration = all_events[-1].timestamp - all_events[0].timestamp
            
        return profile
        
    def load_baseline(self):
        """加载行为基线"""
        if os.path.exists(self.profile_path):
            try:
                with open(self.profile_path, 'r') as f:
                    data = json.load(f)
                self.baseline = BehavioralProfile(**data)
                logger.info("✅ 已加载用户行为基线")
            except Exception as e:
                logger.error(f"加载基线失败: {e}")
                
    def save_baseline(self):
        """保存行为基线"""
        if self.profile:
            with open(self.profile_path, 'w') as f:
                json.dump(self.profile.__dict__, f, indent=2)
            logger.info("💾 用户行为基线已保存")
            
    def train_baseline(self, duration_seconds: int = 300):
        """
        训练行为基线
        收集指定时长的用户行为数据
        """
        logger.info(f"📊 开始收集行为数据，请正常操作 {duration_seconds} 秒...")
        time.sleep(duration_seconds)
        
        self.profile = self.compute_profile()
        self.save_baseline()
        logger.info("✅ 行为基线训练完成")
        
    def detect_anomaly(self) -> Tuple[bool, float, str]:
        """
        检测当前行为是否异常
        返回: (是否异常, 异常分数, 原因)
        """
        if self.baseline is None:
            return False, 0.0, "无行为基线"
            
        current = self.compute_profile()
        if current.total_events < 50:
            return False, 0.0, "样本不足"
            
        anomaly_score = 0.0
        reasons = []
        
        # 检测打字速度异常
        if current.typing_speed > 0 and self.baseline.typing_speed > 0:
            speed_ratio = current.typing_speed / self.baseline.typing_speed
            if speed_ratio > 3 or speed_ratio < 0.3:
                anomaly_score += 0.4
                reasons.append(f"打字速度异常 ({current.typing_speed:.1f} vs {self.baseline.typing_speed:.1f} cps)")
                
        # 检测退格率异常 (自动化脚本通常退格率极低)
        if current.backspace_rate < 0.01 and self.baseline.backspace_rate > 0.05:
            anomaly_score += 0.3
            reasons.append("退格率过低 (疑似自动化)")
            
        # 检测按键持续时间异常
        if current.dwell_time_mean > 0 and self.baseline.dwell_time_mean > 0:
            dwell_ratio = current.dwell_time_mean / self.baseline.dwell_time_mean
            if dwell_ratio > 2 or dwell_ratio < 0.5:
                anomaly_score += 0.2
                reasons.append(f"按键持续时间异常 ({current.dwell_time_mean*1000:.0f}ms)")
                
        is_anomaly = anomaly_score > 0.5
        reason = "; ".join(reasons) if reasons else "无明显异常"
        
        return is_anomaly, anomaly_score, reason
        
    def start(self):
        """启动行为监控"""
        self.running = True
        
        # 启动鼠标监听
        self.mouse_listener = mouse.Listener(
            on_move=self._on_mouse_move,
            on_click=self._on_mouse_click
        )
        self.mouse_listener.start()
        
        # 启动键盘监听
        self.keyboard_listener = keyboard.Listener(
            on_press=self._on_key_press,
            on_release=self._on_key_release
        )
        self.keyboard_listener.start()
        
        logger.info("👁️ 行为监控已启动")
        
    def stop(self):
        """停止行为监控"""
        self.running = False
        if self.mouse_listener:
            self.mouse_listener.stop()
        if self.keyboard_listener:
            self.keyboard_listener.stop()
        logger.info("🛑 行为监控已停止")
        
    def get_stats(self) -> dict:
        """获取统计信息"""
        return {
            'mouse_events': len(self.mouse_events),
            'key_events': len(self.key_events),
            'total_keystrokes': self.total_keystrokes,
            'backspace_rate': self.backspace_rate,
            'typing_speed': self.profile.typing_speed if self.profile else 0
        }