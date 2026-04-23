#!/usr/bin/env python3
"""
金汤 - 生物特征验证模块
人脸识别、声纹识别、可选的脑机接口
"""

import base64
import hashlib
import time
import json
import os
from typing import Tuple, Optional, Dict
from dataclasses import dataclass
import logging

# 尝试导入可选依赖
try:
    import cv2
    import face_recognition
    FACE_AVAILABLE = True
except ImportError:
    FACE_AVAILABLE = False
    
try:
    import speech_recognition as sr
    VOICE_AVAILABLE = True
except ImportError:
    VOICE_AVAILABLE = False
    
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class BiometricProfile:
    """生物特征画像"""
    face_encoding: Optional[bytes] = None
    voice_fingerprint: Optional[bytes] = None
    last_verified: float = 0
    verification_count: int = 0
    failure_count: int = 0


class BiometricValidator:
    """生物特征验证器"""
    
    def __init__(self, config: dict):
        self.config = config
        self.profile_path = "biometric_profile.json"
        self.profile: Optional[BiometricProfile] = None
        
        # 验证阈值
        self.face_threshold = 0.6          # 人脸相似度阈值
        self.voice_threshold = 0.7         # 声纹相似度阈值
        
        # 验证状态
        self.authenticated = False
        self.auth_timeout = 300             # 验证超时(秒)
        self.last_auth_time = 0
        
        # 可用性标志
        self.face_enabled = config.get('face_enabled', False) and FACE_AVAILABLE
        self.voice_enabled = config.get('voice_enabled', False) and VOICE_AVAILABLE
        self.bci_enabled = config.get('brain_computer', False)  # 脑机接口预留
        
        self._load_profile()
        
    def _load_profile(self):
        """加载生物特征配置"""
        if os.path.exists(self.profile_path):
            try:
                with open(self.profile_path, 'r') as f:
                    data = json.load(f)
                self.profile = BiometricProfile(**data)
                logger.info("✅ 生物特征配置已加载")
            except Exception as e:
                logger.error(f"加载配置失败: {e}")
                
    def _save_profile(self):
        """保存生物特征配置"""
        if self.profile:
            with open(self.profile_path, 'w') as f:
                json.dump(self.profile.__dict__, f, indent=2)
            logger.info("💾 生物特征配置已保存")
            
    def enroll_face(self, image_path: str = None, camera_id: int = 0) -> bool:
        """
        注册人脸特征
        """
        if not self.face_enabled:
            logger.error("人脸识别未启用或依赖缺失")
            return False
            
        try:
            if image_path:
                image = face_recognition.load_image_file(image_path)
            else:
                # 从摄像头捕获
                cap = cv2.VideoCapture(camera_id)
                ret, frame = cap.read()
                cap.release()
                if not ret:
                    logger.error("摄像头捕获失败")
                    return False
                image = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                
            # 提取人脸编码
            face_encodings = face_recognition.face_encodings(image)
            if not face_encodings:
                logger.error("未检测到人脸")
                return False
                
            # 保存第一个检测到的人脸
            face_bytes = face_encodings[0].tobytes()
            
            if not self.profile:
                self.profile = BiometricProfile()
            self.profile.face_encoding = base64.b64encode(face_bytes).decode()
            self._save_profile()
            
            logger.info("✅ 人脸注册成功")
            return True
            
        except Exception as e:
            logger.error(f"人脸注册失败: {e}")
            return False
            
    def verify_face(self, image_path: str = None, camera_id: int = 0) -> Tuple[bool, float]:
        """
        验证人脸
        返回: (是否通过, 置信度)
        """
        if not self.face_enabled or not self.profile or not self.profile.face_encoding:
            return False, 0.0
            
        try:
            if image_path:
                image = face_recognition.load_image_file(image_path)
            else:
                cap = cv2.VideoCapture(camera_id)
                ret, frame = cap.read()
                cap.release()
                if not ret:
                    return False, 0.0
                image = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                
            face_encodings = face_recognition.face_encodings(image)
            if not face_encodings:
                return False, 0.0
                
            # 加载已注册的编码
            saved_encoding = np.frombuffer(
                base64.b64decode(self.profile.face_encoding),
                dtype=np.float64
            )
            
            # 计算相似度
            distances = face_recognition.face_distance([saved_encoding], face_encodings[0])
            similarity = 1 - distances[0]
            
            is_match = similarity > self.face_threshold
            
            if is_match:
                self._update_verification_success()
                
            return is_match, similarity
            
        except Exception as e:
            logger.error(f"人脸验证失败: {e}")
            return False, 0.0
            
    def enroll_voice(self, duration: int = 3) -> bool:
        """
        注册声纹特征
        """
        if not self.voice_enabled:
            logger.error("声纹识别未启用")
            return False
            
        try:
            recognizer = sr.Recognizer()
            mic = sr.Microphone()
            
            logger.info(f"请对着麦克风说话 {duration} 秒...")
            
            with mic as source:
                recognizer.adjust_for_ambient_noise(source)
                audio = recognizer.record(source, duration=duration)
                
            # 生成声纹指纹 (简化: 使用音频哈希)
            audio_bytes = audio.get_wav_data()
            voice_hash = hashlib.sha256(audio_bytes).hexdigest()
            
            if not self.profile:
                self.profile = BiometricProfile()
            self.profile.voice_fingerprint = voice_hash
            self._save_profile()
            
            logger.info("✅ 声纹注册成功")
            return True
            
        except Exception as e:
            logger.error(f"声纹注册失败: {e}")
            return False
            
    def verify_voice(self, duration: int = 3) -> Tuple[bool, float]:
        """
        验证声纹
        """
        if not self.voice_enabled or not self.profile or not self.profile.voice_fingerprint:
            return False, 0.0
            
        try:
            recognizer = sr.Recognizer()
            mic = sr.Microphone()
            
            with mic as source:
                recognizer.adjust_for_ambient_noise(source)
                audio = recognizer.record(source, duration=duration)
                
            audio_bytes = audio.get_wav_data()
            current_hash = hashlib.sha256(audio_bytes).hexdigest()
            
            # 简化验证: 比较哈希
            is_match = current_hash == self.profile.voice_fingerprint
            
            return is_match, 1.0 if is_match else 0.0
            
        except Exception as e:
            logger.error(f"声纹验证失败: {e}")
            return False, 0.0
            
    def verify_brain_computer(self) -> Tuple[bool, float]:
        """
        脑机接口验证 (预留接口)
        未来可接入 OpenBCI、NeuroSky 等设备
        """
        if not self.bci_enabled:
            return False, 0.0
            
        # TODO: 实现脑机接口验证
        logger.warning("脑机接口验证暂未实现")
        return False, 0.0
        
    def _update_verification_success(self):
        """更新验证成功状态"""
        self.authenticated = True
        self.last_auth_time = time.time()
        if self.profile:
            self.profile.last_verified = time.time()
            self.profile.verification_count += 1
            self._save_profile()
            
    def is_authenticated(self) -> Tuple[bool, str]:
        """
        检查当前验证状态
        返回: (是否已认证, 状态信息)
        """
        if not self.authenticated:
            return False, "未认证"
            
        if time.time() - self.last_auth_time > self.auth_timeout:
            self.authenticated = False
            return False, "认证已过期"
            
        return True, "已认证"
        
    def require_authentication(self, context: str = "敏感操作") -> Tuple[bool, str]:
        """
        要求用户进行多因素认证
        """
        if self.is_authenticated()[0]:
            return True, "已有有效认证"
            
        logger.info(f"🔐 请进行身份验证: {context}")
        
        # 尝试多种验证方式
        if self.face_enabled:
            success, confidence = self.verify_face()
            if success:
                return True, f"人脸验证通过 (置信度: {confidence:.2%})"
                
        if self.voice_enabled:
            success, confidence = self.verify_voice()
            if success:
                return True, f"声纹验证通过 (置信度: {confidence:.2%})"
                
        if self.bci_enabled:
            success, confidence = self.verify_brain_computer()
            if success:
                return True, f"脑机验证通过 (置信度: {confidence:.2%})"
                
        return False, "身份验证失败"
        
    def get_status(self) -> dict:
        """获取验证状态"""
        return {
            'authenticated': self.authenticated,
            'face_enabled': self.face_enabled,
            'voice_enabled': self.voice_enabled,
            'bci_enabled': self.bci_enabled,
            'face_registered': self.profile and bool(self.profile.face_encoding),
            'voice_registered': self.profile and bool(self.profile.voice_fingerprint),
            'verification_count': self.profile.verification_count if self.profile else 0
        }