import os
import json
from datetime import datetime
from typing import Dict, List, Optional
from ..utils.logger import logger

class LogManager:
    def __init__(self):
        """初始化日志管理器"""
        self.log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
        self.scan_log_file = os.path.join(self.log_dir, 'scan.log')
        self.system_log_file = os.path.join(self.log_dir, 'system.log')
        self._ensure_log_directory()

    def _ensure_log_directory(self):
        """确保日志目录和文件存在"""
        try:
            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)
            
            # 确保日志文件存在
            for log_file in [self.scan_log_file, self.system_log_file]:
                if not os.path.exists(log_file):
                    open(log_file, 'a').close()
                    
        except Exception as e:
            logger.error(f"创建日志目录或文件时出错: {e}")

    async def get_logs(self, 
                      log_type: str = 'scan',
                      start_time: Optional[str] = None,
                      end_time: Optional[str] = None,
                      level: Optional[str] = None,
                      limit: int = 1000) -> List[Dict]:
        """获取日志记录
        
        Args:
            log_type: 日志类型 ('scan' 或 'system')
            start_time: 开始时间 (ISO格式)
            end_time: 结束时间 (ISO格式)
            level: 日志级别 (DEBUG/INFO/WARNING/ERROR)
            limit: 返回的最大记录数
            
        Returns:
            List[Dict]: 日志记录列表
        """
        try:
            logs = []
            log_file = self.scan_log_file if log_type == 'scan' else self.system_log_file
            
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            log_entry = self._parse_log_line(line)
                            if log_entry and self._filter_log_entry(log_entry, start_time, end_time, level):
                                logs.append(log_entry)
                                if len(logs) >= limit:
                                    break
                        except Exception as e:
                            logger.error(f"解析日志行时出错: {e}")
                            continue
            
            return logs
            
        except Exception as e:
            logger.error(f"获取日志时出错: {e}")
            return []

    def _parse_log_line(self, line: str) -> Optional[Dict]:
        """解析单行日志
        
        Args:
            line: 日志行文本
            
        Returns:
            Dict: 解析后的日志条目
        """
        try:
            # 假设日志格式为: [2024-03-09 14:30:45,123] [ERROR] 消息内容
            parts = line.strip().split('] [', 2)
            if len(parts) >= 2:
                timestamp = parts[0].strip('[')
                level = parts[1].strip(']')
                message = parts[-1].strip()
                
                return {
                    'timestamp': timestamp,
                    'level': level,
                    'message': message
                }
            return None
            
        except Exception:
            return None

    def _filter_log_entry(self, 
                         entry: Dict,
                         start_time: Optional[str],
                         end_time: Optional[str],
                         level: Optional[str]) -> bool:
        """过滤日志条目
        
        Args:
            entry: 日志条目
            start_time: 开始时间
            end_time: 结束时间
            level: 日志级别
            
        Returns:
            bool: 是否符合过滤条件
        """
        try:
            # 检查日志级别
            if level and entry['level'].upper() != level.upper():
                return False
            
            # 检查时间范围
            if start_time or end_time:
                log_time = datetime.fromisoformat(entry['timestamp'].replace(',', '.'))
                
                if start_time:
                    start = datetime.fromisoformat(start_time)
                    if log_time < start:
                        return False
                        
                if end_time:
                    end = datetime.fromisoformat(end_time)
                    if log_time > end:
                        return False
            
            return True
            
        except Exception:
            return False

    async def clear_logs(self, log_type: str = 'scan') -> bool:
        """清除日志文件
        
        Args:
            log_type: 日志类型 ('scan' 或 'system')
            
        Returns:
            bool: 是否成功清除
        """
        try:
            log_file = self.scan_log_file if log_type == 'scan' else self.system_log_file
            if os.path.exists(log_file):
                with open(log_file, 'w') as f:
                    f.write('')
                logger.info(f"{log_type} 日志文件已清除")
                return True
            return False
        except Exception as e:
            logger.error(f"清除日志文件时出错: {e}")
            return False

    async def get_log_stats(self, log_type: str = 'scan') -> Dict:
        """获取日志统计信息
        
        Args:
            log_type: 日志类型 ('scan' 或 'system')
            
        Returns:
            Dict: 统计信息
        """
        try:
            stats = {
                'total_entries': 0,
                'by_level': {
                    'DEBUG': 0,
                    'INFO': 0,
                    'WARNING': 0,
                    'ERROR': 0
                },
                'last_entry': None,
                'file_size': 0
            }
            
            log_file = self.scan_log_file if log_type == 'scan' else self.system_log_file
            
            if os.path.exists(log_file):
                stats['file_size'] = os.path.getsize(log_file)
                
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        entry = self._parse_log_line(line)
                        if entry:
                            stats['total_entries'] += 1
                            level = entry['level'].upper()
                            if level in stats['by_level']:
                                stats['by_level'][level] += 1
                            stats['last_entry'] = entry
            
            return stats
            
        except Exception as e:
            logger.error(f"获取日志统计信息时出错: {e}")
            return {}

    def log(self, level: str, message: str, log_type: str = 'scan'):
        """写入日志
        
        Args:
            level: 日志级别
            message: 日志消息
            log_type: 日志类型 ('scan' 或 'system')
        """
        try:
            log_file = self.scan_log_file if log_type == 'scan' else self.system_log_file
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
            log_line = f"[{timestamp}] [{level.upper()}] {message}\n"
            
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(log_line)
                
        except Exception as e:
            logger.error(f"写入日志时出错: {e}") 