import os
import subprocess
from datetime import datetime
from typing import Dict
from ..utils.logger import logger
from ..utils.platform_tools import PlatformTools

class MemoryCleaner:
    def __init__(self):
        self.platform_tools = PlatformTools()
        self.is_windows = os.name == 'nt'
        self.logger = logger

    def _parse_memory_value(self, value: str) -> int:
        """解析带单位的内存值
        
        Args:
            value: 带单位的内存值字符串 (例如: '7827800K', '1.5G')
            
        Returns:
            int: 转换后的字节数
        """
        try:
            value = value.strip()
            
            if value.isdigit():
                return int(value)
            
            number = ''
            unit = ''
            for char in value:
                if char.isdigit() or char == '.':
                    number += char
                else:
                    unit += char.upper()
            
            number = float(number)
            
            unit_multipliers = {
                'K': 1024,
                'KB': 1024,
                'M': 1024 * 1024,
                'MB': 1024 * 1024,
                'G': 1024 * 1024 * 1024,
                'GB': 1024 * 1024 * 1024,
                'T': 1024 * 1024 * 1024 * 1024,
                'TB': 1024 * 1024 * 1024 * 1024
            }
            
            if unit in unit_multipliers:
                return int(number * unit_multipliers[unit])
            
            return int(number)
            
        except Exception as e:
            self.logger.error(f"解析内存值失败 '{value}': {str(e)}")
            return 0

    async def _get_device_memory_info(self, device_id: str) -> Dict:
        """获取设备内存信息"""
        try:
            mem_info = subprocess.run(
                [self.platform_tools.adb_path, "-s", device_id, "shell", "cat", "/proc/meminfo"],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            
            if mem_info.returncode != 0:
                return {}
            
            memory_stats = {}
            for line in mem_info.stdout.splitlines():
                if ':' in line:
                    key, value = line.split(':')
                    key = key.strip()
                    value = value.strip()
                    if value:
                        try:
                            memory_stats[key] = self._parse_memory_value(value)
                        except Exception as e:
                            self.logger.error(f"解析内存信息时出错: {str(e)}")
                            continue
            
            return memory_stats
            
        except Exception as e:
            self.logger.error(f"获取设备内存信息时出错: {str(e)}")
            return {}

    async def _check_root_access(self, device_id: str) -> bool:
        """检查设备是否有root权限"""
        try:
            result = subprocess.run(
                [self.platform_tools.adb_path, "-s", device_id, "shell", "su -c 'whoami'"],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=5
            )
            return result.returncode == 0 and 'root' in result.stdout
        except:
            return False

    async def clean_memory(self, device_id: str) -> Dict:
        """清理设备内存
        
        Args:
            device_id: 设备ID
            
        Returns:
            Dict: 包含清理结果和内存信息的字典
        """
        try:
            # 获取清理前的内存信息
            before_info = await self._get_device_memory_info(device_id)
            
            # 检查root权限
            has_root = await self._check_root_access(device_id)
            
            if has_root:
                await self._clean_memory_with_root(device_id)
            else:
                await self._clean_memory_without_root(device_id)
            
            # 获取清理后的内存信息
            after_info = await self._get_device_memory_info(device_id)
            
            # 计算释放的内存
            freed_memory = (after_info.get("MemAvailable", 0) - before_info.get("MemAvailable", 0)) / 1024  # 转换为MB
            
            return {
                "status": "success",
                "freed": round(freed_memory, 2),
                "memory_info": {
                    "before": {
                        "total": before_info.get("MemTotal", 0) / (1024*1024),
                        "available": before_info.get("MemAvailable", 0) / (1024*1024),
                        "free": before_info.get("MemFree", 0) / (1024*1024)
                    },
                    "after": {
                        "total": after_info.get("MemTotal", 0) / (1024*1024),
                        "available": after_info.get("MemAvailable", 0) / (1024*1024),
                        "free": after_info.get("MemFree", 0) / (1024*1024)
                    }
                }
            }
            
        except Exception as e:
            self.logger.error(f"清理内存失败: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    async def _clean_memory_with_root(self, device_id: str):
        """使用root权限清理内存"""
        try:
            # 1. 验证root权限
            root_check = subprocess.run(
                [self.platform_tools.adb_path, "-s", device_id, "shell", "su -c whoami"],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=5
            )
            
            if root_check.returncode != 0:
                self.logger.error(f"Root权限验证失败: {root_check.stderr}")
                await self._clean_memory_without_root(device_id)
                return

            # 使用Android系统自带的内存清理机制
            commands = [
                # 强制停止后台应用
                "su -c 'am force-stop com.android.chrome'",  # 示例：停止Chrome浏览器
                "su -c 'am force-stop com.android.vending'", # 停止Play商店
                
                # 清理各种缓存
                "su -c 'rm -rf /data/data/*/cache/*'",
                "su -c 'rm -rf /data/data/*/code_cache/*'",
                
                # 清理系统缓存
                "su -c 'rm -rf /cache/*'",
                
                # 使用am命令清理内存
                "su -c 'am kill-all'",
                "su -c 'am force-stop --user all'",
                
                # 使用activity manager清理
                "su -c 'am send-trim-memory * COMPLETE'",
                "su -c 'am send-trim-memory * RUNNING_CRITICAL'",
                
                # 使用package manager清理
                "su -c 'pm trim-caches 999999M'",
                
                # 清理特定目录
                "su -c 'rm -rf /data/local/tmp/*'",
                "su -c 'rm -rf /data/tombstones/*'",
                "su -c 'rm -rf /data/anr/*'",
                
                # 使用svc命令
                "su -c 'svc power stayon false'",
                
                # 使用dumpsys释放内存
                "su -c 'dumpsys meminfo --reset'",
                "su -c 'dumpsys gfxinfo --reset'"
            ]
            
            success = False
            for cmd in commands:
                try:
                    result = subprocess.run(
                        [self.platform_tools.adb_path, "-s", device_id, "shell", cmd],
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='ignore',
                        timeout=5
                    )
                    
                    self.logger.info(f"执行命令: {cmd}")
                    if result.returncode == 0:
                        self.logger.info(f"命令执行成功: {cmd}")
                        success = True
                    else:
                        self.logger.warning(f"命令执行失败: {cmd}, 错误: {result.stderr}")
                except Exception as e:
                    self.logger.warning(f"执行命令出错: {cmd}, 错误: {str(e)}")
                    continue

            if not success:
                self.logger.warning("所有root方式清理内存都失败，尝试其他方法")
                await self._clean_memory_without_root(device_id)
                
        except Exception as e:
            self.logger.error(f"使用root权限清理内存失败: {e}")
            await self._clean_memory_without_root(device_id)

    async def _clean_memory_without_root(self, device_id: str):
        """使用非root方式清理内存"""
        try:
            commands = [
                # 使用activity manager
                "am kill-all",
                "am force-stop --user all",
                "am send-trim-memory * COMPLETE",
                "am send-trim-memory * RUNNING_CRITICAL",
                
                # 使用package manager
                "pm trim-caches 999999M",
                "pm clear-system-cache",
                
                # 停止非必要的应用
                "am force-stop com.android.chrome",
                "am force-stop com.android.vending",
                "am force-stop com.google.android.youtube",
                
                # 使用dumpsys
                "dumpsys meminfo --reset",
                "dumpsys gfxinfo --reset",
                
                # 使用activity manager的其他选项
                "am memory-factor CRITICAL",
                "am memory-factor MODERATE",
                
                # 清理最近任务
                "am clear-recent-tasks",
                
                # 使用svc命令
                "svc power stayon false"
            ]
            
            success = False
            for cmd in commands:
                try:
                    result = subprocess.run(
                        [self.platform_tools.adb_path, "-s", device_id, "shell", cmd],
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='ignore',
                        timeout=10
                    )
                    
                    self.logger.info(f"执行命令: {cmd}")
                    if result.returncode == 0:
                        self.logger.info(f"命令执行成功: {cmd}")
                        success = True
                    else:
                        self.logger.warning(f"命令执行失败: {cmd}, 错误: {result.stderr}")
                except Exception as e:
                    self.logger.warning(f"执行命令出错: {cmd}, 错误: {str(e)}")
                    continue
            
            if not success:
                raise Exception("所有清理内存方法都失败")
                
        except Exception as e:
            self.logger.error(f"使用非root方式清理内存失败: {e}")
            raise 