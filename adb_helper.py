import subprocess
from typing import List, Dict, Optional
import os
from .logger import logger

class ADBHelper:
    @staticmethod
    def execute_command(command: List[str], device_id: Optional[str] = None) -> Dict:
        """执行ADB命令"""
        try:
            if device_id:
                command.insert(1, '-s')
                command.insert(2, device_id)
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            
            return {
                'status': 'success',
                'output': result.stdout.strip(),
                'error': result.stderr.strip()
            }
        except subprocess.CalledProcessError as e:
            logger.error(f"ADB命令执行失败: {e}")
            return {
                'status': 'error',
                'output': '',
                'error': str(e)
            }
        except Exception as e:
            logger.error(f"执行ADB命令时出错: {e}")
            return {
                'status': 'error',
                'output': '',
                'error': str(e)
            }

    @staticmethod
    def check_adb_server():
        """检查ADB服务器状态，如果未运行则启动"""
        try:
            subprocess.run(['adb', 'start-server'], check=True)
            return True
        except Exception as e:
            logger.error(f"启动ADB服务器失败: {e}")
            return False

    @staticmethod
    def kill_adb_server():
        """终止ADB服务器"""
        try:
            subprocess.run(['adb', 'kill-server'], check=True)
            return True
        except Exception as e:
            logger.error(f"终止ADB服务器失败: {e}")
            return False

    @staticmethod
    def get_device_prop(device_id: str, prop: str) -> str:
        """获取设备属性"""
        result = ADBHelper.execute_command(
            ['adb', 'shell', 'getprop', prop],
            device_id
        )
        return result['output'] if result['status'] == 'success' else ''

    @staticmethod
    def push_file(device_id: str, local_path: str, remote_path: str) -> bool:
        """将文件推送到设备"""
        result = ADBHelper.execute_command(
            ['adb', 'push', local_path, remote_path],
            device_id
        )
        return result['status'] == 'success'

    @staticmethod
    def pull_file(device_id: str, remote_path: str, local_path: str) -> bool:
        """从设备拉取文件"""
        result = ADBHelper.execute_command(
            ['adb', 'pull', remote_path, local_path],
            device_id
        )
        return result['status'] == 'success'

    @staticmethod
    def shell_command(device_id: str, command: str) -> Dict:
        """在设备上执行shell命令"""
        return ADBHelper.execute_command(
            ['adb', 'shell', command],
            device_id
        ) 