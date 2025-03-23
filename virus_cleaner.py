import os
import subprocess
import shutil
from typing import Dict, List, Tuple
from ..utils.logger import logger
from ..utils.platform_tools import PlatformTools

class VirusCleaner:
    def __init__(self):
        self.platform_tools = PlatformTools()
        self.quarantine_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'quarantine')
        self._ensure_quarantine_dir()

    def _ensure_quarantine_dir(self):
        """确保隔离区目录存在"""
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

    async def clean_threats(self, device_id: str, threats: List[Dict]) -> Dict[str, List[Dict]]:
        """清理检测到的威胁
        
        Args:
            device_id: 设备ID
            threats: 威胁列表
            
        Returns:
            Dict: 清理结果
        """
        results = {
            'success': [],
            'failed': [],
            'quarantined': []
        }

        for threat in threats:
            try:
                file_path = threat['file_path']
                threat_type = threat.get('threat_type', 'unknown')
                
                # 根据威胁类型选择清理方法
                if self._is_app_threat(file_path):
                    success = await self._clean_app_threat(device_id, file_path)
                else:
                    success = await self._clean_file_threat(device_id, file_path)

                if success:
                    results['success'].append({
                        'file_path': file_path,
                        'threat_type': threat_type,
                        'action': 'removed'
                    })
                else:
                    # 如果无法删除，尝试隔离
                    quarantine_success = await self._quarantine_threat(device_id, file_path)
                    if quarantine_success:
                        results['quarantined'].append({
                            'file_path': file_path,
                            'threat_type': threat_type,
                            'action': 'quarantined'
                        })
                    else:
                        results['failed'].append({
                            'file_path': file_path,
                            'threat_type': threat_type,
                            'error': 'Failed to remove or quarantine'
                        })

            except Exception as e:
                logger.error(f"清理威胁时出错 {file_path}: {str(e)}")
                results['failed'].append({
                    'file_path': file_path,
                    'threat_type': threat.get('threat_type', 'unknown'),
                    'error': str(e)
                })

        return results

    def _is_app_threat(self, file_path: str) -> bool:
        """判断是否为应用威胁"""
        return file_path.endswith('.apk') or '/data/app/' in file_path

    async def _clean_app_threat(self, device_id: str, file_path: str) -> bool:
        """清理应用威胁"""
        try:
            # 提取包名
            package_name = self._get_package_name(file_path)
            if not package_name:
                return False

            # 卸载应用
            result = subprocess.run(
                [self.platform_tools.adb_path, '-s', device_id, 'uninstall', package_name],
                capture_output=True,
                text=True
            )
            
            return result.returncode == 0
        except Exception as e:
            logger.error(f"清理应用威胁时出错: {str(e)}")
            return False

    async def _clean_file_threat(self, device_id: str, file_path: str) -> bool:
        """清理文件威胁"""
        try:
            # 首先尝试直接删除
            result = subprocess.run(
                [self.platform_tools.adb_path, '-s', device_id, 'shell', f'rm -f "{file_path}"'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return True

            # 如果普通删除失败，尝试使用root权限删除
            root_result = subprocess.run(
                [self.platform_tools.adb_path, '-s', device_id, 'shell', f'su -c "rm -f \\"{file_path}\\""'],
                capture_output=True,
                text=True
            )
            
            return root_result.returncode == 0
        except Exception as e:
            logger.error(f"清理文件威胁时出错: {str(e)}")
            return False

    async def _quarantine_threat(self, device_id: str, file_path: str) -> bool:
        """将威胁隔离"""
        try:
            # 创建隔离文件的目标路径
            quarantine_path = os.path.join(
                self.quarantine_dir,
                f"{device_id}_{os.path.basename(file_path)}.quarantine"
            )

            # 先将文件拉取到隔离区
            pull_result = subprocess.run(
                [self.platform_tools.adb_path, '-s', device_id, 'pull', file_path, quarantine_path],
                capture_output=True,
                text=True
            )

            if pull_result.returncode == 0:
                # 删除原文件
                delete_result = await self._clean_file_threat(device_id, file_path)
                if delete_result:
                    return True
                else:
                    # 如果删除失败，也保留隔离的副本
                    logger.warning(f"文件已隔离但原文件删除失败: {file_path}")
                    return True
            
            return False
        except Exception as e:
            logger.error(f"隔离威胁时出错: {str(e)}")
            return False

    def _get_package_name(self, file_path: str) -> str:
        """从APK文件路径获取包名"""
        try:
            # 如果是已安装的应用
            if '/data/app/' in file_path:
                return file_path.split('/')[-1].split('-')[0]
            
            # 如果是APK文件，使用aapt获取包名
            aapt_path = os.path.join(os.path.dirname(self.platform_tools.adb_path), 'aapt.exe')
            if os.path.exists(aapt_path):
                result = subprocess.run(
                    [aapt_path, 'd', 'badging', file_path],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if line.startswith('package:'):
                            return line.split("name='")[1].split("'")[0]
            
            return ""
        except Exception as e:
            logger.error(f"获取包名时出错: {str(e)}")
            return ""

    async def restore_from_quarantine(self, device_id: str, quarantine_file: str) -> bool:
        """从隔离区恢复文件（谨慎使用）"""
        try:
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_file)
            if not os.path.exists(quarantine_path):
                return False

            # 获取原始文件名
            original_name = quarantine_file.replace(f"{device_id}_", "").replace(".quarantine", "")
            
            # 推送文件回设备
            result = subprocess.run(
                [self.platform_tools.adb_path, '-s', device_id, 'push', quarantine_path, f"/sdcard/{original_name}"],
                capture_output=True,
                text=True
            )
            
            return result.returncode == 0
        except Exception as e:
            logger.error(f"从隔离区恢复文件时出错: {str(e)}")
            return False

    def get_quarantine_list(self) -> List[Dict]:
        """获取隔离区文件列表"""
        try:
            quarantine_files = []
            for file in os.listdir(self.quarantine_dir):
                if file.endswith('.quarantine'):
                    file_path = os.path.join(self.quarantine_dir, file)
                    quarantine_files.append({
                        'filename': file,
                        'size': os.path.getsize(file_path),
                        'quarantine_time': os.path.getctime(file_path)
                    })
            return quarantine_files
        except Exception as e:
            logger.error(f"获取隔离区列表时出错: {str(e)}")
            return [] 