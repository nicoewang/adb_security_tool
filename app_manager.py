import subprocess
from typing import List, Dict
import json
import os

class AppManager:
    def __init__(self):
        pass

    def get_installed_apps(self, device_id: str) -> List[Dict]:
        """获取设备上已安装的应用列表"""
        try:
            # 获取所有已安装的包
            result = subprocess.run(['adb', '-s', device_id, 'shell', 'pm', 'list', 'packages', '-f', '-3'],
                                capture_output=True, text=True)
            
            apps = []
            for line in result.stdout.split('\n'):
                if '=' in line:
                    path, package = line.strip().split('=')
                    path = path.replace('package:', '')
                    
                    # 获取应用信息
                    app_info = self._get_app_info(device_id, package, path)
                    if app_info:
                        apps.append(app_info)
            
            return apps
        except Exception as e:
            print(f"获取已安装应用列表时出错: {str(e)}")
            return []

    def _get_app_info(self, device_id: str, package: str, path: str) -> Dict:
        """获取应用详细信息"""
        try:
            # 获取应用名称
            label_cmd = f"aapt dump badging {path} | grep 'application-label:'"
            result = subprocess.run(['adb', '-s', device_id, 'shell', label_cmd],
                                capture_output=True, text=True)
            label = result.stdout.split("'")[1] if "'" in result.stdout else package

            # 获取版本信息
            version_cmd = f"dumpsys package {package} | grep versionName"
            result = subprocess.run(['adb', '-s', device_id, 'shell', version_cmd],
                                capture_output=True, text=True)
            version = result.stdout.strip().split('=')[1] if '=' in result.stdout else ''

            # 获取应用大小
            size_cmd = f"du -k {path}"
            result = subprocess.run(['adb', '-s', device_id, 'shell', size_cmd],
                                capture_output=True, text=True)
            size = int(result.stdout.split()[0]) * 1024 if result.stdout.split() else 0

            # 获取权限列表
            perm_cmd = f"dumpsys package {package} | grep 'granted=true'"
            result = subprocess.run(['adb', '-s', device_id, 'shell', perm_cmd],
                                capture_output=True, text=True)
            permissions = [p.strip() for p in result.stdout.split('\n') if p.strip()]

            return {
                'package': package,
                'label': label,
                'version': version,
                'size': size,
                'path': path,
                'permissions': permissions
            }
        except Exception as e:
            print(f"获取应用 {package} 信息时出错: {str(e)}")
            return None

    def uninstall_app(self, device_id: str, package_name: str) -> Dict:
        """卸载应用"""
        try:
            result = subprocess.run(['adb', '-s', device_id, 'uninstall', package_name],
                                capture_output=True, text=True)
            
            if 'Success' in result.stdout:
                return {
                    'status': 'success',
                    'message': f'成功卸载应用 {package_name}'
                }
            else:
                return {
                    'status': 'error',
                    'message': f'卸载应用 {package_name} 失败: {result.stderr}'
                }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'卸载应用时出错: {str(e)}'
            }

    def install_app(self, device_id: str, apk_path: str) -> Dict:
        """安装应用"""
        try:
            result = subprocess.run(['adb', '-s', device_id, 'install', '-r', apk_path],
                                capture_output=True, text=True)
            
            if 'Success' in result.stdout:
                return {
                    'status': 'success',
                    'message': '应用安装成功'
                }
            else:
                return {
                    'status': 'error',
                    'message': f'应用安装失败: {result.stderr}'
                }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'安装应用时出错: {str(e)}'
            } 