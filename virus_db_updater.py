import os
import json
import hashlib
import aiohttp
import asyncio
from datetime import datetime
from typing import Dict, List
from ..utils.logger import logger

class VirusDBUpdater:
    def __init__(self):
        self.db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'virus_db')
        self.signatures_file = os.path.join(self.db_path, 'signatures.json')
        self.md5_blacklist_file = os.path.join(self.db_path, 'md5_blacklist.json')
        self.info_file = os.path.join(self.db_path, 'db_info.json')
        self.update_url = "https://example.com/virus-db/latest"  # 替换为实际的更新服务器
        self._init_db()

    def _init_db(self):
        """初始化病毒库文件"""
        os.makedirs(self.db_path, exist_ok=True)
        
        # 初始化签名文件
        if not os.path.exists(self.signatures_file):
            with open(self.signatures_file, 'w') as f:
                json.dump({"signatures": []}, f)
        
        # 初始化MD5黑名单
        if not os.path.exists(self.md5_blacklist_file):
            with open(self.md5_blacklist_file, 'w') as f:
                json.dump({}, f)
        
        # 初始化数据库信息
        if not os.path.exists(self.info_file):
            info = {
                "version": "1.0.0",
                "last_update": datetime.now().isoformat(),
                "total_signatures": 0,
                "auto_update": True
            }
            with open(self.info_file, 'w') as f:
                json.dump(info, f)

    async def update_database(self) -> Dict:
        """更新病毒特征库"""
        try:
            # 获取当前版本信息
            current_info = self.get_database_info()
            old_version = current_info['version']

            # 检查更新
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.update_url}?current_version={old_version}"
                ) as response:
                    if response.status == 200:
                        update_data = await response.json()
                        
                        if update_data.get('has_update'):
                            # 更新签名
                            signatures = update_data.get('signatures', [])
                            await self._update_signatures(signatures)
                            
                            # 更新MD5黑名单
                            blacklist = update_data.get('md5_blacklist', {})
                            await self._update_blacklist(blacklist)
                            
                            # 更新数据库信息
                            new_version = update_data.get('version')
                            await self._update_db_info(new_version)
                            
                            logger.info(f"病毒库已更新到版本 {new_version}")
                            return {
                                "status": "success",
                                "old_version": old_version,
                                "new_version": new_version,
                                "update_time": datetime.now().isoformat(),
                                "updated_signatures": len(signatures)
                            }
                        else:
                            return {
                                "status": "success",
                                "message": "已是最新版本",
                                "version": old_version
                            }
                    else:
                        raise Exception(f"更新服务器返回错误: {response.status}")
                        
        except Exception as e:
            logger.error(f"更新病毒库时出错: {str(e)}")
            return {
                "status": "error",
                "error": str(e)
            }

    async def _update_signatures(self, signatures: List[Dict]):
        """更新病毒签名"""
        try:
            current_signatures = self._load_json(self.signatures_file)
            current_signatures['signatures'].extend(signatures)
            
            # 去重
            unique_signatures = {
                json.dumps(sig, sort_keys=True): sig 
                for sig in current_signatures['signatures']
            }
            current_signatures['signatures'] = list(unique_signatures.values())
            
            # 保存更新
            with open(self.signatures_file, 'w') as f:
                json.dump(current_signatures, f, indent=2)
                
        except Exception as e:
            logger.error(f"更新病毒签名时出错: {str(e)}")
            raise

    async def _update_blacklist(self, blacklist: Dict):
        """更新MD5黑名单"""
        try:
            current_blacklist = self._load_json(self.md5_blacklist_file)
            current_blacklist.update(blacklist)
            
            with open(self.md5_blacklist_file, 'w') as f:
                json.dump(current_blacklist, f, indent=2)
                
        except Exception as e:
            logger.error(f"更新MD5黑名单时出错: {str(e)}")
            raise

    async def _update_db_info(self, new_version: str):
        """更新数据库信息"""
        try:
            info = self._load_json(self.info_file)
            info.update({
                "version": new_version,
                "last_update": datetime.now().isoformat(),
                "total_signatures": len(self._load_json(self.signatures_file)['signatures'])
            })
            
            with open(self.info_file, 'w') as f:
                json.dump(info, f, indent=2)
                
        except Exception as e:
            logger.error(f"更新数据库信息时出错: {str(e)}")
            raise

    def get_database_info(self) -> Dict:
        """获取病毒特征库信息"""
        try:
            info = self._load_json(self.info_file)
            info['database_size'] = self._get_database_size()
            return info
        except Exception as e:
            logger.error(f"获取数据库信息时出错: {str(e)}")
            return {
                "version": "unknown",
                "last_update": "unknown",
                "total_signatures": 0,
                "database_size": 0,
                "auto_update": True
            }

    def _get_database_size(self) -> int:
        """获取数据库大小（字节）"""
        total_size = 0
        for file in [self.signatures_file, self.md5_blacklist_file, self.info_file]:
            if os.path.exists(file):
                total_size += os.path.getsize(file)
        return total_size

    def _load_json(self, file_path: str) -> Dict:
        """加载JSON文件"""
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"加载JSON文件时出错 {file_path}: {str(e)}")
            return {}

    def get_md5_blacklist(self) -> Dict:
        """获取MD5黑名单"""
        return self._load_json(self.md5_blacklist_file)

    def add_to_md5_blacklist(self, md5: str, info: Dict):
        """添加MD5到黑名单"""
        try:
            blacklist = self._load_json(self.md5_blacklist_file)
            blacklist[md5] = {
                **info,
                "add_time": datetime.now().isoformat()
            }
            
            with open(self.md5_blacklist_file, 'w') as f:
                json.dump(blacklist, f, indent=2)
                
        except Exception as e:
            logger.error(f"添加MD5到黑名单时出错: {str(e)}")
            raise 