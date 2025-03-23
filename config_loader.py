import os
from typing import Optional
from .logger import logger

class ConfigLoader:
    @staticmethod
    def load_api_key(key_file: str = 'key.txt') -> Optional[str]:
        """从文件加载API密钥"""
        try:
            if os.path.exists(key_file):
                with open(key_file, 'r') as f:
                    return f.read().strip()
            else:
                logger.warning(f"API密钥文件 {key_file} 不存在")
                return None
        except Exception as e:
            logger.error(f"读取API密钥失败: {e}")
            return None

    @staticmethod
    def get_virus_total_api_key() -> str:
        """获取VirusTotal API密钥"""
        # 优先从环境变量获取
        api_key = os.getenv('VIRUS_TOTAL_API_KEY')
        if not api_key:
            # 如果环境变量中没有，则从文件读取
            api_key = ConfigLoader.load_api_key()
        return api_key or '' 