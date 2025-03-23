import logging
import os
from logging.handlers import RotatingFileHandler

def setup_logger(name: str, log_file: str = 'app.log', level=logging.INFO):
    """配置日志记录器"""
    # 使用绝对路径
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'logs')
    log_file = os.path.join(log_dir, log_file)
    
    # 创建日志目录
    os.makedirs(log_dir, exist_ok=True)
    
    # 创建格式化器
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 创建文件处理器
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    
    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # 创建日志记录器
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# 创建全局日志记录器
logger = setup_logger('virus_scanner') 