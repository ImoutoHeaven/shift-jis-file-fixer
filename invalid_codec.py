#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import math
import sys
import argparse
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
import jellyfish
from langdetect import detect_langs
import unicodedata
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import logging
import platform
import ctypes
from datetime import datetime
import shutil
import json

class WindowsConsole:
    """Windows控制台编码处理类"""
    def __init__(self):
        self.is_windows = platform.system() == 'Windows'
        if self.is_windows:
            self.kernel32 = ctypes.windll.kernel32
            self.handle = self.kernel32.GetStdHandle(-11)
            self.kernel32.SetConsoleMode(self.handle, 7)
            self.kernel32.SetConsoleOutputCP(65001)

    def setup(self):
        if self.is_windows:
            os.environ['PYTHONIOENCODING'] = 'utf-8'

@dataclass
class EncodingCandidate:
    """表示一个可能的编码结果"""
    decoded_text: str
    encoding: str
    confidence: float
    features: Dict[str, float]

class FileRenamer:
    """文件重命名处理类"""
    def __init__(self, logger):
        self.logger = logger
        self.is_windows = platform.system() == 'Windows'
        self.rename_history = []

    def sanitize_filename(self, filename: str) -> str:
        """净化文件名，移除不允许的字符"""
        invalid_chars = r'[<>:"/\\|?*]'
        sanitized = re.sub(invalid_chars, '_', filename)
        reserved_names = {'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4',
                         'LPT1', 'LPT2', 'LPT3', 'CLOCK$'}
        name_without_ext = os.path.splitext(sanitized)[0].upper()
        if name_without_ext in reserved_names:
            sanitized = f"_{sanitized}"
        return sanitized

    def get_unique_name(self, target_path: Path) -> Path:
        """获取唯一的文件名，避免覆盖现有文件"""
        if not target_path.exists():
            return target_path
            
        counter = 1
        stem = target_path.stem
        suffix = target_path.suffix
        parent = target_path.parent
        
        while True:
            new_name = f"{stem}_{counter}{suffix}"
            new_path = parent / new_name
            if not new_path.exists():
                return new_path
            counter += 1

    def rename_file(self, old_path: Path, new_name: str) -> bool:
        """安全地重命名文件"""
        try:
            # 净化新文件名
            sanitized_name = self.sanitize_filename(new_name)
            new_path = old_path.parent / sanitized_name
            
            # 确保新文件名唯一
            new_path = self.get_unique_name(new_path)
            
            # 记录重命名前的信息
            self.rename_history.append({
                'old_path': str(old_path),
                'new_path': str(new_path)
            })
            
            # 执行重命名
            old_path.rename(new_path)
            
            self.logger.info(f"成功重命名: {old_path} -> {new_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"重命名失败 {old_path}: {str(e)}")
            return False

    def save_rename_history(self, history_file: Path):
        """保存重命名历史记录"""
        if not self.rename_history:
            return
            
        history_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(history_file, 'w', encoding='utf-8') as f:
            f.write("文件重命名历史记录\n")
            f.write(f"执行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("-" * 80 + "\n\n")
            
            for item in self.rename_history:
                f.write(f"原始路径: {item['old_path']}\n")
                f.write(f"新路径: {item['new_path']}\n")
                f.write("-" * 80 + "\n\n")
            
        return history_file

class RenameRecovery:
    """重命名恢复处理类"""
    def __init__(self, logger):
        self.logger = logger
        self.recovery_records = []
        
    def parse_recovery_log(self, log_path: Path) -> List[Dict]:
        """解析恢复日志文件"""
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # 解析日志内容
            records = []
            current_record = {}
            
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('-' * 20):
                    if current_record and all(k in current_record for k in ['old_path', 'new_path']):
                        records.append(current_record)
                        current_record = {}
                    continue
                    
                if line.startswith('原始路径: '):
                    current_record['old_path'] = line.replace('原始路径: ', '').strip()
                elif line.startswith('新路径: '):
                    current_record['new_path'] = line.replace('新路径: ', '').strip()
            
            # 检查最后一条记录
            if current_record and all(k in current_record for k in ['old_path', 'new_path']):
                records.append(current_record)
            
            return records
            
        except Exception as e:
            self.logger.error(f"解析恢复日志失败: {str(e)}")
            return []
            
    def verify_paths(self, record: Dict) -> bool:
        """验证恢复所需的路径是否存在"""
        new_path = Path(record['new_path'])
        old_path = Path(record['old_path'])
        
        if not new_path.exists():
            self.logger.error(f"当前文件不存在: {new_path}")
            return False
            
        return True
        
    def recover_single_file(self, record: Dict) -> bool:
        """恢复单个文件的重命名"""
        try:
            new_path = Path(record['new_path'])
            old_path = Path(record['old_path'])
            
            # 验证路径
            if not self.verify_paths(record):
                return False
            
            # 如果原始路径已存在，创建临时backup
            if old_path.exists():
                temp_backup = old_path.with_suffix(old_path.suffix + '.temp')
                shutil.move(old_path, temp_backup)
            
            # 执行恢复
            shutil.move(new_path, old_path)
            
            # 记录恢复操作
            self.recovery_records.append({
                'recovered_path': str(old_path),
                'from_path': str(new_path)
            })
            
            self.logger.info(f"成功恢复文件: {new_path} -> {old_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"恢复文件失败 {new_path}: {str(e)}")
            return False
            
    def save_recovery_log(self, output_dir: Path):
        """保存恢复操作日志"""
        if not self.recovery_records:
            return
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        recovery_log = output_dir / f'recovery_log_{timestamp}.txt'
        
        with open(recovery_log, 'w', encoding='utf-8') as f:
            f.write("文件恢复操作记录\n")
            f.write(f"执行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("-" * 80 + "\n\n")
            
            for record in self.recovery_records:
                f.write(f"恢复路径: {record['recovered_path']}\n")
                f.write(f"从路径: {record['from_path']}\n")
                f.write("-" * 80 + "\n\n")
class AdvancedEncodingDetector:
    """高级编码检测类"""
    def __init__(self, scan_path: str = None, auto_rename: bool = False):
        self.scan_path = Path(scan_path) if scan_path else Path.cwd()
        self.auto_rename = auto_rename
        
        # 常见的日文文件名特征pattern
        self.jp_patterns = [
            r'第\d+章',
            r'[\u3040-\u309F]+',
            r'[\u30A0-\u30FF]+',
            r'[\u4E00-\u9FFF]+',
            r'(?:\s|_)?(?:vol|Ver?|version)[\.\d]+(?:\s|_)?',
            r'\[.*?\]',
            r'\(.*?\)',
        ]
        
        self.encoding_pairs = [
            ('shift_jis', 'gbk'),
            ('shift_jis', 'gb2312'),
            ('euc_jp', 'gbk'),
            ('cp932', 'gbk'),
            ('utf-8', 'gbk')
        ]
        
        self.setup_logging()
        self.renamer = FileRenamer(self.logger)
        
    def setup_logging(self):
        """设置日志系统"""
        self.logger = logging.getLogger(__name__)

    def calculate_text_entropy(self, text: str) -> float:
        """计算文本的信息熵"""
        freq = defaultdict(int)
        for char in text:
            freq[char] += 1
        
        length = len(text)
        entropy = 0
        
        for count in freq.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
            
        return entropy

    def get_character_ratio(self, text: str, ranges: List[Tuple[int, int]]) -> float:
        """计算特定Unicode范围内字符的比例"""
        if not text:
            return 0
            
        count = sum(1 for char in text 
                   for start, end in ranges 
                   if start <= ord(char) <= end)
        return count / len(text)

    def calculate_pattern_matches(self, text: str) -> float:
        """计算日文文件名特征pattern的匹配程度"""
        match_count = sum(bool(re.search(pattern, text)) 
                         for pattern in self.jp_patterns)
        return match_count / len(self.jp_patterns)

    def detect_encoding_candidate(self, filename: str) -> List[EncodingCandidate]:
        """检测文件名可能的编码情况"""
        candidates = []
        
        for source_enc, target_enc in self.encoding_pairs:
            try:
                # 尝试用目标编码转换为bytes，再用源编码解码
                bytes_data = filename.encode(target_enc)
                decoded = bytes_data.decode(source_enc)
                
                # 过滤掉解码结果完全相同的情况
                if decoded == filename:
                    continue
                
                # 计算特征
                features = {
                    'entropy': self.calculate_text_entropy(decoded),
                    'jp_char_ratio': self.get_character_ratio(
                        decoded, 
                        [(0x3040, 0x309F),  # 平假名
                         (0x30A0, 0x30FF),  # 片假名
                         (0x4E00, 0x9FFF)]  # 汉字
                    ),
                    'pattern_match': self.calculate_pattern_matches(decoded),
                    'similarity': jellyfish.jaro_winkler_similarity(filename, decoded)
                }
                
                # 计算综合置信度
                confidence = (
                    features['jp_char_ratio'] * 0.4 +
                    features['pattern_match'] * 0.3 +
                    (1 - features['similarity']) * 0.2 +
                    min(features['entropy'] / 4, 1.0) * 0.1
                )
                
                candidates.append(EncodingCandidate(
                    decoded_text=decoded,
                    encoding=f"{source_enc}->{target_enc}",
                    confidence=confidence,
                    features=features
                ))
                
            except (UnicodeEncodeError, UnicodeDecodeError):
                continue
                
        return sorted(candidates, key=lambda x: x.confidence, reverse=True)

    def analyze_file(self, filepath: Path) -> Dict:
        """分析单个文件"""
        try:
            filename = filepath.name
            candidates = self.detect_encoding_candidate(filename)
            
            if not candidates:
                return None
                
            best_candidate = candidates[0]
            
            # 仅当置信度超过阈值时才返回结果
            if best_candidate.confidence > 0.5:
                return {
                    'path': str(filepath),
                    'original_name': filename,
                    'detected_encoding': best_candidate.encoding,
                    'suggested_name': best_candidate.decoded_text,
                    'confidence': best_candidate.confidence,
                    'features': best_candidate.features
                }
        except Exception as e:
            self.logger.error(f"处理文件 {filepath}时出错: {str(e)}")
        return None

    def scan_directory(self, min_confidence: float = 0.5) -> List[Dict]:
        """扫描目录查找并可选择性地修复编码问题的文件"""
        self.logger.info(f"开始扫描目录: {self.scan_path}")
        results = []
        renamed_count = 0
        
        try:
            with ThreadPoolExecutor() as executor:
                futures = []
                
                for filepath in self.scan_path.rglob('*'):
                    if filepath.is_file():
                        futures.append(executor.submit(self.analyze_file, filepath))
                
                for future in futures:
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                            
                            # 如果启用了自动重命名，尝试重命名文件
                            if self.auto_rename and result['confidence'] >= min_confidence:
                                old_path = Path(result['path'])
                                new_name = result['suggested_name']
                                
                                if self.renamer.rename_file(old_path, new_name):
                                    renamed_count += 1
                                
                    except Exception as e:
                        self.logger.error(f"处理结果时出错: {str(e)}")
            
            self.logger.info(f"扫描完成，找到 {len(results)} 个可能存在编码问题的文件")
            if self.auto_rename:
                self.logger.info(f"成功重命名 {renamed_count} 个文件")
            
        except Exception as e:
            self.logger.error(f"扫描过程中出错: {str(e)}")
            
        return results

class EncodingDetectorCLI:
    """命令行接口处理类"""
    def __init__(self):
        self.parser = self.create_parser()
        
    def create_parser(self):
        """创建命令行参数解析器"""
        parser = argparse.ArgumentParser(description='文件名编码问题检测工具')
        parser.add_argument('path', nargs='?', default=None,
                          help='要扫描的目录路径，默认为当前目录')
        parser.add_argument('-c', '--confidence', type=float, default=0.5,
                          help='最小置信度阈值 (0-1), 默认为0.5')
        parser.add_argument('--auto-rename', action='store_true',
                          help='自动重命名检测到的问题文件（默认关闭）')
        parser.add_argument('--recovery',
                          help='指定重命名日志文件路径（用于恢复操作）')
        parser.add_argument('--reverse', action='store_true',
                          help='根据重命名日志撤销重命名操作（需要指定--recovery）')
        return parser
        
    def validate_args(self, args):
        """验证并补充命令行参数"""
        if args.reverse and not args.recovery:
            self.parser.error("使用--reverse必须同时指定--recovery参数")
            
        if args.recovery and args.reverse and not os.path.exists(args.recovery):
            self.parser.error(f"重命名日志文件不存在: {args.recovery}")
            
        if args.confidence < 0 or args.confidence > 1:
            self.parser.error("置信度阈值必须在0到1之间")
            
        return True

def create_timestamped_dirs() -> tuple[Path, Path]:
    """创建带时间戳的输出目录"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # 创建带时间戳的输出目录
    scan_output_dir = Path(f'encoding_scan_results_{timestamp}')
    scan_output_dir.mkdir(exist_ok=True)
    
    # 创建带时间戳的重命名日志目录
    rename_output_dir = Path(f'rename_logs_{timestamp}')
    rename_output_dir.mkdir(exist_ok=True)
    
    return scan_output_dir, rename_output_dir

def main():
    """主函数"""
    # 设置Windows控制台
    console = WindowsConsole()
    console.setup()
    
    # 解析命令行参数
    cli = EncodingDetectorCLI()
    args = cli.parser.parse_args()
    
    # 创建带时间戳的输出目录
    scan_output_dir, rename_output_dir = create_timestamped_dirs()
    
    # 如果启用了auto-rename但没有指定recovery路径，则自动生成
    if args.auto_rename and not args.recovery:
        args.recovery = str(rename_output_dir / 'rename_history.txt')
    
    if not cli.validate_args(args):
        return
    
    # 配置日志
    log_file = scan_output_dir / 'operation.log'
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger(__name__)
    
    try:
        if args.reverse:
            logger.info("开始执行恢复操作...")
            recovery = RenameRecovery(logger)
            records = recovery.parse_recovery_log(Path(args.recovery))
            
            if not records:
                logger.error("未找到有效的恢复记录")
                return
                
            success_count = 0
            for record in records:
                if recovery.recover_single_file(record):
                    success_count += 1
                    
            logger.info(f"恢复操作完成: 成功恢复 {success_count}/{len(records)} 个文件")
            
        else:
            detector = AdvancedEncodingDetector(args.path, args.auto_rename)
            results = detector.scan_directory(min_confidence=args.confidence)
            
            if not results:
                print("未发现疑似编码问题的文件名")
                return
            
            # 生成扫描报告
            report_file = scan_output_dir / 'scan_report.txt'
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"文件名编码问题扫描报告\n")
                f.write(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"扫描目录: {args.path or os.getcwd()}\n")
                f.write("-" * 80 + "\n\n")
                
                for item in sorted(results, key=lambda x: x['confidence'], reverse=True):
                    f.write(f"文件: {item['original_name']}\n")
                    f.write(f"建议改为: {item['suggested_name']}\n")
                    f.write(f"置信度: {item['confidence']:.2%}\n")
                    f.write("-" * 80 + "\n")
                
            print(f"\n发现 {len(results)} 个可能存在编码问题的文件:")
            print(f"详细报告已保存至: {report_file}")
            
            if args.auto_rename:
                print(f"重命名日志保存至: {args.recovery}")
            
            print("-" * 80)
            
            for item in sorted(results, key=lambda x: x['confidence'], reverse=True):
                print(f"文件: {item['original_name']}")
                print(f"建议改为: {item['suggested_name']}")
                print(f"置信度: {item['confidence']:.2%}")
                print("-" * 80)
            
            # 如果启用了自动重命名，保存重命名历史
            if args.auto_rename:
                detector.renamer.save_rename_history(Path(args.recovery))
                
    except Exception as e:
        logger.error(f"执行过程中出错: {str(e)}")
        raise

if __name__ == "__main__":
    main()
