# File Encoding Detective

一个强大的文件名编码问题检测和修复工具，专门用于解决日文文件名在不同编码系统之间转换时出现的乱码问题。

## 功能特点

- 自动检测文件名的编码问题
- 智能识别日文文件名特征
- 支持多种编码转换方案（Shift-JIS, GBK, EUC-JP等）
- 提供自动重命名功能
- 支持重命名操作的撤销和恢复
- 生成详细的扫描报告和操作日志
- 多线程处理以提高性能
- 支持Windows控制台编码自动配置

## 系统要求

- Python 3.7+
- 操作系统：Windows/Linux/MacOS

## 安装

1. 克隆仓库或下载源代码
2. 安装依赖包：

```bash
pip install jellyfish langdetect
```

## 使用方法

### 基本扫描

扫描当前目录下的文件名编码问题：

```bash
python invalid_codec.py
```

扫描指定目录：

```bash
python invalid_codec.py /path/to/directory
```

### 高级选项

设置最小置信度阈值（0-1之间）：

```bash
python invalid_codec.py --confidence 0.7
```

启用自动重命名功能：

```bash
python invalid_codec.py --auto-rename
```

从日志文件恢复重命名操作：

```bash
python invalid_codec.py --recovery rename_logs_20241125_120000/rename_history.txt --reverse
```

## 输出说明

工具会在执行目录下创建两个时间戳文件夹：

1. `encoding_scan_results_YYYYMMDD_HHMMSS/`
   - `scan_report.txt`: 详细的扫描报告
   - `operation.log`: 操作日志文件

2. `rename_logs_YYYYMMDD_HHMMSS/`（仅在启用自动重命名时创建）
   - `rename_history.txt`: 重命名操作记录

### 扫描报告示例

```
文件名编码问题扫描报告
扫描时间: 2024-11-25 12:00:00
扫描目录: /path/to/scan
----------------------------------------

文件: ‚±‚Ì‚¢‚ë‚Í‚Å‚·‚©.txt
建议改为: このいろはです.txt
置信度: 95.2%
----------------------------------------
```

## 工作原理

该工具使用以下方法来检测和修复文件名编码问题：

1. **编码检测**：
   - 尝试多种编码组合（如Shift-JIS->GBK, EUC-JP->GBK等）
   - 计算文本特征（信息熵、日文字符比例等）
   - 使用模式匹配识别日文文件名特征

2. **置信度计算**：
   - 日文字符比例：40%权重
   - 模式匹配得分：30%权重
   - 字符串相似度：20%权重
   - 信息熵：10%权重

3. **安全措施**：
   - 文件名冲突处理
   - 重命名操作日志
   - 支持撤销恢复
   - Windows保留名称处理

## 注意事项

1. 建议在执行自动重命名前先查看扫描报告
2. 重要文件建议先备份后操作
3. 保存重命名日志以便需要时恢复
4. 高置信度阈值可减少误判，但可能遗漏部分问题文件

## 错误处理

工具会生成详细的操作日志，记录所有错误和异常情况。如遇问题，请查看：
- `operation.log`文件了解详细错误信息
- 确保对目标文件和目录有足够的访问权限
- 检查系统编码设置是否正确
