# 🛡️ Muma Scan - 网站木马一键扫描器

全盘扫描服务器文件系统，检测网站挂马、WebShell、后门程序的 Bash 脚本工具。

## 功能特性

- **多维检测**：特征正则匹配 + 文件熵分析 + 权限异常检测 + 可疑文件名检测 + 目录越位检测
- **海量规则**：92 条 PHP 木马规则 + 34 条 JSP 后门规则 + 46 条可疑文件名模式
- **支持类型**：PHP 一句话木马、编码混淆、系统命令执行后门、冰蝎/蚁剑/菜刀等已知 Webshell
- **三种报告**：终端彩色输出 + HTML 可视化报告 + JSON 结构化数据
- **并发扫描**：自动利用全部 CPU 核并行检测
- **隔离机制**：可疑文件自动备份至隔离区，可恢复
- **性能优化**：预过滤 + 级别过滤 + 增量扫描三级加速

## 环境要求

- Bash 4+
- Python 3
- `file`、`find`、`xargs`、`stat`、`grep`（GNU grep 需支持 `-P` 选项）
- `bc`（浮点运算，熵检测用）

## 快速开始

```bash
# 下载
git clone https://github.com/huhuafeng/webshell-scanner.git
cd webshell-scanner

# 快速扫描 Web 目录
sudo ./scan.sh --quick

# 全盘扫描
sudo ./scan.sh --full
```

## 命令选项

| 选项 | 说明 |
|---|---|
| `-f, --full` | 全盘扫描（扫描 `config.sh` 中 `SCAN_DIRS` 定义的所有目录） |
| `-q, --quick` | 快速扫描（仅 `/var/www` 和 `/home`，仅 CRITICAL 级别规则） |
| `-p, --path DIR` | 指定扫描路径（可重复使用，如 `-p /www -p /blog`） |
| `-n, --recent DAYS` | 增量扫描，仅扫描最近 N 天修改的文件 |
| `-L, --level LVL` | 规则级别：`CRITICAL` / `HIGH` / `ALL`（默认 ALL） |
| `-r, --report` | 查看上次扫描结果 |
| `-l, --list` | 列出隔离区文件 |
| `-c, --cleanup` | 清理隔离区 |
| `-h, --help` | 显示帮助 |

## 使用示例

```bash
# 全盘扫描
sudo ./scan.sh --full

# 快速扫描 Web 目录（仅 CRITICAL 规则）
sudo ./scan.sh --quick

# 扫描指定目录
sudo ./scan.sh --path /var/www/html

# 多目录扫描
sudo ./scan.sh --path /www -p /blog -p /forum

# 增量扫描：仅最近 7 天修改的文件
sudo ./scan.sh --full -n 7

# 指定规则级别扫描（适合快速排查）
sudo ./scan.sh --full -L CRITICAL

# 增量 + 指定级别（最适合日常巡检）
sudo ./scan.sh --full -n 7 -L CRITICAL

# 查看上次扫描报告
./scan.sh --report
```

## 报告示例

```bash
# 终端输出（彩色分级）
./scan.sh --report

# HTML 报告（浏览器打开）
open output/scan_${TIMESTAMP}.html

# JSON 报告
cat output/scan_${TIMESTAMP}.json
```

## 目录结构

```
webshell-scanner/
├── scan.sh              # 主入口脚本
├── config.sh            # 配置文件（路径、阈值、白名单）
├── README.md
├── lib/
│   ├── scanner.sh       # 文件遍历引擎（find + 并发）
│   ├── detector.sh      # 检测引擎（正则匹配 + 熵分析 + 权限检测）
│   ├── reporter.sh      # 报告生成器（终端/HTML/JSON）
│   └── quarantine.sh    # 隔离模块
├── rules/
│   ├── php_sigs.txt     # PHP 木马特征规则（92条）
│   ├── jsp_sigs.txt     # JSP 后门特征规则（34条）
│   ├── hidden_files.txt # 可疑文件名模式（46条）
│   └── pre_filter.txt   # 预过滤关键词（加速用）
└── output/              # 扫描报告输出
```

## 检测级别说明

```
CRITICAL (严重) — 确定为后门代码
  ├── eval(base64_decode)  经典一句话木马
  ├── system($_GET)        系统命令执行
  ├── preg_replace /e      /e 修饰符代码执行
  ├── gzinflate(substr())  内嵌 gzip 压缩载荷
  └── 已知 Webshell 指纹    冰蝎/蚁剑/菜刀/r57 等

HIGH (高危) — 高度可疑
  ├── 文件权限 0777        全局可写
  ├── 超长 base64 编码     混淆载荷
  ├── 高熵值 (>6.5)       编码/加密内容
  └── 脚本文件在 uploads 等非预期目录

MEDIUM (中危) — 需人工确认
  ├── phpinfo()           信息泄露
  ├── mysql_query($_POST) 动态 SQL 查询
  ├── fopen('w')          写入文件操作
  └── 已知木马文件名
```

## 自定义配置

编辑 `config.sh`：

- **扫描路径**：修改 `SCAN_DIRS` 添加/删除扫描目录
- **白名单**：`WHITELIST_PATTERNS` 中添加忽略路径模式
- **检测阈值**：调整 `ENTROPY_THRESHOLD`（默认 6.5）控制熵检测灵敏度
- **并发数**：`PARALLEL_JOBS` 控制扫描进程数（0=自动）

## License

MIT
