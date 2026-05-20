#!/bin/bash
# ============================================
# 木马扫描器 - 配置文件
# 所有用户可调参数在此集中管理，修改后重启扫描即可生效。
# ============================================

# ---------- 扫描路径 ----------
# SCAN_DIRS: --full 模式下遍历的顶级目录列表
# 扫描器会递归遍历每个目录（最深 10 层），只处理 SCAN_EXTENSIONS 定义的文件
SCAN_DIRS=(
    "/var/www"      # Web 站点根目录（PHP/HTML 常见位置）
    "/home"         # 用户主目录（共享主机环境常见）
    "/tmp"          # 临时目录（木马常驻点）
    "/dev/shm"      # 共享内存（内存马常见驻留点）
    "/var/tmp"      # 持久临时目录
    "/opt"          # 第三方软件安装目录
    "/usr/local"    # 本地软件/脚本目录
    "/etc"          # 系统配置目录（常被写入恶意配置）
)

# EXTRA_SCAN_DIRS: 用户可手动添加的额外扫描路径（当前版本未自动使用，留作扩展）
EXTRA_SCAN_DIRS=()

# ---------- 文件扩展名（扫描目标） ----------
# SCAN_EXTENSIONS: 只扫描以下扩展名的文件，降低非脚本文件的误报
SCAN_EXTENSIONS=("php" "php5" "phtml" "php7" "php8" "jsp" "jspx" "asp" "aspx" "asa" "cer" "cgi" "pl" "py" "sh")

# ---------- 白名单（跳过目录） ----------
# SKIP_DIRS: find 命令中通过 -prune 跳过的目录路径，减少无用 I/O
# 这些目录通常不包含 Web 脚本或为系统虚拟文件系统
SKIP_DIRS=(
    "/proc"                     # 进程虚拟文件系统
    "/sys"                      # 内核虚拟文件系统
    "/dev"                      # 设备文件
    "/run"                      # 运行时文件
    "/var/cache"                # 缓存目录
    "/var/lib/php/sessions"     # PHP 会话文件（海量小文件）
    "/var/log"                  # 日志目录
    "/var/spool"                # 打印/邮件队列
)

# ---------- 白名单（跳过文件/路径模式） ----------
# WHITELIST_PATTERNS: grep -E 模式匹配，匹配到的文件从扫描列表中排除
# 用于跳过第三方库/框架/主题等大量文件但基本无害的目录
WHITELIST_PATTERNS=(
    "wp-content/themes/"            # WordPress 主题（知名框架文件）
    "wp-content/plugins/woocommerce" # WooCommerce 插件
    "vendor/"                       # Composer 依赖包
    "node_modules/"                 # npm 依赖包
    "bootstrap/"                    # Bootstrap 前端框架
    "jquery"                        # jQuery 库
    "\.min\.js"                     # 压缩版 JS（无恶意代码空间）
    "\.min\.css"                    # 压缩版 CSS
    "ckeditor"                      # CKEditor 富文本编辑器
    "tinymce"                       # TinyMCE 富文本编辑器
)

# ---------- 检测阈值 ----------
# ENTROPY_THRESHOLD: 香农熵阈值（单位 bits/byte），文件前 2048 字节熵值超过此值标记为可疑
# 正常 PHP 文本熵值通常 < 6.0；加密/压缩/编码混淆的载荷通常 > 6.5
ENTROPY_THRESHOLD=6.5
# MAX_FILE_SIZE: 超过此大小的文件不扫描内容（避免大文件 OOM），单位字节
MAX_FILE_SIZE=10485760             # 10MB
# MAX_LINE_LENGTH: 超过此行数的文件不扫描（避免超长文件耗时），单位行
MAX_LINE_LENGTH=50000              # 50000 行
# SUSPICIOUS_SIZE_MIN: 小于此大小的文件不触发熵检测（太小的文件熵不可靠），单位字节
SUSPICIOUS_SIZE_MIN=10240          # 10KB
# SUSPICIOUS_SIZE_MAX: 大于此大小的文件不触发熵检测（大文件熵趋近正常值），单位字节
SUSPICIOUS_SIZE_MAX=512000         # 500KB

# ---------- 并发设置 ----------
# PARALLEL_JOBS: 并发扫描子进程数。0 = 自动检测 CPU 核数后使用
PARALLEL_JOBS=0

# ---------- 报告 ----------
# REPORT_DIR: 扫描结果输出目录（相对于脚本根目录）
REPORT_DIR="output"
# REPORT_KEEP_DAYS: 历史报告保留天数，超期自动清理
REPORT_KEEP_DAYS=30
# HTML_REPORT: 是否额外生成 HTML 可视化报告
HTML_REPORT=true
# JSON_REPORT: 是否生成 JSON 格式报告（默认始终生成）
JSON_REPORT=true

# ---------- 隔离 ----------
# QUARANTINE_DIR: 隔离目录名（位于 REPORT_DIR 之下），存放被隔离的可疑文件副本
QUARANTINE_DIR="quarantine"
