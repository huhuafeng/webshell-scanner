#!/bin/bash
# ============================================
# 木马扫描器 - 配置文件
# ============================================

# ---------- 扫描路径 ----------
SCAN_DIRS=(
    "/var/www"
    "/home"
    "/tmp"
    "/dev/shm"
    "/var/tmp"
    "/opt"
    "/usr/local"
    "/etc"
)

# 用户可手动添加额外路径
EXTRA_SCAN_DIRS=()

# ---------- 文件扩展名（扫描目标） ----------
SCAN_EXTENSIONS=("php" "php5" "phtml" "php7" "php8" "jsp" "jspx" "asp" "aspx" "asa" "cer" "cgi" "pl" "py" "sh")

# ---------- 白名单（跳过目录） ----------
SKIP_DIRS=(
    "/proc"
    "/sys"
    "/dev"
    "/run"
    "/var/cache"
    "/var/lib/php/sessions"
    "/var/log"
    "/var/spool"
)

# ---------- 白名单（跳过文件/路径模式） ----------
WHITELIST_PATTERNS=(
    "wp-content/themes/"
    "wp-content/plugins/woocommerce"
    "vendor/"
    "node_modules/"
    "bootstrap/"
    "jquery"
    "\.min\.js"
    "\.min\.css"
    "ckeditor"
    "tinymce"
)

# ---------- 检测阈值 ----------
ENTROPY_THRESHOLD=6.5          # 熵阈值（bits/byte，超过标记可疑）
MAX_FILE_SIZE=10485760         # 最大扫描文件大小（10MB）
MAX_LINE_LENGTH=50000          # 文件最大行数（超出跳过）
SUSPICIOUS_SIZE_MIN=10240      # 最小可疑文件大小（10KB）
SUSPICIOUS_SIZE_MAX=512000     # 最大可疑文件大小（500KB）

# ---------- 并发设置 ----------
PARALLEL_JOBS=0                # 并发任务数（0=自动检测CPU核数）

# ---------- 报告 ----------
REPORT_DIR="output"
REPORT_KEEP_DAYS=30            # 报告保留天数
HTML_REPORT=true               # 是否生成HTML报告
JSON_REPORT=true               # 是否生成JSON报告

# ---------- 隔离 ----------
QUARANTINE_DIR="quarantine"
