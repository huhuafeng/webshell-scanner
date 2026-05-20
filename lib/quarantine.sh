#!/bin/bash
# ============================================
# 隔离模块 - 备份可疑文件
# 功能：当扫描发现可疑文件时，将其复制到隔离区（保留原始路径结构
#       以方便溯源），并记录隔离日志。支持查看隔离列表、还原和统计。
# 隔离区位于 output/quarantine/ 目录下。
# ============================================

# ---------- 初始化隔离区 ----------
# quarantine_init: 在 REPORT_DIR 下创建隔离目录并返回其绝对路径。
# 参数：无
# 返回：隔离区目录的完整路径
function quarantine_init() {
    local quarantine_dir="${REPORT_DIR}/${QUARANTINE_DIR}"
    mkdir -p "$quarantine_dir" 2>/dev/null
    echo "$quarantine_dir"
}

# ---------- 隔离单文件 ----------
# quarantine_file: 将可疑文件复制到隔离区。
# 隔离文件命名格式: 时间戳_原始路径（路径分隔符 / 替换为 _）
# 同时追加一条日志到 quarantine.log。
# 参数:
#   $1 - file: 原始文件绝对路径
#   $2 - quarantine_dir: 隔离区目录路径
#   $3 - reason: 隔离原因描述文本
# 返回:
#   成功时输出隔离文件的目标路径；失败时返回 1
function quarantine_file() {
    local file="$1"
    local quarantine_dir="$2"
    local reason="$3"
    
    [ ! -f "$file" ] && return 1  # 文件已不存在则跳过
    
    # 将路径中的 / 替换为 _ 生成安全文件名，去掉开头的 _（原根目录 /）
    local safe_name=$(echo "$file" | sed 's|/|_|g' | sed 's|^_||')
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local dest="${quarantine_dir}/${timestamp}_${safe_name}"
    
    # cp -a 保持原始权限、属主、时间戳
    cp -a "$file" "$dest" 2>/dev/null || return 1
    
    # 追加隔离日志，便于后续审计和恢复
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ISOLATED: $file -> $dest (reason: $reason)" >> "${quarantine_dir}/quarantine.log"
    
    echo "$dest"  # 输出目标路径供调用方使用
}

# ---------- 列出隔离文件 ----------
# quarantine_list: 读取 quarantine.log 并逐行打印隔离记录。
# 参数: $1 — 隔离区目录路径
function quarantine_list() {
    local quarantine_dir="$1"
    
    if [ ! -f "${quarantine_dir}/quarantine.log" ]; then
        echo "  隔离区为空"
        return
    fi
    
    echo "  隔离文件列表:"
    cat "${quarantine_dir}/quarantine.log" 2>/dev/null | while read -r line; do
        echo "    $line"
    done
}

# ---------- 还原隔离文件 ----------
# quarantine_restore: 从隔离区将文件还原到原始路径。
# 从文件名中解析原始路径（去除时间戳前缀，将 _ 恢复为 /）。
# 参数:
#   $1 - quarantine_file: 隔离区中的文件路径
#   $2 - quarantine_dir: 隔离区目录路径
# 返回:
#   成功时输出还原信息；失败时返回 1
function quarantine_restore() {
    local quarantine_file="$1"
    local quarantine_dir="$2"
    
    if [ ! -f "$quarantine_file" ]; then
        echo "  错误: 文件不存在: $quarantine_file"
        return 1
    fi
    
    # 从文件名还原原始路径：去掉 "20250101_120000_" 前缀，再将 _ 替换回 /
    local timestamp_name=$(basename "$quarantine_file")
    local orig_name=$(echo "$timestamp_name" | sed 's/^[0-9]\{8\}_[0-9]\{6\}_//' | sed 's/_/\//g')
    
    local dest_dir=$(dirname "/$orig_name")
    mkdir -p "$dest_dir" 2>/dev/null
    cp -a "$quarantine_file" "/$orig_name" 2>/dev/null || {
        echo "  错误: 无法还原到 /$orig_name"
        return 1
    }
    
    echo "  已还原: $quarantine_file -> /$orig_name"
}

# ---------- 隔离区统计 ----------
# quarantine_stats: 统计隔离区中的文件数量和总大小。
# 参数: $1 — 隔离区目录路径
function quarantine_stats() {
    local quarantine_dir="$1"
    local count=0
    local size=0
    
    if [ -d "$quarantine_dir" ]; then
        # 排除 .log 文件，只统计实际隔离的文件
        count=$(find "$quarantine_dir" -type f ! -name "*.log" 2>/dev/null | wc -l)
        size=$(du -sh "$quarantine_dir" 2>/dev/null | cut -f1)
    fi
    
    echo "  隔离文件数: $count"
    echo "  隔离区大小: ${size:-0}"
}
