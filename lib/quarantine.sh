#!/bin/bash
# ============================================
# 隔离模块 - 备份可疑文件
# ============================================

function quarantine_init() {
    local quarantine_dir="${REPORT_DIR}/${QUARANTINE_DIR}"
    mkdir -p "$quarantine_dir" 2>/dev/null
    echo "$quarantine_dir"
}

function quarantine_file() {
    local file="$1"
    local quarantine_dir="$2"
    local reason="$3"
    
    [ ! -f "$file" ] && return 1
    
    # 生成隔离路径（保留原始路径结构）
    local safe_name=$(echo "$file" | sed 's|/|_|g' | sed 's|^_||')
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local dest="${quarantine_dir}/${timestamp}_${safe_name}"
    
    # 复制文件（保留权限和时间）
    cp -a "$file" "$dest" 2>/dev/null || return 1
    
    # 记录隔离日志
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ISOLATED: $file -> $dest (reason: $reason)" >> "${quarantine_dir}/quarantine.log"
    
    echo "$dest"
}

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

function quarantine_restore() {
    local quarantine_file="$1"
    local quarantine_dir="$2"
    
    if [ ! -f "$quarantine_file" ]; then
        echo "  错误: 文件不存在: $quarantine_file"
        return 1
    fi
    
    # 从文件名还原原始路径
    local timestamp_name=$(basename "$quarantine_file")
    local orig_name=$(echo "$timestamp_name" | sed 's/^[0-9]\{8\}_[0-9]\{6\}_//' | sed 's/_/\//g')
    
    # 还原文件
    local dest_dir=$(dirname "/$orig_name")
    mkdir -p "$dest_dir" 2>/dev/null
    cp -a "$quarantine_file" "/$orig_name" 2>/dev/null || {
        echo "  错误: 无法还原到 /$orig_name"
        return 1
    }
    
    echo "  已还原: $quarantine_file -> /$orig_name"
}

function quarantine_stats() {
    local quarantine_dir="$1"
    local count=0
    local size=0
    
    if [ -d "$quarantine_dir" ]; then
        count=$(find "$quarantine_dir" -type f ! -name "*.log" 2>/dev/null | wc -l)
        size=$(du -sh "$quarantine_dir" 2>/dev/null | cut -f1)
    fi
    
    echo "  隔离文件数: $count"
    echo "  隔离区大小: ${size:-0}"
}
