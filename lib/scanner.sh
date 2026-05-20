#!/bin/bash
# ============================================
# 扫描引擎 - 文件遍历与基础信息采集
# ============================================

# 初始化扫描任务列表
function scanner_init() {
    local scan_dirs=("$@")
    local file_list=()
    local temp_file=$(mktemp)
    
    # 构建 find 扩展名条件
    local ext_conditions=()
    for ext in "${SCAN_EXTENSIONS[@]}"; do
        if [ ${#ext_conditions[@]} -eq 0 ]; then
            ext_conditions+=(-name "*.$ext")
        else
            ext_conditions+=(-o -name "*.$ext")
        fi
    done

    # 构建跳过路径条件
    local skip_conditions=()
    for dir in "${SKIP_DIRS[@]}"; do
        skip_conditions+=( -path "$dir" -prune )
        skip_conditions+=( -o )
    done

    # 遍历每个扫描目录
    for scan_dir in "${scan_dirs[@]}"; do
        [ -d "$scan_dir" ] || continue
        echo "  [*] Scanning: $scan_dir" >&2
        
        find "$scan_dir" -maxdepth 10 \
            "${skip_conditions[@]}" \
            -type f \( "${ext_conditions[@]}" \) \
            -size -"${MAX_FILE_SIZE}"c \
            -readable \
            -print0 2>/dev/null >> "$temp_file"
    done

    echo "$temp_file"
}

# 跳过白名单模式
function scanner_filter_whitelist() {
    local file_list="$1"
    local filtered=$(mktemp)
    
    while IFS= read -r -d '' file; do
        local skip=false
        for pattern in "${WHITELIST_PATTERNS[@]}"; do
            if echo "$file" | grep -qiE "$pattern" 2>/dev/null; then
                skip=true
                break
            fi
        done
        $skip || printf '%s\0' "$file"
    done < "$file_list" > "$filtered"
    
    echo "$filtered"
}

# 获取文件详细信息
function scanner_get_file_info() {
    local file="$1"
    
    # 使用 stat 获取文件信息
    local perms=$(stat -c "%a" "$file" 2>/dev/null)
    local size=$(stat -c "%s" "$file" 2>/dev/null)
    local owner=$(stat -c "%U" "$file" 2>/dev/null)
    local group=$(stat -c "%G" "$file" 2>/dev/null)
    local mtime=$(stat -c "%Y" "$file" 2>/dev/null)
    local mtime_str=$(stat -c "%y" "$file" 2>/dev/null | cut -d. -f1)
    
    # 检测文件类型（mime）
    local mime=$(file -b --mime-type "$file" 2>/dev/null)
    
    # 获取文件行数
    local lines=0
    [ "$size" -lt 1048576 ] && lines=$(wc -l < "$file" 2>/dev/null)
    
    # 返回 base64 编码的 KV 对，避免特殊字符问题
    echo "file=$file"
    echo "perms=$perms"
    echo "size=$size"
    echo "owner=$owner"
    echo "group=$group"
    echo "mtime=$mtime"
    echo "mtime_str=$mtime_str"
    echo "mime=$mime"
    echo "lines=$lines"
}

# 是否是文本/脚本文件（只扫描文本类文件内容）
function scanner_is_text_file() {
    local file="$1"
    local mime=$(file -b --mime-type "$file" 2>/dev/null)
    case "$mime" in
        text/*|application/x-php|application/x-sh|application/x-perl|application/x-python|application/x-httpd-php*|inode/x-empty)
            return 0
            ;;
        application/xml|application/json)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# 并行执行任务
function scanner_parallel_exec() {
    local file_list="$1"
    local worker_func="$2"
    local max_jobs=${PARALLEL_JOBS:-$(nproc 2>/dev/null || echo 4)}
    
    if [ "$max_jobs" -le 0 ]; then
        max_jobs=$(nproc 2>/dev/null || echo 4)
    fi
    
    xargs -0 -P "$max_jobs" -I {} bash -c "$worker_func \"{}\"" < "$file_list"
}
