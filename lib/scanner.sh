#!/bin/bash
# ============================================
# 扫描引擎 - 文件遍历与基础信息采集
# 功能：遍历指定目录树，按扩展名筛选脚本文件，
#       应用白名单过滤，收集文件元数据（权限/大小/属主/MIME 等）。
# 被 scan.sh 和 detector.sh 调用。
# ============================================

# ---------- 初始化文件扫描列表 ----------
# scanner_init: 对每个 SCAN_DIRS 目录执行 find 命令，
#   收集匹配 SCAN_EXTENSIONS 且不超过 MAX_FILE_SIZE 的脚本文件。
# 返回：临时文件路径，内容为 NUL 分隔的文件路径列表。
# 参数: $@ — 要扫描的目录列表（可变参数）
function scanner_init() {
    local scan_dirs=("$@")
    local file_list=()
    local temp_file=$(mktemp)   # 临时文件，累积所有 find 结果
    
    # 动态构建 find 的扩展名条件
    # 输出形如: -name "*.php" -o -name "*.jsp" -o ...
    # 如设置了 SCAN_TYPES（如 "php,jsp"），则优先使用命令行指定的类型
    local extensions=()
    if [ -n "$SCAN_TYPES" ]; then
        IFS=',' read -ra extensions <<< "$SCAN_TYPES"
        # 兼容用户带点写法，如 ".php" → "php"
        for i in "${!extensions[@]}"; do
            extensions[$i]=$(echo "${extensions[$i]}" | sed 's/^\.//')
        done
    else
        extensions=("${SCAN_EXTENSIONS[@]}")
    fi

    local ext_conditions=()
    for ext in "${extensions[@]}"; do
        if [ ${#ext_conditions[@]} -eq 0 ]; then
            ext_conditions+=(-name "*.$ext")    # 第一个条件，无 -o 前缀
        else
            ext_conditions+=(-o -name "*.$ext")  # 后续条件用 -o 连接
        fi
    done

    # 构建 find 的跳过目录条件
    # 输出形如: -path "/proc" -prune -o -path "/sys" -prune -o ...
    # -prune 告诉 find 不要进入这些目录
    local skip_conditions=()
    for dir in "${SKIP_DIRS[@]}"; do
        skip_conditions+=( -path "$dir" -prune )
        skip_conditions+=( -o )     # -o 连接下一个表达式
    done

    # 遍历每个扫描目录，执行 find 并追加到临时文件
    for scan_dir in "${scan_dirs[@]}"; do
        [ -d "$scan_dir" ] || continue          # 目录不存在则跳过
        echo "  [*] Scanning: $scan_dir" >&2
        
        # 如果设置了 SCAN_RECENT_DAYS，添加 -mtime 限制只扫描最近修改的文件
        local recency_condition=()
        if [ "${SCAN_RECENT_DAYS:-0}" -gt 0 ] 2>/dev/null; then
            recency_condition=(-mtime -"$SCAN_RECENT_DAYS")
        fi
        
        # find 参数说明：
        #   -maxdepth 10      : 最大递归深度 10 层
        #   -prune            : 跳过 SKIP_DIRS 中的系统目录
        #   -type f           : 只找普通文件
        #   "${ext_cond...}"  : 匹配 SCAN_EXTENSIONS 定义的扩展名
        #   -mtime -N         : 仅最近 N 天修改（增量扫描，可选）
        #   -size -${MAX}c    : 跳过超过 MAX_FILE_SIZE 的大文件
        #   -readable         : 只处理当前用户可读的文件
        #   -print0           : NUL 分隔输出，避免文件名含空格/换行问题
        find "$scan_dir" -maxdepth 10 \
            "${skip_conditions[@]}" \
            -type f \( "${ext_conditions[@]}" \) \
            "${recency_condition[@]}" \
            -size -"${MAX_FILE_SIZE}"c \
            -readable \
            -print0 2>/dev/null >> "$temp_file"
    done

    echo "$temp_file"   # 返回临时文件路径，由调用方读取和清理
}

# ---------- 白名单过滤 ----------
# scanner_filter_whitelist: 读取 scanner_init 生成的 NUL 分隔文件列表，
#   对每个文件路径依次匹配 WHITELIST_PATTERNS 模式，
#   匹配到的跳过（不输出），未匹配的保留。
# 参数: $1 — scanner_init 返回的原始文件列表路径
# 返回：临时文件路径，内容为过滤后的 NUL 分隔文件路径列表
function scanner_filter_whitelist() {
    local file_list="$1"
    local filtered=$(mktemp)    # 过滤后的列表临时文件
    
    # IFS= 保持行首/行尾空白；-r 防止反斜杠转义；-d '' 按 NUL 分隔读取
    while IFS= read -r -d '' file; do
        local skip=false
        for pattern in "${WHITELIST_PATTERNS[@]}"; do
            if echo "$file" | grep -qiE "$pattern" 2>/dev/null; then
                skip=true       # 匹配到任一白名单模式即标记跳过
                break
            fi
        done
        $skip || printf '%s\0' "$file"  # 未跳过的文件写入输出
    done < "$file_list" > "$filtered"
    
    echo "$filtered"  # 返回过滤后列表路径
}

# ---------- 获取文件详细信息 ----------
# scanner_get_file_info: 收集单个文件的元数据（权限/大小/属主等）
# 参数: $1 — 文件路径
# 输出：key=value 格式的元数据行，供调用方 eval 使用
function scanner_get_file_info() {
    local file="$1"
    
    # perms: 文件权限八进制表示（如 644, 755, 777）
    local perms=$(stat -c "%a" "$file" 2>/dev/null)
    # size: 文件大小（字节）
    local size=$(stat -c "%s" "$file" 2>/dev/null)
    local owner=$(stat -c "%U" "$file" 2>/dev/null)   # 属主用户名
    local group=$(stat -c "%G" "$file" 2>/dev/null)   # 属组名
    local mtime=$(stat -c "%Y" "$file" 2>/dev/null)   # 修改时间（Unix 时间戳）
    local mtime_str=$(stat -c "%y" "$file" 2>/dev/null | cut -d. -f1)  # 可读时间
    
    local mime=$(file -b --mime-type "$file" 2>/dev/null)  # MIME 类型
    
    local lines=0
    [ "$size" -lt 1048576 ] && lines=$(wc -l < "$file" 2>/dev/null)  # <1MB 才统计行数
    
    # 输出 key=value 格式，供调用方 eval 解析
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

# ---------- 文本文件检测 ----------
# scanner_is_text_file: 用 MIME 类型判断文件是否为文本/脚本类文件。
# 只有文本类文件才做内容扫描，避免扫描二进制文件造成误报和资源浪费。
# 参数: $1 — 文件路径
# 返回: 0=是文本文件, 1=非文本文件
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

# ---------- 并行执行任务 ----------
# scanner_parallel_exec: 使用 xargs -P 对文件列表启动并发子进程。
# 注意：实际扫描并发逻辑已在 scan.sh 中内联实现，此函数预留作公共接口。
# 参数: $1 — NUL 分隔的文件列表
#       $2 — 子进程执行命令模板
function scanner_parallel_exec() {
    local file_list="$1"
    local worker_func="$2"
    local max_jobs=${PARALLEL_JOBS:-$(nproc 2>/dev/null || echo 4)}
    
    if [ "$max_jobs" -le 0 ]; then
        max_jobs=$(nproc 2>/dev/null || echo 4)
    fi
    
    xargs -0 -P "$max_jobs" -I {} bash -c "$worker_func \"{}\"" < "$file_list"
}
