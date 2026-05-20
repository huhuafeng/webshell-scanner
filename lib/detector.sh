#!/bin/bash
# ============================================
# 检测引擎 - 特征匹配、编码检测、熵分析
# 支持并行执行，每个子进程输出 JSON Lines 到 stdout
# ============================================

RESULTS_CRITICAL=0
RESULTS_HIGH=0
RESULTS_MEDIUM=0
RESULTS_LOW=0

function detector_init() {
    RESULTS_FILE=$(mktemp)
    echo "[]" > "$RESULTS_FILE"
    RESULTS_CRITICAL=0
    RESULTS_HIGH=0
    RESULTS_MEDIUM=0
    RESULTS_LOW=0
}

# 在子进程中输出单行 JSON
function detector_output_line() {
    local file="$1"
    local level="$2"
    local rule_name="$3"
    local description="$4"
    local line="$5"
    local context="$6"
    
    # 转义特殊字符，输出 JSON Lines
    python3 -c "
import json, sys
r = {
    'file': '$file',
    'level': '$level',
    'rule': '$rule_name',
    'desc': '$description',
    'line': ${line:-0},
    'context': '''$context'''
}
print(json.dumps(r, ensure_ascii=False))
" 2>/dev/null
}

# trim whitespace helper
function detector_trim() {
    local var="$1"
    var="${var#"${var%%[![:space:]]*}"}"
    var="${var%"${var##*[![:space:]]}"}"
    printf '%s' "$var"
}

# -------- 规则匹配 --------
function detector_match_rules() {
    local file="$1"
    local rules_file="$2"
    
    while IFS='|' read -r level name regex desc; do
        [[ -z "$level" || "$level" =~ ^# ]] && continue
        level=$(detector_trim "$level")
        name=$(detector_trim "$name")
        regex=$(detector_trim "$regex")
        desc=$(detector_trim "$desc")
        
        [ -z "$regex" ] && continue
        
        local matches=$(grep -noP "$regex" "$file" 2>/dev/null | head -5)
        if [ -n "$matches" ]; then
            while IFS=: read -r line content; do
                [ -z "$line" ] && continue
                local ctx=$(sed -n "${line}p" "$file" 2>/dev/null | sed 's/^[[:space:]]*//' | cut -c1-200)
                detector_output_line "$file" "$level" "$name" "$desc" "$line" "$ctx"
            done <<< "$matches"
        fi
    done < "$rules_file"
}

# -------- 熵分析（检测编码混淆）--------
function detector_entropy_check() {
    local file="$1"
    local size=$(stat -c "%s" "$file" 2>/dev/null)
    
    [ "$size" -gt "$SUSPICIOUS_SIZE_MAX" ] && return
    
    local entropy=$(python3 -c "
import sys, math
try:
    with open('$file', 'rb') as f:
        data = f.read(2048)
    if not data: sys.exit(0)
    text_chars = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    if text_chars > len(data) * 0.8:
        sys.exit(0)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = -sum((c/len(data)) * math.log2(c/len(data)) for c in counts if c > 0)
    print(f'{entropy:.2f}')
except:
    sys.exit(0)
" 2>/dev/null)
    
    [ -z "$entropy" ] && return
    
    if (( $(echo "$entropy > $ENTROPY_THRESHOLD" | bc -l 2>/dev/null) )); then
        detector_output_line "$file" "HIGH" "high-entropy" "文件熵值=${entropy}(阈值=${ENTROPY_THRESHOLD})，可能是编码混淆载荷" "1" ""
    fi
}

# -------- 权限异常检测 --------
function detector_permission_check() {
    local file="$1"
    local perms=$(stat -c "%a" "$file" 2>/dev/null)
    
    if [ "$perms" = "777" ]; then
        detector_output_line "$file" "HIGH" "world-writable" "文件权限为 0777，全局可写" "0" ""
    fi
    
    local owner=$(stat -c "%U" "$file" 2>/dev/null)
    local dir=$(dirname "$file")
    if [ "$owner" = "www-data" ] || [ "$owner" = "nobody" ]; then
        case "$dir" in
            /etc/*|/usr/local/bin/*|/usr/bin/*|/opt/*|/tmp/*|/dev/shm/*|/var/tmp/*)
                detector_output_line "$file" "MEDIUM" "unusual-owner" "文件属主为 $owner（在非Web目录下异常）" "0" ""
                ;;
        esac
    fi
}

# -------- 文件名检测 --------
function detector_filename_check() {
    local file="$1"
    local basename=$(basename "$file")
    
    while IFS='|' read -r level pattern desc; do
        [[ -z "$level" || "$level" =~ ^# ]] && continue
        level=$(detector_trim "$level")
        pattern=$(detector_trim "$pattern")
        desc=$(detector_trim "$desc")
        
        [ -z "$pattern" ] && continue
        
        if echo "$basename" | grep -qP "$pattern"; then
            detector_output_line "$file" "$level" "suspicious-filename" "可疑文件名: $basename - $desc" "0" ""
        fi
    done < "$RULES_DIR/hidden_files.txt"
}

# -------- 目录位置检测 --------
function detector_location_check() {
    local file="$1"
    local dir=$(dirname "$file")
    
    local suspicious_dirs=("uploads" "upload" "images" "img" "media" "files" "attachments" "tmp" "temp" "cache" "backup" "logs" "error" "avatars" "gallery")
    for sd in "${suspicious_dirs[@]}"; do
        if echo "$dir" | grep -qiE "/${sd}(/|$)"; then
            local ext="${file##*.}"
            case "$ext" in
                php|php5|phtml|php7|php8|jsp|jspx|asp|aspx|cgi|pl)
                    detector_output_line "$file" "HIGH" "wrong-location" "脚本文件出现在非预期目录: $dir" "0" ""
                    break
                    ;;
            esac
        fi
    done
}

# -------- 单文件扫描（子进程入口）--------
# 输出: JSON Lines 到 stdout
function detector_scan_file() {
    local file="$1"
    
    [ ! -f "$file" ] || [ ! -r "$file" ] && return
    
    local size=$(stat -c "%s" "$file" 2>/dev/null)
    [ "$size" -gt "$MAX_FILE_SIZE" ] && return
    [ "$size" -eq 0 ] && return
    
    detector_filename_check "$file"
    detector_location_check "$file"
    detector_permission_check "$file"
    
    local mime=$(file -b --mime-type "$file" 2>/dev/null)
    case "$mime" in
        text/*|application/x-php|application/x-sh|application/x-perl|application/x-python|application/x-httpd-php*|inode/x-empty|application/xml|application/json)
            ;;
        *)
            return
            ;;
    esac
    
    detector_match_rules "$file" "$RULES_DIR/php_sigs.txt"
    
    case "$file" in
        *.jsp|*.jspx)
            detector_match_rules "$file" "$RULES_DIR/jsp_sigs.txt"
            ;;
    esac
    
    detector_entropy_check "$file"
}

# -------- 合并结果（由主进程调用）--------
function detector_merge_results() {
    local result_dir="$1"
    
    # 收集所有子进程输出，合并为单一 JSON 数组
    python3 -c "
import json, glob, sys

result_dir = '$result_dir'
all_results = []

for f in sorted(glob.glob(result_dir + '/worker_*.json')):
    with open(f) as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    all_results.append(json.loads(line))
                except:
                    pass

with open('$RESULTS_FILE', 'w') as f:
    json.dump(all_results, f, ensure_ascii=False, indent=2)

# 计算汇总
crit = sum(1 for r in all_results if r['level'] == 'CRITICAL')
high = sum(1 for r in all_results if r['level'] == 'HIGH')
med = sum(1 for r in all_results if r['level'] == 'MEDIUM')
low = sum(1 for r in all_results if r['level'] == 'LOW')
print(f'RESULTS_CRITICAL={crit}')
print(f'RESULTS_HIGH={high}')
print(f'RESULTS_MEDIUM={med}')
print(f'RESULTS_LOW={low}')
print(f'TOTAL={len(all_results)}')
" 2>/dev/null
}

function detector_get_results() {
    cat "$RESULTS_FILE" 2>/dev/null
}

function detector_get_summary() {
    echo "CRITICAL=$RESULTS_CRITICAL"
    echo "HIGH=$RESULTS_HIGH"
    echo "MEDIUM=$RESULTS_MEDIUM"
    echo "LOW=$RESULTS_LOW"
    echo "TOTAL=$((RESULTS_CRITICAL + RESULTS_HIGH + RESULTS_MEDIUM + RESULTS_LOW))"
}

function detector_cleanup() {
    [ -f "$RESULTS_FILE" ] && rm -f "$RESULTS_FILE"
}
