#!/bin/bash
# ============================================
# 检测引擎 - 特征匹配、编码检测、熵分析
# 功能：对单个文件执行多维度检测：
#   1. 规则特征匹配（php_sigs.txt / jsp_sigs.txt 正则库）
#   2. 文件熵值分析（识别编码混淆/加密载荷）
#   3. 权限异常检测（0777、非 Web 属主）
#   4. 可疑文件名检测（hidden_files.txt 模式库）
#   5. 目录位置检测（脚本文件出现在 uploads/ 等非预期目录）
# 支持并行执行，每个子进程输出 JSON Lines 到 stdout。
# 主进程通过 detector_merge_results 汇总。
# ============================================

# 全局告警计数变量（由 detector_merge_results 的 eval 输出设置）
RESULTS_CRITICAL=0
RESULTS_HIGH=0
RESULTS_MEDIUM=0
RESULTS_LOW=0

# ---------- 检测引擎初始化 ----------
# detector_init: 创建临时 JSON 结果文件，重置所有告警计数器。
# 每次扫描开始前调用一次。
# 参数：无
function detector_init() {
    RESULTS_FILE=$(mktemp)   # 临时文件，存储最终合并的 JSON 结果数组
    echo "[]" > "$RESULTS_FILE"
    RESULTS_CRITICAL=0
    RESULTS_HIGH=0
    RESULTS_MEDIUM=0
    RESULTS_LOW=0
}

# ---------- 单条结果输出 ----------
# detector_output_line: 以单行 JSON 格式输出一条检测告警。
# 在子进程中被调用，通常重定向到独立 .json 文件。
# 参数:
#   $1 - file: 告警文件路径
#   $2 - level: 告警级别 (CRITICAL/HIGH/MEDIUM/LOW)
#   $3 - rule_name: 匹配的规则名称
#   $4 - description: 告警描述文本
#   $5 - line: 匹配行号（0 表示不适用）
#   $6 - context: 匹配行的上下文内容（最多 200 字符）
function detector_output_line() {
    local file="$1"
    local level="$2"
    local rule_name="$3"
    local description="$4"
    local line="$5"
    local context="$6"
    
    # 清理 context：去除非 ASCII 可打印字符和单引号（避免破坏 Python 字符串）
    context=$(echo "$context" | tr -dc '[:print:]' | sed "s/'/ /g" | cut -c1-200)
    
    python3 -c "
import json, sys
r = {
    'file': '$file',
    'level': '$level',
    'rule': '$rule_name',
    'desc': '$description',
    'line': ${line:-0},
    'context': '$context'
}
print(json.dumps(r, ensure_ascii=False))
" 2>/dev/null
}

# ---------- 字符串空白修剪辅助 ----------
# detector_trim: 去除字符串首尾空白字符（空格、Tab、换行等）。
# 用于清洗规则文件中由 IFS='|' 读取后遗留在字段周围的多余空白。
# 参数: $1 — 待修剪的字符串
# 返回: 修剪后的字符串（通过 printf 输出）
function detector_trim() {
    local var="$1"
    var="${var#"${var%%[![:space:]]*}"}"    # 去掉前导空白
    var="${var%"${var##*[![:space:]]}"}"    # 去掉后缀空白
    printf '%s' "$var"
}

# -------- 规则特征匹配 --------
# detector_match_rules: 读取规则文件（php_sigs.txt 或 jsp_sigs.txt），
#   对文件逐行执行 Perl 兼容正则（grep -P）匹配。
#   每条匹配结果通过 detector_output_line 输出。
#   性能优化：支持两级过滤加速——
#     第一级：grep -F 预过滤（先检查是否含任何危险关键词，不含则跳过全文正则）
#     第二级：SCAN_LEVEL 级别过滤（低于设定级别的规则跳过）
# 参数:
#   $1 - file: 待检测文件路径
#   $2 - rules_file: 规则文件路径（格式：级别|名称|正则表达式|描述）
function detector_match_rules() {
    local file="$1"
    local rules_file="$2"
    local pre_filter_file="$RULES_DIR/pre_filter.txt"
    
    # ==== 第一级：grep -F 预过滤 ====
    # 先检查文件是否包含任意预过滤关键词。若无，直接跳过整个规则集（约 90+ 条正则）
    # 效果：对 10 万文件扫描，预过滤可将正则阶段耗时从 15min 降到 2min
    if [ "${SCAN_USE_PREFILTER:-true}" = "true" ] && [ -f "$pre_filter_file" ]; then
        if ! grep -qFa -f "$pre_filter_file" "$file" 2>/dev/null; then
            return  # 不包含任何危险关键词，跳过全部正则匹配
        fi
    fi
    
    # ==== 第二级：逐条正则匹配 ====
    # 根据 SCAN_LEVEL 定义级别优先级
    local level_priority
    case "$SCAN_LEVEL" in
        CRITICAL) level_priority=1 ;;
        HIGH)     level_priority=2 ;;
        MEDIUM)   level_priority=3 ;;
        LOW)      level_priority=4 ;;
        *)        level_priority=999 ;;  # ALL / 未设置：不限制
    esac
    
    # IFS='|' 按竖线分隔读取规则文件；-r 防止反斜杠转义
    while IFS='|' read -r level name regex desc; do
        [[ -z "$level" || "$level" =~ ^# ]] && continue  # 跳过空行和注释行
        level=$(detector_trim "$level")
        name=$(detector_trim "$name")
        regex=$(detector_trim "$regex")
        desc=$(detector_trim "$desc")
        
        [ -z "$regex" ] && continue  # 正则表达式为空则跳过
        
        # SCAN_LEVEL 优先级过滤：低于设定级别的规则跳过
        if [ "$level_priority" -ne 999 ]; then
            case "$level" in
                CRITICAL) this_priority=1 ;;
                HIGH)     this_priority=2 ;;
                MEDIUM)   this_priority=3 ;;
                LOW)      this_priority=4 ;;
                *)        this_priority=999 ;;
            esac
            [ "$this_priority" -gt "$level_priority" ] && continue
        fi
        
        # grep -anoP: -a 二进制当文本处理, -n 行号, -o 仅匹配文本, -P Perl 正则
        # head -5 限制最多输出前 5 条匹配，避免单个文件告警淹没
        local matches=$(grep -anoP "$regex" "$file" 2>/dev/null | head -5)
        if [ -n "$matches" ]; then
            # 逐条解析 "行号:匹配内容" 格式
            while IFS=: read -r line content; do
                [ -z "$line" ] && continue
                # 截取匹配行的前 200 字符作为上下文
                local ctx=$(sed -n "${line}p" "$file" 2>/dev/null | sed 's/^[[:space:]]*//' | cut -c1-200)
                detector_output_line "$file" "$level" "$name" "$desc" "$line" "$ctx"
            done <<< "$matches"
        fi
    done < "$rules_file"
}

# -------- 熵分析（检测编码混淆）--------
# detector_entropy_check: 读取文件前 2048 字节，计算香农熵（Shannon entropy）。
#   先判断是否为文本（可打印字符 > 80% 则跳过，避免误报英文代码）。
#   熵值 > ENTROPY_THRESHOLD 标记为 HIGH 告警。
# 原理：正常源代码熵值约 4.5-6.0，加密/压缩/编码混淆载荷熵值 > 6.5。
# 参数: $1 — 文件路径
function detector_entropy_check() {
    local file="$1"
    local size=$(stat -c "%s" "$file" 2>/dev/null)
    
    [ "$size" -gt "$SUSPICIOUS_SIZE_MAX" ] && return  # 超 500KB 不做熵检测
    
    local entropy=$(python3 -c "
import sys, math
try:
    with open('$file', 'rb') as f:
        data = f.read(2048)
    if not data: sys.exit(0)
    # 统计可打印字符比例，超过 80% 判定为文本文件，跳过熵检测
    text_chars = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    if text_chars > len(data) * 0.8:
        sys.exit(0)
    # 计算 256 字节频率分布
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    # 香农熵公式: H = -Σ(p(i) * log2(p(i)))
    entropy = -sum((c/len(data)) * math.log2(c/len(data)) for c in counts if c > 0)
    print(f'{entropy:.2f}')
except:
    sys.exit(0)
" 2>/dev/null)
    
    [ -z "$entropy" ] && return
    
    # bc 比较浮点数
    if (( $(echo "$entropy > $ENTROPY_THRESHOLD" | bc -l 2>/dev/null) )); then
        detector_output_line "$file" "HIGH" "high-entropy" "文件熵值=${entropy}(阈值=${ENTROPY_THRESHOLD})，可能是编码混淆载荷" "1" ""
    fi
}

# -------- 权限异常检测 --------
# detector_permission_check: 检查文件是否存在异常权限配置。
#   1. 全局可写 (0777) — 任何人都可修改，高危
#   2. Web 服务属主 (www-data/nobody) 出现在非 Web 路径 — 可疑
# 参数: $1 — 文件路径
function detector_permission_check() {
    local file="$1"
    local perms=$(stat -c "%a" "$file" 2>/dev/null)
    
    if [ "$perms" = "777" ]; then
        detector_output_line "$file" "HIGH" "world-writable" "文件权限为 0777，全局可写" "0" ""
    fi
    
    local owner=$(stat -c "%U" "$file" 2>/dev/null)
    local dir=$(dirname "$file")
    # www-data/nobody 应只出现在 Web 目录，出现在 /etc、/tmp、/opt 等说明异常
    if [ "$owner" = "www-data" ] || [ "$owner" = "nobody" ]; then
        case "$dir" in
            /etc/*|/usr/local/bin/*|/usr/bin/*|/opt/*|/tmp/*|/dev/shm/*|/var/tmp/*)
                detector_output_line "$file" "MEDIUM" "unusual-owner" "文件属主为 $owner（在非Web目录下异常）" "0" ""
                ;;
        esac
    fi
}

# -------- 文件名检测 --------
# detector_filename_check: 对照 hidden_files.txt 中的可疑文件名模式，
#   检测当前文件名是否匹配。
# 典型检测项：隐藏文件、双后缀文件、已知木马文件名等。
# 参数: $1 — 文件路径
function detector_filename_check() {
    local file="$1"
    local basename=$(basename "$file")
    
    # 读取规则文件，格式：级别|模式(正则)|描述
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
# detector_location_check: 检测可执行脚本文件是否出现在非预期目录。
#   例如 .php 文件出现在 uploads/、images/、tmp/ 等目录，
#   通常这些目录不应包含可执行脚本，出现则大概率是木马。
# 参数: $1 — 文件路径
function detector_location_check() {
    local file="$1"
    local dir=$(dirname "$file")
    
    # suspicious_dirs: 预期不应有可执行脚本的目录名列表
    local suspicious_dirs=("uploads" "upload" "images" "img" "media" "files" "attachments" "tmp" "temp" "cache" "backup" "logs" "error" "avatars" "gallery")
    for sd in "${suspicious_dirs[@]}"; do
        if echo "$dir" | grep -qiE "/${sd}(/|$)"; then
            local ext="${file##*.}"
            # 只对可执行脚本扩展名发出告警
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
# detector_scan_file: 对单个文件执行全套检测流程。
#   这是子进程的入口函数，通过 xargs 并发调用。
# 执行顺序:
#   1. 文件名检查 → 2. 位置检查 → 3. 权限检查
#   4. 规则匹配（PHP 特征） → 5. JSP 特征（仅 .jsp/.jspx）
#   6. 熵值分析
# 参数: $1 — 文件路径
# 输出: JSON Lines 到 stdout（每条检测结果一行）
function detector_scan_file() {
    local file="$1"
    
    [ ! -f "$file" ] || [ ! -r "$file" ] && return  # 文件不存在或不可读则跳过
    
    local size=$(stat -c "%s" "$file" 2>/dev/null)
    [ "$size" -gt "$MAX_FILE_SIZE" ] && return  # 超大文件跳过内容扫描
    [ "$size" -eq 0 ] && return  # 空文件跳过
    
    # 第一轮：元数据检查（不读文件内容）
    detector_filename_check "$file"
    detector_location_check "$file"
    detector_permission_check "$file"
    
    # 判断是否已知脚本扩展名
    local ext="${file##*.}"
    local known_script=false
    case "$ext" in
        php|php5|phtml|php7|php8|jsp|jspx|asp|aspx|cgi|pl|py|sh|shtml)
            known_script=true
            ;;
    esac
    
    if ! $known_script; then
        # 非脚本扩展名：通过 MIME 判断是否为文本类文件
        # 这样做可以检测图片文件中嵌入的 polyglot 木马
        local mime=$(file -b --mime-type "$file" 2>/dev/null)
        case "$mime" in
            text/*|application/xml|application/json|inode/x-empty)
                ;;  # 文本类文件继续扫描
            *)
                return  # 二进制/图片文件跳过内容检测
                ;;
        esac
    fi
    
    # 第二轮：内容检测
    detector_match_rules "$file" "$RULES_DIR/php_sigs.txt"  # 匹配 PHP 特征
    
    case "$file" in
        *.jsp|*.jspx)
            detector_match_rules "$file" "$RULES_DIR/jsp_sigs.txt"  # JSP 额外匹配
            ;;
    esac
    
    detector_entropy_check "$file"  # 熵分析
}

# -------- 合并结果（由主进程调用）--------
# detector_merge_results: 读取 worker_dir 下所有子进程输出的 JSON Lines 文件，
#   合并为单一 JSON 数组写入 RESULTS_FILE，并输出汇总统计变量。
# 参数: $1 — result_dir: 存放各子进程 .json 文件的临时目录
# 输出（stdout）: 变量赋值语句如 RESULTS_CRITICAL=3，供主进程 eval
function detector_merge_results() {
    local result_dir="$1"
    
    python3 -c "
import json, glob, sys

result_dir = '$result_dir'
all_results = []

# 遍历所有 worker_*.json 文件（按文件名排序保证可复现）
for f in sorted(glob.glob(result_dir + '/worker_*.json')):
    with open(f) as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    all_results.append(json.loads(line))
                except:
                    pass  # 跳过非 JSON 行（子进程异常输出）

# 将合并结果写入 RESULTS_FILE（全局变量由 bash 替换）
with open('$RESULTS_FILE', 'w') as f:
    json.dump(all_results, f, ensure_ascii=False, indent=2)

# 按级别统计告警数量，输出 bash eval 兼容的变量赋值
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

# ---------- 辅助函数 ----------
# detector_get_results: 将当前 RESULTS_FILE 内容输出到 stdout。
# 参数：无
function detector_get_results() {
    cat "$RESULTS_FILE" 2>/dev/null
}

# detector_get_summary: 以变量赋值格式输出当前告警统计。
# 参数：无
# 输出: CRITICAL=0 等行
function detector_get_summary() {
    echo "CRITICAL=$RESULTS_CRITICAL"
    echo "HIGH=$RESULTS_HIGH"
    echo "MEDIUM=$RESULTS_MEDIUM"
    echo "LOW=$RESULTS_LOW"
    echo "TOTAL=$((RESULTS_CRITICAL + RESULTS_HIGH + RESULTS_MEDIUM + RESULTS_LOW))"
}

# detector_cleanup: 删除临时结果文件（每次扫描完成后调用）。
# 参数：无
function detector_cleanup() {
    [ -f "$RESULTS_FILE" ] && rm -f "$RESULTS_FILE"
}
