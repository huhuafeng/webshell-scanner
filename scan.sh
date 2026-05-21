#!/bin/bash
# ============================================
# MUMA SCAN - 网站木马一键扫描器
# 功能：遍历服务器文件系统，基于正则规则库检测 PHP/JSP 木马、
#       分析文件熵值识别编码混淆、检查异常权限与可疑文件名，
#       生成终端/HTML/JSON 格式报告，并支持可疑文件隔离。
# 用法: ./scan.sh [OPTIONS]
# 依赖: bash 4+, python3, bc, file, find, xargs, stat, grep
# ============================================

set -e

# ---------- 基础设置 ----------
# SCRIPT_DIR: 脚本自身所在目录（用于定位 lib/、rules/、output/ 等子目录）
# 使用 readlink -f 解析软链接，确保通过 muma-scan 全局命令也能正确定位
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"       # 模块库目录
RULES_DIR="$SCRIPT_DIR/rules"   # 检测规则文件目录

# ---------- 加载模块 ----------
source "$SCRIPT_DIR/config.sh"    # 加载配置（扫描路径、阈值、白名单等）
source "$LIB_DIR/scanner.sh"      # 加载文件遍历引擎
source "$LIB_DIR/detector.sh"     # 加载检测引擎（特征匹配/熵分析/权限检查等）
source "$LIB_DIR/reporter.sh"     # 加载报告生成器
source "$LIB_DIR/quarantine.sh"   # 加载隔离模块

# ---------- 创建输出目录 ----------
# 确保报告输出目录存在；quarantine_init 返回隔离区路径
mkdir -p "$SCRIPT_DIR/$REPORT_DIR" 2>/dev/null
QUARANTINE_DIR=$(quarantine_init)

# ---------- 颜色 ----------
# 以下为终端彩色输出的 ANSI 转义码
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# ---------- 使用帮助 ----------
# show_help: 打印命令行选项说明，然后退出。
# 参数：无。从全局变量 $0 读取脚本名。
function show_help() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -f, --full        全盘扫描（默认扫描 SCAN_DIRS 中的所有目录）"
    echo "  -q, --quick       快速模式（仅 CRITICAL 级别规则，可配合 -p/--full 使用）"
    echo "  -p, --path DIR    指定扫描路径（可重复使用）"
    echo "  -r, --report      查看上次扫描报告"
    echo "  -c, --cleanup     清理隔离区"
    echo "  -l, --list        列出隔离区文件"
    echo "  -n, --recent DAYS 仅扫描最近 N 天内修改的文件（增量扫描）"
    echo "  -t, --type EXT    指定文件类型（如 php / php,jsp / .php,.asp）"
    echo "  -L, --level LVL   规则级别：CRITICAL / HIGH / ALL（默认 ALL）"
    echo "  -d, --detail      显示完整告警详情（默认仅显示摘要和报告路径）"
    echo "  -h, --help        显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 --full                 全盘扫描"
    echo "  $0 --quick                快速模式（仅 CRITICAL 规则）"
    echo "  $0 --quick --full         全盘快速扫描"
    echo "  $0 -q -p /www             快速扫描指定目录"
    echo "  $0 --path /var/www/html   扫描指定路径"
    echo "  $0 -t php                 仅扫描 .php 文件"
    echo "  $0 -t php,jsp,asp         扫描多种文件类型"
    echo "  $0 --full -t php          全盘仅扫 .php"
    echo "  $0 -n 7                   增量扫描：仅最近 7 天修改的文件"
    echo "  $0 --full -L CRITICAL     全盘 + 仅 CRITICAL 级别规则"
    echo "  $0 --report               查看上次扫描报告"
    echo "  $0 --list                 列出已隔离文件"
    echo "  $0 --cleanup              清理隔离区"
    exit 0
}

# ---------- 查看历史报告 ----------
# show_report: 读取上次扫描结果 JSON 和元数据，调用终端报告函数展示。
# 流程：检测 last_scan_results.json 是否存在 → 加载 last_scan_meta.txt 元数据
#       → 调用 reporter_generate_terminal 输出到终端。
# 参数：无。路径硬编码在函数内。
function show_report() {
    local report_file="$SCRIPT_DIR/$REPORT_DIR/last_scan_results.json"
    if [ ! -f "$report_file" ]; then
        echo -e "${YELLOW}⚠️  没有找到历史扫描报告。${NC}"
        echo "   请先执行一次扫描: $0 --full"
        exit 0
    fi
    
    local meta_file="$SCRIPT_DIR/$REPORT_DIR/last_scan_meta.txt"
    local scan_time=""
    local scan_dirs=""
    local files_count=""
    [ -f "$meta_file" ] && source "$meta_file"
    
    reporter_generate_terminal "$report_file" "$scan_time" "$scan_dirs" "$files_count"
}

# ---------- 扫描主流程 ----------
# run_scan: 木马扫描的核心流程，按顺序执行以下步骤：
#   1. 初始化检测引擎（清空上次结果）
#   2. 遍历文件系统，查找符合扩展名的脚本文件
#   3. 按白名单过滤文件列表
#   4. 并发执行扫描（xargs + 子进程调用 detector_scan_file）
#   5. 合并子进程结果为 JSON 数组，统计各等级告警数
#   6. 保存时间戳报告 + 覆盖 last_scan 用于 -r 查看
#   7. 终端报告（带颜色输出）
#   8. HTML 报告（如配置开启）
#   9. 清理临时文件与过期历史报告
# 参数: $@ — 要扫描的目录列表（可变参数）
function run_scan() {
    local scan_dirs=("$@")          # 待扫描的目录数组
    
    local scan_time=$(date '+%Y-%m-%d %H:%M:%S')       # 人类可读时间
    local scan_timestamp=$(date '+%Y%m%d_%H%M%S')       # 文件名用时间戳
    local start_epoch=$(date +%s)                        # 开始时间戳（用于统计耗时）
    
    echo -e "${CYAN}${BOLD}🛡️  MUMA SCAN - 网站木马扫描器${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  扫描时间: $scan_time"
    echo -e "  扫描路径: ${scan_dirs[*]}"
    echo ""
    
    # 1. 初始化检测引擎
    # 创建临时结果文件，重置告警计数器
    detector_init
    
    # 2. 构建文件列表
    echo -e "${CYAN}[1/4] 正在遍历文件...${NC}"
    local raw_list=$(scanner_init "${scan_dirs[@]}")           # 原始文件列表（NUL 分隔）
    local filtered_list=$(scanner_filter_whitelist "$raw_list") # 白名单过滤后列表
    local files_count=0
    files_count=$(cat "$filtered_list" 2>/dev/null | tr '\0' '\n' | wc -l)  # 统计文件数
    echo -e "  ✅ 发现 ${BOLD}$files_count${NC} 个脚本文件"
    echo ""
    
    # 3. 执行扫描（并发）
    # 使用 xargs -P 并发启动 detector_scan_file 子进程
    # 每个子进程的 JSON 结果输出到独立 worker_dir 下的独立文件
    echo -e "${CYAN}[2/4] 正在执行扫描...${NC}"
    local max_jobs=${PARALLEL_JOBS:-$(nproc 2>/dev/null || echo 4)}
    [ "$max_jobs" -le 0 ] && max_jobs=4
    
    local worker_dir=$(mktemp -d)  # 临时目录，存放各子进程的 JSON 结果文件
    
    # scan_func: 通过 bash -c 在子进程中执行的扫描命令
    # 参数占位: {} = 文件名, _ = $0 占位, $worker_dir = 输出目录, $SCRIPT_DIR = 脚本根目录
    # 子进程需要重新 source detector.sh 和 config.sh 以获取函数和变量定义
    local scan_func='file="$1"; worker_id="worker_$$_$RANDOM"; out_dir="$2"; source "$3/lib/detector.sh"; source "$3/config.sh"; RULES_DIR="$3/rules"; ENTROPY_THRESHOLD='"$ENTROPY_THRESHOLD"'; MAX_FILE_SIZE='"$MAX_FILE_SIZE"'; SUSPICIOUS_SIZE_MAX='"$SUSPICIOUS_SIZE_MAX"'; SCAN_LEVEL='"$SCAN_LEVEL"'; SCAN_USE_PREFILTER='"$SCAN_USE_PREFILTER"'; detector_scan_file "$file" > "$out_dir/${worker_id}.json" 2>/dev/null'
    
    # 后台进度监控：每 0.3 秒统计已完成的任务数，实时显示进度条
    local total=$files_count
    local progress_pid=""
    if [ "$total" -gt 0 ] 2>/dev/null; then
        (
            while true; do
                processed=$(find "$worker_dir" -name "worker_*.json" 2>/dev/null | wc -l)
                pct=$(( processed * 100 / total ))
                # 构造 20 格进度条
                filled=$(( pct / 5 ))
                bar=""
                for ((i=0; i<filled; i++)); do bar+="█"; done
                for ((i=filled; i<20; i++)); do bar+="░"; done
                printf "\r  正在扫描: [%-20s] %d%% (%d/%d)" "$bar" "$pct" "$processed" "$total"
                [ "$processed" -ge "$total" ] && break
                sleep 0.3
            done
        ) &
        progress_pid=$!
    fi
    
    xargs -0 -P "$max_jobs" -I {} bash -c "$scan_func" _ {} "$worker_dir" "$SCRIPT_DIR" < "$filtered_list"
    
    # 关闭进度监控，打印最终 100% 行
    # 注意: 进度监控可能已自行退出（达到 total 后 break），
    # kill/wait 对已死进程会返回非零，加 || true 防止 set -e 中断
    if [ -n "$progress_pid" ]; then
        kill "$progress_pid" 2>/dev/null || true
        wait "$progress_pid" 2>/dev/null || true
        printf "\r  正在扫描: [████████████████████] 100%% (%d/%d)\n" "$total" "$total"
    fi
    
    # 4. 合并结果
    # 读取 worker_dir 下所有 *.json，合并为单一 JSON 数组，写入 RESULTS_FILE
    # 返回变量赋值语句如 RESULTS_CRITICAL=3 等
    echo -e "${CYAN}[3/4] 正在生成报告...${NC}"
    local results=$(detector_merge_results "$worker_dir")
    eval "$results" 2>/dev/null
    
    rm -rf "$worker_dir" 2>/dev/null  # 清理子进程临时文件
    
    # 打印各等级告警数量概览
    echo -e "  CRITICAL: ${RED}${BOLD}$RESULTS_CRITICAL${NC}"
    echo -e "  HIGH:     ${ORANGE}${BOLD}$RESULTS_HIGH${NC}"
    echo -e "  MEDIUM:   ${YELLOW}$RESULTS_MEDIUM${NC}"
    echo -e "  LOW:      ${BLUE}$RESULTS_LOW${NC}"
    echo ""
    
    # 5. 保存报告
    # json_output: 带时间戳的 JSON 报告（永久存档）
    # html_output: 带时间戳的 HTML 报告（可视化查看）
    # last_json: 固定名 JSON，用于 --report 快速查看最新结果
    # last_meta: 保存扫描时间/路径/文件数等元数据
    local json_output="$SCRIPT_DIR/$REPORT_DIR/scan_${scan_timestamp}.json"
    local html_output="$SCRIPT_DIR/$REPORT_DIR/scan_${scan_timestamp}.html"
    local last_json="$SCRIPT_DIR/$REPORT_DIR/last_scan_results.json"
    local last_meta="$SCRIPT_DIR/$REPORT_DIR/last_scan_meta.txt"
    
    cp "$RESULTS_FILE" "$json_output" 2>/dev/null
    cp "$RESULTS_FILE" "$last_json" 2>/dev/null
    
    cat > "$last_meta" << EOF
scan_time="$scan_time"
scan_dirs="${scan_dirs[*]}"
files_count="$files_count"
EOF
    
    # 6. 终端报告
    # -d/--detail: 显示完整告警详情列表；否则只输出摘要+报告路径
    echo -e "${CYAN}[4/4] 扫描完成${NC}"
    echo ""
    if [ "$SHOW_DETAIL" = "true" ]; then
        reporter_generate_terminal "$RESULTS_FILE" "$scan_time" "${scan_dirs[*]}" "$files_count"
    else
        echo -e "  扫描时间: $scan_time"
        echo -e "  扫描路径: ${scan_dirs[*]}"
        echo -e "  扫描文件: $files_count"
        echo -e "  ${YELLOW}⚠️  共 ${RESULTS_CRITICAL:-0} 条告警（严重 ${RESULTS_CRITICAL:-0} / 高危 ${RESULTS_HIGH:-0} / 中危 ${RESULTS_MEDIUM:-0}）${NC}"
        echo ""
        echo -e "     详细报告: ${CYAN}$html_output${NC}"
        echo -e "     JSON 数据: ${CYAN}$json_output${NC}"
        echo -e "     查看详情: ${CYAN}muma-scan --report${NC}"
        echo ""
    fi
    
    # 7. HTML 报告（可选）
    if [ "$HTML_REPORT" = true ]; then
        reporter_generate_html "$RESULTS_FILE" "$html_output" "$scan_time" "${scan_dirs[*]}" "$files_count"
    fi
    
    echo -e "  HTML 报告: ${CYAN}$html_output${NC}"
    echo -e "  JSON 报告: ${CYAN}$json_output${NC}"
    
    # 统计并显示总执行时间
    local elapsed=$(( $(date +%s) - start_epoch ))
    if [ "$elapsed" -ge 60 ]; then
        echo -e "  ⏱  执行时间: $(( elapsed / 60 ))分$(( elapsed % 60 ))秒"
    else
        echo -e "  ⏱  执行时间: ${elapsed}秒"
    fi
    echo ""
    
    # 8. 清理临时文件
    rm -f "$raw_list" "$filtered_list" 2>/dev/null
    detector_cleanup
    
    # 9. 清理过期报告
    # 根据 REPORT_KEEP_DAYS 删除超过保留天数的历史报告文件
    find "$SCRIPT_DIR/$REPORT_DIR" -name "scan_*.json" -mtime +"$REPORT_KEEP_DAYS" -delete 2>/dev/null
    find "$SCRIPT_DIR/$REPORT_DIR" -name "scan_*.html" -mtime +"$REPORT_KEEP_DAYS" -delete 2>/dev/null
}

# ---------- 命令行参数解析 ----------
# CUSTOM_PATHS: 存储 -p/--path 指定的自定义扫描路径
# MODE: 当前操作模式（full/quick/report/list/cleanup/空=默认）
CUSTOM_PATHS=()
MODE=""

while [ $# -gt 0 ]; do
    case "$1" in
        -f|--full)
            MODE="full"       # 全盘扫描：使用 SCAN_DIRS 配置
            shift
            ;;
        -q|--quick)
            # 快速模式：仅使用 CRITICAL 级别规则 + 启用预过滤
            # 不影响扫描路径，可配合 -p 或 --full 使用
            SCAN_LEVEL="${SCAN_LEVEL:-CRITICAL}"
            SCAN_USE_PREFILTER="${SCAN_USE_PREFILTER:-true}"
            shift
            ;;
        -p|--path)
            shift
            [ -z "$1" ] && { echo "错误: --path 需要指定目录路径"; exit 1; }
            CUSTOM_PATHS+=("$1")   # 支持多次 -p 累积多个路径
            shift
            ;;
        -r|--report)
            MODE="report"     # 查看上次扫描报告
            shift
            ;;
        -l|--list)
            MODE="list"       # 列出隔离区文件
            shift
            ;;
        -c|--cleanup)
            MODE="cleanup"    # 清理隔离区
            shift
            ;;
        -n|--recent)
            shift
            [ -z "$1" ] && { echo "错误: --recent 需要指定天数"; exit 1; }
            SCAN_RECENT_DAYS="$1"   # 增量扫描：仅扫描最近 N 天修改的文件
            shift
            ;;
        -t|--type)
            shift
            [ -z "$1" ] && { echo "错误: --type 需要指定文件类型，如 php / php,jsp"; exit 1; }
            SCAN_TYPES="$1"         # 文件类型过滤，如 "php" / "php,jsp,asp"
            shift
            ;;
        -L|--level)
            shift
            [ -z "$1" ] && { echo "错误: --level 需要指定级别 (CRITICAL/HIGH/ALL)"; exit 1; }
            case "$(echo "$1" | tr '[:lower:]' '[:upper:]')" in
                CRITICAL|HIGH|ALL) SCAN_LEVEL=$(echo "$1" | tr '[:lower:]' '[:upper:]') ;;
                *) echo "错误: 无效级别 $1，可选：CRITICAL / HIGH / ALL"; exit 1 ;;
            esac
            shift
            ;;
        -d|--detail)
            SHOW_DETAIL="true"    # 显示完整的告警详情列表
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "未知选项: $1"
            echo "使用 -h 查看帮助"
            exit 1
            ;;
    esac
done

# ---------- 权限检查 ----------
# 非 root 用户可能无法读取 /proc、/etc 等目录，给出警告但不阻止
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${YELLOW}⚠️  警告: 非 root 用户运行，部分目录可能无法访问${NC}"
    echo -e "  建议使用: sudo $0 ${BASH_ARGV[*]}"
    echo ""
fi

# ---------- 根据 MODE 分发执行 ----------
case "$MODE" in
    full)
        run_scan "${SCAN_DIRS[@]}"
        ;;
    report)
        show_report
        ;;
    list)
        quarantine_list "$QUARANTINE_DIR"
        ;;
    cleanup)
        echo -e "${YELLOW}清理隔离区: ${QUARANTINE_DIR}${NC}"
        rm -rf "${QUARANTINE_DIR:?}/"*
        echo "  ✅ 已清理"
        ;;
    *)
        # 默认情况下：若有 -p 路径则扫描自定义路径，否则启动快速扫描
        if [ ${#CUSTOM_PATHS[@]} -gt 0 ]; then
            run_scan "${CUSTOM_PATHS[@]}"
        else
            run_scan "/var/www" "/home"
        fi
        ;;
esac
