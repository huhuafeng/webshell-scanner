#!/bin/bash
# ============================================
# MUMA SCAN - 网站木马一键扫描器
# 用法: ./scan.sh [OPTIONS]
# ============================================

set -e

# ---------- 基础设置 ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"
RULES_DIR="$SCRIPT_DIR/rules"

# ---------- 加载模块 ----------
source "$SCRIPT_DIR/config.sh"
source "$LIB_DIR/scanner.sh"
source "$LIB_DIR/detector.sh"
source "$LIB_DIR/reporter.sh"
source "$LIB_DIR/quarantine.sh"

# ---------- 创建输出目录 ----------
mkdir -p "$SCRIPT_DIR/$REPORT_DIR" 2>/dev/null
QUARANTINE_DIR=$(quarantine_init)

# ---------- 颜色 ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# ---------- 使用帮助 ----------
function show_help() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -f, --full        全盘扫描（默认扫描 SCAN_DIRS 中的所有目录）"
    echo "  -q, --quick       快速扫描（仅扫描 /var/www 和 /home 中的 Web 目录）"
    echo "  -p, --path DIR    指定扫描路径（可重复使用）"
    echo "  -r, --report      查看上次扫描报告"
    echo "  -c, --cleanup     清理隔离区"
    echo "  -l, --list        列出隔离区文件"
    echo "  -h, --help        显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 --full                 全盘扫描"
    echo "  $0 --quick                快速扫描"
    echo "  $0 --path /var/www/html   扫描指定路径"
    echo "  $0 --path /www -p /blog   扫描多个指定路径"
    echo "  $0 --report               查看上次扫描报告"
    exit 0
}

# ---------- 查看报告 ----------
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
function run_scan() {
    local scan_dirs=("$@")
    
    local scan_time=$(date '+%Y-%m-%d %H:%M:%S')
    local scan_timestamp=$(date '+%Y%m%d_%H%M%S')
    
    echo -e "${CYAN}${BOLD}🛡️  MUMA SCAN - 网站木马扫描器${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  扫描时间: $scan_time"
    echo -e "  扫描路径: ${scan_dirs[*]}"
    echo ""
    
    # 1. 初始化检测引擎
    detector_init
    
    # 2. 构建文件列表
    echo -e "${CYAN}[1/4] 正在遍历文件...${NC}"
    local raw_list=$(scanner_init "${scan_dirs[@]}")
    local filtered_list=$(scanner_filter_whitelist "$raw_list")
    local files_count=0
    files_count=$(cat "$filtered_list" 2>/dev/null | tr '\0' '\n' | wc -l)
    echo -e "  ✅ 发现 ${BOLD}$files_count${NC} 个脚本文件"
    echo ""
    
    # 3. 执行扫描（并发）
    echo -e "${CYAN}[2/4] 正在执行扫描...${NC}"
    local max_jobs=${PARALLEL_JOBS:-$(nproc 2>/dev/null || echo 4)}
    [ "$max_jobs" -le 0 ] && max_jobs=4
    
    # 创建临时目录存放子进程结果
    local worker_dir=$(mktemp -d)
    
    local scan_func='file="$1"; worker_id="worker_$$_$RANDOM"; out_dir="$2"; source "$3/lib/detector.sh"; source "$3/config.sh"; RULES_DIR="$3/rules"; ENTROPY_THRESHOLD='"$ENTROPY_THRESHOLD"'; MAX_FILE_SIZE='"$MAX_FILE_SIZE"'; SUSPICIOUS_SIZE_MAX='"$SUSPICIOUS_SIZE_MAX"'; detector_scan_file "$file" > "$out_dir/${worker_id}.json" 2>/dev/null'
    
    xargs -0 -P "$max_jobs" -I {} bash -c "$scan_func" _ {} "$worker_dir" "$SCRIPT_DIR" < "$filtered_list"
    
    # 4. 合并结果
    echo -e "${CYAN}[3/4] 正在生成报告...${NC}"
    local results=$(detector_merge_results "$worker_dir")
    eval "$results" 2>/dev/null
    
    # 清理工作目录
    rm -rf "$worker_dir" 2>/dev/null
    
    echo -e "  CRITICAL: ${RED}${BOLD}$RESULTS_CRITICAL${NC}"
    echo -e "  HIGH:     ${ORANGE}${BOLD}$RESULTS_HIGH${NC}"
    echo -e "  MEDIUM:   ${YELLOW}$RESULTS_MEDIUM${NC}"
    echo -e "  LOW:      ${BLUE}$RESULTS_LOW${NC}"
    echo ""
    
    # 5. 保存报告
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
    echo -e "${CYAN}[4/4] 扫描完成${NC}"
    echo ""
    reporter_generate_terminal "$RESULTS_FILE" "$scan_time" "${scan_dirs[*]}" "$files_count"
    
    # 7. HTML 报告
    if [ "$HTML_REPORT" = true ]; then
        reporter_generate_html "$RESULTS_FILE" "$html_output" "$scan_time" "${scan_dirs[*]}" "$files_count"
        echo -e "  HTML 报告: ${CYAN}$html_output${NC}"
    fi
    
    echo -e "  JSON 报告: ${CYAN}$json_output${NC}"
    echo ""
    
    # 8. 清理临时文件
    rm -f "$raw_list" "$filtered_list" 2>/dev/null
    detector_cleanup
    
    # 9. 清理过期报告
    find "$SCRIPT_DIR/$REPORT_DIR" -name "scan_*.json" -mtime +"$REPORT_KEEP_DAYS" -delete 2>/dev/null
    find "$SCRIPT_DIR/$REPORT_DIR" -name "scan_*.html" -mtime +"$REPORT_KEEP_DAYS" -delete 2>/dev/null
}

# ---------- 参数解析 ----------
CUSTOM_PATHS=()
MODE=""

while [ $# -gt 0 ]; do
    case "$1" in
        -f|--full)
            MODE="full"
            shift
            ;;
        -q|--quick)
            MODE="quick"
            shift
            ;;
        -p|--path)
            shift
            [ -z "$1" ] && { echo "错误: --path 需要指定目录路径"; exit 1; }
            CUSTOM_PATHS+=("$1")
            shift
            ;;
        -r|--report)
            MODE="report"
            shift
            ;;
        -l|--list)
            MODE="list"
            shift
            ;;
        -c|--cleanup)
            MODE="cleanup"
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

# 检查 root 权限
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${YELLOW}⚠️  警告: 非 root 用户运行，部分目录可能无法访问${NC}"
    echo -e "  建议使用: sudo $0 ${BASH_ARGV[*]}"
    echo ""
fi

case "$MODE" in
    full)
        run_scan "${SCAN_DIRS[@]}"
        ;;
    quick)
        run_scan "/var/www" "/home"
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
        # 如果指定了自定义路径
        if [ ${#CUSTOM_PATHS[@]} -gt 0 ]; then
            run_scan "${CUSTOM_PATHS[@]}"
        else
            # 默认快速扫描
            run_scan "/var/www" "/home"
        fi
        ;;
esac
