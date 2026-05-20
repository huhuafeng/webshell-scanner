#!/bin/bash
# ============================================
# 报告生成器 - 终端/HTML/JSON 输出
# 功能：读取合并后的 JSON 结果文件，生成三种格式输出：
#   1. 终端彩色表格（带告警级别颜色标记）
#   2. HTML 报告（可视化仪表板，含摘要卡片和排序表格）
#   3. JSON 原始数据（透传检测结果，供外部工具消费）
# ============================================

# ---------- 颜色定义 ----------
# 终端输出的 ANSI 颜色转义码，与 scan.sh 中的颜色变量对齐
RED='\033[0;31m'
YELLOW='\033[1;33m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# ---------- 打印启动横幅 ----------
# reporter_print_banner: 输出扫描器的 ASCII 艺术标题（红色边框）。
# 参数：无
function reporter_print_banner() {
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║     🛡️  MUMA SCAN - 网站木马扫描器 v1.0    ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════╝${NC}"
    echo ""
}

# ---------- 告警级别着色 ----------
# reporter_level_color: 根据级别返回带颜色的级别名称字符串。
# 参数: $1 — 级别名称 (CRITICAL/HIGH/MEDIUM/LOW)
# 返回：带 ANSI 转义码的着色字符串
function reporter_level_color() {
    case "$1" in
        CRITICAL) echo -e "${RED}${BOLD}CRITICAL${NC}" ;;
        HIGH)     echo -e "${ORANGE}${BOLD}HIGH${NC}" ;;
        MEDIUM)   echo -e "${YELLOW}MEDIUM${NC}" ;;
        LOW)      echo -e "${BLUE}LOW${NC}" ;;
        *)        echo "$1" ;;
    esac
}

# ---------- 终端报告生成 ----------
# reporter_generate_terminal: 读取 JSON 结果，输出带颜色格式的终端报告。
# 报告包含：启动横幅 → 扫描基本信息 → 告警摘要统计 → 逐条告警详情。
# 参数:
#   $1 - results_file: 合并后的 JSON 结果文件路径
#   $2 - scan_time: 扫描开始时间（字符串）
#   $3 - scan_dirs: 扫描路径（字符串，空格分隔）
#   $4 - files_count: 扫描文件总数（整数）
function reporter_generate_terminal() {
    local results_file="$1"
    local scan_time="$2"
    local scan_dirs="$3"
    local files_count="$4"
    
    reporter_print_banner
    
    echo -e "${CYAN}[基本信息]${NC}"
    echo -e "  扫描时间:   $scan_time"
    echo -e "  扫描路径:   $scan_dirs"
    echo -e "  扫描文件数: $files_count"
    echo ""
    
    # 读取结果总数，判断是否有告警
    local count=$(python3 -c "
import json, sys
with open('$results_file') as f:
    data = json.load(f)
print(len(data))
" 2>/dev/null)
    
    if [ "$count" -eq 0 ] 2>/dev/null; then
        echo -e "${GREEN}✅ 未发现可疑文件，服务器状态良好。${NC}"
        echo ""
        return
    fi
    
    # 获取各级别告警数量
    eval "$(python3 -c "
import json, sys
with open('$results_file') as f:
    data = json.load(f)
crit = sum(1 for x in data if x['level']=='CRITICAL')
high = sum(1 for x in data if x['level']=='HIGH')
med = sum(1 for x in data if x['level']=='MEDIUM')
low = sum(1 for x in data if x['level']=='LOW')
print(f'CRIT={crit};HIGH={high};MED={med};LOW={low};TOTAL={len(data)}')
" 2>/dev/null)"
    
    # 输出摘要统计（只有非零的级别才显示）
    echo -e "${CYAN}[扫描结果摘要]${NC}"
    [ "$CRIT" -gt 0 ] && echo -e "  ${RED}${BOLD}严重 (CRITICAL): $CRIT${NC}"
    [ "$HIGH" -gt 0 ] && echo -e "  ${ORANGE}${BOLD}高危 (HIGH):     $HIGH${NC}"
    [ "$MED" -gt 0 ] && echo -e "  ${YELLOW}中危 (MEDIUM):   $MED${NC}"
    [ "$LOW" -gt 0 ] && echo -e "  ${BLUE}低危 (LOW):      $LOW${NC}"
    echo -e "  ${BOLD}总计: $TOTAL 条告警${NC}"
    echo ""
    
    # 输出详细告警列表（按级别排序 → 按文件路径排序 → 按行号排序）
    echo -e "${CYAN}[详细告警列表]${NC}"
    local HOME_DIR="$HOME"
    python3 -c "
import json, sys, os

with open('$results_file') as f:
    data = json.load(f)

lvls = {'CRITICAL':0, 'HIGH':1, 'MEDIUM':2, 'LOW':3}
data.sort(key=lambda x: (lvls.get(x['level'], 99), x['file'], x['line']))

home = '$HOME_DIR'
color_map = {
    'CRITICAL': '\033[0;31m\033[1mCRITICAL\033[0m',
    'HIGH':     '\033[0;33m\033[1mHIGH\033[0m',
    'MEDIUM':   '\033[1;33mMEDIUM\033[0m',
    'LOW':      '\033[0;34mLOW\033[0m',
}
CYAN = '\033[0;36m'
BOLD = '\033[1m'
NC = '\033[0m'

for r in data:
    lv = color_map.get(r['level'], r['level'])
    f = r['file'].replace(home, '~')
    ctx = r.get('context', '')[:120]
    print(f'  [{lv}] {BOLD}{r[\"rule\"]}{NC}')
    print(f'        文件: {CYAN}{f}{NC}:{r.get(\"line\",0)}')
    print(f'        描述: {r[\"desc\"]}')
    if ctx:
        print(f'        内容: {ctx}')
    print()
" 2>/dev/null
    
    echo ""
    echo -e "${YELLOW}⚠️  以上告警需人工确认。怀疑文件已自动备份至隔离区。${NC}"
    echo ""
}

# ---------- HTML 报告生成 ----------
# reporter_generate_html: 读取 JSON 结果，生成自包含的 HTML 报告页面。
# 页面包含：渐变色标题区 → 摘要卡片 → 排序表格（含着色级别徽标）。
# 参数:
#   $1 - rf: 结果 JSON 文件路径
#   $2 - of: 输出 HTML 文件路径
#   $3 - st: 扫描时间（字符串）
#   $4 - sd: 扫描路径（字符串）
#   $5 - fc: 扫描文件数（整数）
function reporter_generate_html() {
    local rf="$1"
    local of="$2"
    local st="$3"
    local sd="$4"
    local fc="$5"
    
    python3 -c "
import json, html, sys

# 从 bash 传入的变量
scan_time = '$st'
scan_dirs_txt = '$sd'
file_count = '$fc'
home_dir = '$HOME'

with open('$rf') as f:
    results = json.load(f)

# 排序：先按级别（CRITICAL 排最前），再按路径和行号
lvls = {'CRITICAL':0, 'HIGH':1, 'MEDIUM':2, 'LOW':3}
results.sort(key=lambda x: (lvls.get(x['level'], 99), x['file'], x['line']))

# 统计各级别数量
crit = sum(1 for x in results if x['level']=='CRITICAL')
high = sum(1 for x in results if x['level']=='HIGH')
med = sum(1 for x in results if x['level']=='MEDIUM')
low = sum(1 for x in results if x['level']=='LOW')
total = len(results)

# 构建表格行 HTML
rows = ''
for r in results:
    f = r['file']
    ctx = html.escape(r.get('context','')[:200])
    desc = html.escape(r['desc'])
    rows += '<tr class=\"' + r['level'].lower() + '\">'
    rows += '<td><span class=\"badge badge-' + r['level'].lower() + '\">' + r['level'] + '</span></td>'
    rows += '<td>' + html.escape(r['rule']) + '</td>'
    rows += '<td title=\"' + html.escape(f) + '\">' + f.replace(home_dir, '~') + '</td>'
    rows += '<td class=\"line\">' + str(r.get('line','-')) + '</td>'
    rows += '<td>' + desc + '</td></tr>'

st_escaped = html.escape(scan_time)
sd_escaped = html.escape(scan_dirs_txt)

html_content = f'''<!DOCTYPE html>
<html lang=\"zh-CN\">
<head>
<meta charset=\"UTF-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
<title>木马扫描报告 - {st_escaped}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system, Microsoft YaHei, sans-serif; background:#f5f6fa; padding:20px; color:#333; }}
.header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color:#fff; padding:30px; border-radius:10px; margin-bottom:20px; }}
.header h1 {{ font-size:24px; margin-bottom:10px; }}
.header p {{ opacity:0.9; font-size:14px; }}
.summary {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(120px,1fr)); gap:15px; margin-bottom:20px; }}
.summary-item {{ background:#fff; padding:20px; border-radius:8px; text-align:center; box-shadow:0 2px 4px rgba(0,0,0,0.1); }}
.summary-item .num {{ font-size:32px; font-weight:bold; }}
.summary-item .label {{ font-size:13px; color:#666; margin-top:5px; }}
.critical .num {{ color:#e74c3c; }}
.high .num {{ color:#e67e22; }}
.medium .num {{ color:#f1c40f; }}
.low .num {{ color:#3498db; }}
.total .num {{ color:#9b59b6; }}
table {{ width:100%; background:#fff; border-radius:8px; overflow:hidden; box-shadow:0 2px 4px rgba(0,0,0,0.1); }}
th {{ background:#2c3e50; color:#fff; padding:12px 15px; text-align:left; font-size:13px; }}
td {{ padding:10px 15px; border-bottom:1px solid #eee; font-size:13px; word-break:break-all; }}
tr:hover td {{ background:#f8f9fa; }}
tr.critical td {{ border-left:3px solid #e74c3c; }}
tr.high td {{ border-left:3px solid #e67e22; }}
tr.medium td {{ border-left:3px solid #f1c40f; }}
tr.low td {{ border-left:3px solid #3498db; }}
.badge {{ display:inline-block; padding:2px 8px; border-radius:3px; color:#fff; font-size:11px; font-weight:bold; }}
.badge-critical {{ background:#e74c3c; }}
.badge-high {{ background:#e67e22; }}
.badge-medium {{ background:#f1c40f; color:#333; }}
.badge-low {{ background:#3498db; }}
.line {{ text-align:center; color:#999; font-family:monospace; }}
.footer {{ text-align:center; color:#999; font-size:12px; margin-top:20px; padding:20px; }}
</style>
</head>
<body>
<div class=\"header\">
    <h1>网站木马扫描报告</h1>
    <p>扫描时间: {st_escaped} | 扫描路径: {sd_escaped} | 扫描文件: {file_count}</p>
</div>
<div class=\"summary\">
    <div class=\"summary-item critical\"><div class=\"num\">{crit}</div><div class=\"label\">严重</div></div>
    <div class=\"summary-item high\"><div class=\"num\">{high}</div><div class=\"label\">高危</div></div>
    <div class=\"summary-item medium\"><div class=\"num\">{med}</div><div class=\"label\">中危</div></div>
    <div class=\"summary-item low\"><div class=\"num\">{low}</div><div class=\"label\">低危</div></div>
    <div class=\"summary-item total\"><div class=\"num\">{total}</div><div class=\"label\">总计</div></div>
</div>
<table>
<thead><tr><th>级别</th><th>规则</th><th>文件</th><th>行号</th><th>描述</th></tr></thead>
<tbody>{rows}</tbody>
</table>
<div class=\"footer\">Muma Scan v1.0 - Generated automatically</div>
</body>
</html>'''

with open('$of', 'w', encoding='utf-8') as f:
    f.write(html_content)
print('HTML report generated: $of')
" 2>/dev/null
}
