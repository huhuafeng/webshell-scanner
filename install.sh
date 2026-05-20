#!/bin/bash
# ============================================
# 一键安装脚本 - 下载并运行木马扫描器
# 用法：
#   curl -sSL https://raw.githubusercontent.com/huhuafeng/webshell-scanner/master/install.sh | sudo bash
#   或
#   wget -qO- https://raw.githubusercontent.com/huhuafeng/webshell-scanner/master/install.sh | sudo bash
# ============================================

set -e

echo "========================================"
echo "  🛡️  MUMA SCAN - 一键安装"
echo "========================================"
echo ""

INSTALL_DIR="/opt/webshell-scanner"
REPO_URL="https://github.com/huhuafeng/webshell-scanner.git"

# 检查依赖
echo "[1/3] 检查依赖..."
for cmd in git bash python3 file find xargs stat grep bc; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "  ❌ 缺少依赖: $cmd"
        echo "  请先安装: apt install -y $cmd"
        exit 1
    fi
done
echo "  ✅ 依赖检查通过"
echo ""

# 克隆仓库
echo "[2/3] 下载项目..."
if [ -d "$INSTALL_DIR" ]; then
    echo "  ⚠️  目标目录已存在，更新中..."
    cd "$INSTALL_DIR" && git pull
else
    git clone --depth=1 "$REPO_URL" "$INSTALL_DIR"
fi
echo "  ✅ 下载完成: $INSTALL_DIR"
echo ""

# 设置权限
echo "[3/3] 设置执行权限..."
chmod +x "$INSTALL_DIR/scan.sh"
chmod +x "$INSTALL_DIR/lib/"*.sh

# 创建全局软链接
ln -sf "$INSTALL_DIR/scan.sh" /usr/local/bin/muma-scan
echo "  ✅ 已创建全局命令: muma-scan"
echo ""

echo "========================================"
echo "  🎉 安装成功！"
echo "========================================"
echo ""
echo "现在可以直接使用 muma-scan 命令："
echo ""
echo "快速扫描:"
echo "  sudo muma-scan --quick"
echo ""
echo "全盘扫描:"
echo "  sudo muma-scan --full"
echo ""
echo "扫描指定目录:"
echo "  sudo muma-scan --path /var/www/html"
echo ""
echo "增量扫描（仅最近 7 天）:"
echo "  sudo muma-scan --full -n 7"
echo ""
echo "查看帮助:"
echo "  muma-scan --help"
echo ""
echo "查看报告:"
echo "  muma-scan --report"
echo ""
echo "------------------------"
echo "安装路径: $INSTALL_DIR"
echo "卸载: rm -rf $INSTALL_DIR /usr/local/bin/muma-scan"
echo ""
