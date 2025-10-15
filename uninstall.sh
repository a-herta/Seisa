#!/system/bin/sh
# =====================================================================
# 🧹 uninstall.sh - 卸载清理脚本
# =====================================================================

set -e

MODDIR=$(dirname "$0")
. "$MODDIR/common.sh"

log_safe "✨ === [uninstall] ==="
log_safe "🗑️ 开始卸载清理..."

# 1. 尝试通过 service.sh 优雅地停止服务
if [ -x "$SERVICE" ]; then
  sh "$SERVICE" stop >/dev/null 2>&1 || log_safe "❓ 服务可能未完全停止"
fi

# 2. 使用 pkill 终止所有残留的核心进程, 确保无遗漏
if command -v pkill >/dev/null 2>&1; then
  log_safe "🔍 终止残留的 '$BIN_NAME' 进程..."
  pkill -9 -f "$BIN_NAME.*$MODID" 2>/dev/null || true
fi

# 3. 再次尝试直接调用规则脚本清理网络规则, 作为最终保障
if [ -x "$TPROXY" ]; then
  sh "$TPROXY" stop >/dev/null 2>&1 || log_safe "❓ 网络规则可能未完全清理"
fi

log_safe "✅ 卸载清理完毕"

rm -rf "$PERSIST_DIR"
