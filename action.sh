#!/system/bin/sh
# =====================================================================
# 🎬 action.sh - 模块操作入口脚本
# ---------------------------------------------------------------------
# 一键启动/停止代理核心主程序及防火墙规则
# =====================================================================

set -e

MODDIR=$(dirname "$0")
. "$MODDIR/common.sh"

log_safe "❤️ === [action] === ❤️"
log_safe "🎬 正在切换服务状态..."

[ -x "$SERVICE" ] || abort_safe "❌ 服务 $(basename "$SERVICE") 不可执行, 操作中止"

if [ -f "$FLAG" ]; then
  log_safe "⛔ 服务已运行, 正在停止..."
  sh "$SERVICE" stop >/dev/null 2>&1 || abort_safe "❌ 服务 $(basename "$SERVICE") 停止失败"
  log_safe "✅ 服务 $(basename "$SERVICE") 停止成功"
else
  log_safe "🚀 服务未运行, 正在启动..."
  sh "$SERVICE" >/dev/null 2>&1 || log_safe "❌ 服务 $(basename "$SERVICE") 启动失败"
  log_safe "✅ 服务 $(basename "$SERVICE") 启动成功"
fi