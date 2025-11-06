#!/system/bin/sh
# =====================================================================
# 📥 update-bin.sh - 核心程序自动更新脚本
# =====================================================================

set -e

MODDIR=$(dirname "$0")
. "$MODDIR/common.sh"

BIN_REPO="$1"

log_safe "✨ === [update-bin] === ✨"
log_safe "🚀 开始更新代理核心..."

# --- 架构检测 ---
case $(getprop ro.product.cpu.abi) in
arm64-v8a) ARCHITECTURE="android-arm64" ;;
armeabi-v7a) ARCHITECTURE="android-armv7" ;;
x86_64) ARCHITECTURE="android-amd64" ;;
x86) ARCHITECTURE="android-386" ;;
*)
  ARCHITECTURE=""
  log_safe "🤔 未知CPU架构, 将依赖远程匹配"
  ;;
esac
[ -n "$ARCHITECTURE" ] && log_safe "💻 检测到 CPU 架构: $ARCHITECTURE"

# --- 备份旧核心 ---
if [ -f "$BIN_PATH" ]; then
  cp -p "$BIN_PATH" "${BIN_PATH}.bak" 2>/dev/null || true
  log_safe "📝 已备份当前核心到 ${BIN_PATH}.bak"
fi

# --- 调用 fetch-core.sh ---
sh "$MODDIR/fetch-core.sh" "$BIN_REPO" "$BIN_NAME" "$ARCHITECTURE" "$BIN_PATH" || {
  log_safe "❌ 核心更新失败"
  # 如果更新失败, 尝试恢复备份
  if [ -f "${BIN_PATH}.bak" ]; then
    mv "${BIN_PATH}.bak" "$BIN_PATH"
    log_safe "🔄 已从备份恢复"
  fi
  exit 1
}

log_safe "✨ 代理核心更新成功"
