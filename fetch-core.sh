#!/system/bin/sh
# =====================================================================
# 📥 fetch-core.sh - 智能下载代理核心的脚本
# =====================================================================

set -e

MODDIR=$(dirname "$0")
. "$MODDIR/common.sh"

# --- 输入参数校验 ---
if [ "$#" -lt 3 ]; then
  echo "::error::用法: $0 <repo> <bin_name> <arch> <output_path>" >&2
  exit 1
fi

BIN_REPO="$1"
BIN_NAME="$2"
ARCHITECTURE="$3"
OUTPUT_PATH="$4"

MAX_RETRIES=${MAX_RETRIES:-3}
RETRY_DELAY=${RETRY_DELAY:-5}
TMPDIR=$(mktemp -d "${PERSIST_DIR}/.tmp.XXXXXX" 2>/dev/null || mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# --- 函数 ---
log_safe() {
  echo "$@" >&2
}

# 带重试的 curl
retry_curl() {
  url="$1" output_path="$2" count=0
  while [ "$count" -lt "$MAX_RETRIES" ]; do
    if [ -n "$AUTH_HDR" ]; then
      curl -sSL -H "Accept: application/vnd.github.v3+json" -H "$AUTH_HDR" "$url" -o "$output_path" && [ -s "$output_path" ] && return 0
    else
      curl -sSL -H "Accept: application/vnd.github.v3+json" "$url" -o "$output_path" && [ -s "$output_path" ] && return 0
    fi
    count=$((count + 1))
    [ "$count" -ge "$MAX_RETRIES" ] && log_safe "❌ 下载失败: $url" && return 1
    log_safe "⏳ 下载失败, $RETRY_DELAY 秒后重试 ($count/$MAX_RETRIES)..."
    sleep "$RETRY_DELAY"
  done
}

# 递归解压, 直到找到目标二进制文件或无法再解压
decompress_recursively() {
  file_path="$1"
  target_dir="$2"
  found_path=""

  while true; do
    # 检查当前目录下是否已存在目标文件
    found_path=$(find "$target_dir" -type f -iname "$BIN_NAME" | head -n 1)
    [ -n "$found_path" ] && echo "$found_path" && return 0

    # 寻找下一个需要解压的文件
    if file "$file_path" | grep -qi 'gzip compressed data'; then
      compressed_file="$file_path"
      log_safe "🗜️ tar.gz 压缩包, 解压中..."
      # 创建一个临时子目录来解压, 避免文件名冲突
      sub_dir=$(mktemp -d "$target_dir/decompress.XXXXXX")
      tar -xzf "$compressed_file" -C "$sub_dir"
      # 删除已解压的压缩包, 以便下次循环处理新文件
      rm -f "$compressed_file"
      # 更新 file_path 为新解压出的目录, 以便下次循环
      file_path="$sub_dir"
    elif file "$file_path" | grep -qi 'Zip archive data'; then
      compressed_file="$file_path"
      log_safe "🗜️ zip 压缩包, 解压中..."
      sub_dir=$(mktemp -d "$target_dir/decompress.XXXXXX")
      unzip -o "$compressed_file" -d "$sub_dir" >/dev/null 2>&1
      rm -f "$compressed_file"
      file_path="$sub_dir"
    else
      # 如果目录中还有其他压缩文件, 递归处理
      next_archive=$(find "$target_dir" -type f \( -name "*.zip" -o -name "*.tar.gz" -o -name "*.gz" \) | head -n 1)
      if [ -n "$next_archive" ]; then
        file_path="$next_archive"
        continue
      fi
      # 没有任何可解压的文件了
      break
    fi
  done

  # 再次在整个解压目录中寻找目标文件
  found_path=$(find "$target_dir" -type f -iname "$BIN_NAME" | head -n 1)
  [ -n "$found_path" ] && echo "$found_path" && return 0

  return 1
}

# --- 主逻辑 ---

log_safe "✨ === [fetch-core] === ✨"
log_safe "🚀 开始获取核心: $BIN_REPO"
log_safe "💻 目标架构: ${ARCHITECTURE:-'自动匹配'}"
log_safe "📛 目标二进制: $BIN_NAME"

# GitHub Token
if [ -f "$PERSIST_DIR/github_token" ]; then
  GHTOKEN=$(tr -d '\r\n' <"$PERSIST_DIR/github_token" 2>/dev/null)
  [ -n "$GHTOKEN" ] && AUTH_HDR="Authorization: token $GHTOKEN"
fi

# --- 解析 BIN_REPO ---
# 格式: workflow@owner/repo/branch 或 owner/repo
IS_WORKFLOW=false
if echo "$BIN_REPO" | grep -q '@'; then
  IS_WORKFLOW=true
  WORKFLOW_BRANCH=$(echo "$BIN_REPO" | cut -d'/' -f3)
  REPO_SLUG=$(echo "$BIN_REPO" | cut -d'@' -f2 | cut -d'/' -f1,2)
  API_URL_BASE="https://api.github.com/repos/${REPO_SLUG}"
  log_safe "🌀 工作流模式: 从 ${REPO_SLUG} 的 ${WORKFLOW_BRANCH} 分支获取"
else
  REPO_SLUG="$BIN_REPO"
  API_URL_BASE="https://api.github.com/repos/${REPO_SLUG}"
  log_safe "🏷️ Release 模式: 从 ${REPO_SLUG} 获取"
fi

# --- 寻找下载链接 ---
ASSET_URL=""

if [ "$IS_WORKFLOW" = "true" ]; then
  # --- 模式一: 从 GitHub Actions Artifacts 下载 ---
  log_safe "📡 查询最新的成功工作流..."
  WORKFLOWS_API="${API_URL_BASE}/actions/runs?branch=${WORKFLOW_BRANCH}&status=success&per_page=1"
  retry_curl "$WORKFLOWS_API" "$TMPDIR/workflows.json" || exit 1

  LATEST_RUN_ID=$(grep -o '"id": *[0-9]*' "$TMPDIR/workflows.json" | head -n 1 | grep -o '[0-9]*')
  [ -z "$LATEST_RUN_ID" ] && log_safe "❌ 未找到任何成功的工作流运行" && exit 1
  log_safe "✅ 找到最新成功的工作流运行 ID: $LATEST_RUN_ID"

  ARTIFACTS_API="${API_URL_BASE}/actions/runs/${LATEST_RUN_ID}/artifacts"
  retry_curl "$ARTIFACTS_API" "$TMPDIR/artifacts.json" || exit 1

  log_safe "🔗 解析构建产物下载链接..."
  # 优先匹配架构, 其次匹配通用名称
  # 将单行 JSON 拆分为多行, 更易于 grep 处理
  ARTIFACT_LIST=$(sed 's/},{/}\n{/g' "$TMPDIR/artifacts.json")

  # 优先匹配架构
  ASSET_URL=$(echo "$ARTIFACT_LIST" | grep -i '"name":"[^"]*'"$ARCHITECTURE"'["]*"' | sed 's/.*\"archive_download_url\":\"\([^\"]*\)\".*/\1/' | head -n 1)
  # 其次匹配通用名称
  [ -z "$ASSET_URL" ] && ASSET_URL=$(echo "$ARTIFACT_LIST" | grep -i '"name":"[^"]*'"$BIN_NAME"'["]*"' | sed 's/.*\"archive_download_url\":\"\([^\"]*\)\".*/\1/' | head -n 1)

else
  # --- 模式二: 从 GitHub Releases 下载 ---
  log_safe "📡 查询最新的 Release..."
  JSON_FILE="$TMPDIR/release.json"
  RELEASE_API="$API_URL_BASE/releases/latest"
  retry_curl "$RELEASE_API" "$JSON_FILE" || {
    log_safe "⚠️ 获取最新 Release 失败, 尝试获取所有 Release 列表..."
    JSON_FILE="$TMPDIR/releases.json"
    RELEASE_API="$API_URL_BASE/releases"
    retry_curl "$RELEASE_API" "$JSON_FILE" || exit 1
  }

  log_safe "🔗 解析 Release 资源下载链接..."
  ALL_URLS=$(grep -o '"browser_download_url":"[^"]*"' "$JSON_FILE" | awk -F '"' '{print $4}')
  ASSET_URL=$(echo "$ALL_URLS" | awk -v arch="$ARCHITECTURE" 'tolower($0) ~ tolower(arch) { print; exit }')
  [ -z "$ASSET_URL" ] && ASSET_URL=$(echo "$ALL_URLS" | awk -v name="$BIN_NAME" 'tolower($0) ~ tolower(name) { print; exit }')
  [ -z "$ASSET_URL" ] && ASSET_URL=$(echo "$ALL_URLS" | head -n 1) # 最后手段, 拿第一个
fi

[ -z "$ASSET_URL" ] && log_safe "❌ 未找到任何合适的下载链接" && exit 1
log_safe "✅ 确定下载链接: $ASSET_URL"

# --- 下载与解压 ---
FNAME="$TMPDIR/asset.download"
log_safe "📥 正在下载..."
retry_curl "$ASSET_URL" "$FNAME" || exit 1

log_safe "📦 下载完成, 开始智能解压..."
BPATH=$(decompress_recursively "$FNAME" "$TMPDIR")

[ -z "$BPATH" ] && log_safe "❌ 在下载的资源中未找到目标文件: $BIN_NAME" && exit 1

# --- 验证与安装 ---
log_safe "✅ 找到目标文件: $BPATH"
chmod 755 "$BPATH"
VER=$("$BPATH" version 2>/dev/null | awk '/version/ {sub(/.*version /, ""); sub(/^v/, ""); print $1}')
[ -n "$VER" ] && log_safe "ℹ️ 核心版本: $VER"

mv "$BPATH" "$OUTPUT_PATH"
chmod 755 "$OUTPUT_PATH"
log_safe "🎉 成功将 $BIN_NAME 安装到 $OUTPUT_PATH"

exit 0
