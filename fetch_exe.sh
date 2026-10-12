#!/bin/bash
# =====================================================
# 拉取最新的 Windows exe 到本地，命名带时间戳
# 用法: ./fetch_exe.sh          （拉最新一次成功构建）
#       ./fetch_exe.sh --watch  （等待当前进行中的构建完成并拉取）
# =====================================================
set -e
REPO="yuanfei-jason/wuduzhikaipao-modifier"
OUT_DIR="$(cd "$(dirname "$0")" && pwd)/dist"
TS=$(date +%Y%m%d_%H%M%S)
ARTIFACT_NAME="我独自开炮存档修改器-exe"

mkdir -p "$OUT_DIR"

# 选定 run：默认最新成功的；--watch 模式则等最新一条(含进行中)
if [ "$1" = "--watch" ]; then
    RUN_ID=$(gh run list --repo "$REPO" --workflow "Build Windows EXE" --limit 1 --json databaseId,status --jq '.[0].databaseId')
    echo "等待构建 $RUN_ID 完成..."
    gh run watch "$RUN_ID" --repo "$REPO" --exit-status > /dev/null
else
    RUN_ID=$(gh run list --repo "$REPO" --workflow "Build Windows EXE" --status success --limit 1 --json databaseId --jq '.[0].databaseId')
    if [ -z "$RUN_ID" ]; then
        echo "错误：没有已成功完成的构建"; exit 1
    fi
fi

echo "下载 run $RUN_ID 的产物..."
TMP_DIR=$(mktemp -d)
gh run download "$RUN_ID" --repo "$REPO" -n "$ARTIFACT_NAME" -D "$TMP_DIR"

EXE_SRC=$(find "$TMP_DIR" -name "*.exe" | head -1)
if [ -z "$EXE_SRC" ]; then
    echo "错误：产物里没有 exe"; rm -rf "$TMP_DIR"; exit 1
fi

EXE_DST="$OUT_DIR/我独自开炮存档修改器_${TS}.exe"
mv "$EXE_SRC" "$EXE_DST"
rm -rf "$TMP_DIR"

SIZE_MB=$(du -m "$EXE_DST" | cut -d' ' -f1)
echo "✅ 已下载: $EXE_DST (${SIZE_MB} MB)"

# 只保留最近 5 个，防止堆积
ls -t "$OUT_DIR"/我独自开炮存档修改器_*.exe 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true
