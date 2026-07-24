#!/bin/bash
set -euo pipefail

# 定义颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 帮助函数
show_help() {
    echo "用法: $0 <模块名|all>"
    echo "支持的模块名："
    echo "  sword                   - 构建 sword 模块 (eBPF 指标采集)"
    echo "  rust-mouse              - 构建 rust-mouse 模块"
    echo "  all                     - 构建所有模块"
    echo "示例："
    echo "  $0 sword"
    echo "  $0 all"
}

if [ $# -eq 0 ]; then
    echo "${RED}错误：请传入模块参数！${NC}"
    show_help
    exit 1
fi

# 获取 Git 最新 Commit ID（前10位）
echo "${YELLOW}正在获取 Git 最新 Commit ID...${NC}"
commitId=$(git log -n 1 --pretty=format:"%H")
short_commit_id=${commitId:0:10}
echo "${GREEN}Git 短 Commit ID：${short_commit_id}${NC}"

update_deployment_image() {
    local image_repo="$1"
    local version="$2"
    local deployment_file="deployment.yaml"
    local image="${image_repo}:${version}"

    if [ ! -f "${deployment_file}" ]; then
        echo "${YELLOW}警告：${deployment_file} 不存在，跳过镜像 tag 替换${NC}"
        return
    fi

    IMAGE_REPO="${image_repo}" IMAGE="${image}" DEPLOYMENT_FILE="${deployment_file}" python3 - <<'PY'
import os
from pathlib import Path

image_repo = os.environ["IMAGE_REPO"]
image = os.environ["IMAGE"]
deployment_file = Path(os.environ["DEPLOYMENT_FILE"])
lines = deployment_file.read_text(encoding="utf-8").splitlines(keepends=True)
updated = False
new_lines = []

for line in lines:
    stripped = line.lstrip()
    indent = line[: len(line) - len(stripped)]
    if stripped.startswith("image:") and stripped.split(":", 1)[1].strip().startswith(f"{image_repo}:"):
        newline = "\n" if line.endswith("\n") else ""
        new_lines.append(f"{indent}image: {image}{newline}")
        updated = True
    else:
        new_lines.append(line)

if not updated:
    raise SystemExit(f"未找到镜像配置: {image_repo}")

deployment_file.write_text("".join(new_lines), encoding="utf-8")
PY
    echo "${GREEN}已更新 ${deployment_file} 镜像：${image}${NC}"
}

# 构建 sword 模块
build_sword() {
    local version_prefix="v0.1.0"
    local module_name="sword"
    local cargo_pkg="sword"
    local dockerfile_path="./Dockerfile"
    local image_repo="xwharbor.wxchina.com/cpaas/component/sword"
    local version="${version_prefix}-${short_commit_id}"

    echo "\n${YELLOW}开始构建 ${module_name} 模块，版本：${version}${NC}"

    echo "1. 执行 cargo build --release..."
    cargo build -p ${cargo_pkg} --release

    echo "2. 构建 Docker 镜像..."
    docker build -f ${dockerfile_path} -t ${image_repo}:${version} .

    echo "3. 推送 Docker 镜像..."
    docker push ${image_repo}:${version}

    echo "4. 更新 deployment.yaml 镜像 tag..."
    update_deployment_image "${image_repo}" "${version}"

    echo "${GREEN}${module_name} 模块构建并推送完成！${NC}"
}

# 构建 rust-mouse 模块
build_rust_mouse() {
    local version_prefix="v0.1.0"
    local module_name="rust-mouse"
    local cargo_pkg="rust-mouse"
    local dockerfile_path="./rust-mouse/Dockerfile"
    local image_repo="xwharbor.wxchina.com/cpaas/component/rust-mouse"
    local version="${version_prefix}-${short_commit_id}"

    echo "\n${YELLOW}开始构建 ${module_name} 模块，版本：${version}${NC}"

    echo "1. 执行 cargo build --release..."
    cargo build -p ${cargo_pkg} --release

    if [ -f "${dockerfile_path}" ]; then
        echo "2. 构建 Docker 镜像..."
        docker build -f ${dockerfile_path} -t ${image_repo}:${version} .

        echo "3. 推送 Docker 镜像..."
        docker push ${image_repo}:${version}

        echo "4. 更新 deployment.yaml 镜像 tag..."
        update_deployment_image "${image_repo}" "${version}"
    else
        echo "${YELLOW}警告：${dockerfile_path} 不存在，跳过 Docker 构建${NC}"
    fi

    echo "${GREEN}${module_name} 模块构建完成！${NC}"
}

# 根据传入的参数执行对应构建
case "$1" in
    sword)
        build_sword
        ;;
    rust-mouse)
        build_rust_mouse
        ;;
    all)
        build_sword
        build_rust_mouse
        echo "\n${GREEN}所有模块构建并推送完成！${NC}"
        ;;
    *)
        echo "${RED}错误：不支持的模块参数 '$1'！${NC}"
        show_help
        exit 1
        ;;
esac

exit 0
