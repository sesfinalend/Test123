#!/bin/bash
set -e  # 脚本中任一命令返回非零状态时，立即退出

############################################
# 预检查：检查并安装必要的系统依赖：screen 和 python3-venv
############################################

# 检查是否存在 apt-get 工具（适用于 Debian/Ubuntu 系统）
if ! command -v apt-get >/dev/null 2>&1; then
    echo "错误：未检测到 apt-get 工具，本脚本自动安装依赖仅适用于 Debian/Ubuntu 系统。"
    exit 1
fi

# 更新包列表（可选）
echo "更新 apt 包列表..."
apt update

# 检查 screen 是否安装
if ! command -v screen >/dev/null 2>&1; then
    echo "未检测到 screen，正在自动安装 screen..."
     apt-get install -y screen
else
    echo "检测到 screen 已安装。"
fi

# 检查 python3-venv 是否可用（即检查 python3 -m venv 是否能正常运行）
if ! python3 -m venv --help >/dev/null 2>&1; then
    echo "未检测到 python3-venv，正在自动安装 python3-venv..."
     apt-get install -y python3-venv
else
    echo "检测到 python3-venv 可用。"
fi

############################################
# 主体部分：部署项目
############################################

# 项目 Git 仓库地址（根据实际情况修改）
REPO_URL="https://github.com/overlord114514/youknowhat.git"
# 本地项目目录名称（根据需要修改）
PROJECT_DIR="youknowhat"

# 切换到脚本所在目录，确保路径正确
SCRIPT_DIR=$(dirname "$0")
cd "$SCRIPT_DIR"

# 检查项目目录是否存在
if [ -d "$PROJECT_DIR" ]; then
    echo "仓库目录 $PROJECT_DIR 已存在，正在更新代码..."
    cd "$PROJECT_DIR"
    git pull
else
    echo "克隆仓库 $REPO_URL 到当前目录..."
    git clone "$REPO_URL"
    cd "$PROJECT_DIR"
fi

# 输出当前工作目录及目录结构
echo "当前工作目录: $(pwd)"
echo "目录结构："
ls -l

# 再次检查 Python 环境是否支持 venv 模块
if ! python3 -m venv --help >/dev/null 2>&1; then
    echo "错误：你的 python3 环境不支持 venv 模块，请检查安装或手动安装 python3-venv 包。"
    exit 1
fi

# 判断虚拟环境目录是否存在以及激活脚本是否存在
if [ -d "venv" ]; then
    if [ -f "venv/bin/activate" ]; then
        echo "检测到存在有效虚拟环境，跳过创建。"
    else
        echo "警告：存在虚拟环境目录 venv，但未发现激活脚本 venv/bin/activate。"
        echo "可能是之前虚拟环境创建失败或损坏，现删除并重新创建虚拟环境..."
        rm -rf venv
        echo "重新创建虚拟环境..."
        python3 -m venv venv
    fi
else
    echo "未检测到虚拟环境，创建虚拟环境..."
    python3 -m venv venv
fi

# 输出虚拟环境目录结构供调试
echo "虚拟环境创建后，venv/bin 目录内容："
ls -l venv/bin

# 再次确认激活脚本是否存在
if [ ! -f "venv/bin/activate" ]; then
    echo "错误：未能找到虚拟环境激活脚本 venv/bin/activate。"
    echo "请检查虚拟环境是否创建成功，或手动创建："
    echo "    python3 -m venv venv"
    exit 1
fi

echo "激活虚拟环境..."
. venv/bin/activate

echo "升级 pip..."
pip install --upgrade pip

# 如果存在 requirements.txt，则安装依赖
if [ -f "requirements.txt" ]; then
    echo "安装依赖包..."
    pip install -r requirements.txt
else
    echo "未找到 requirements.txt 文件，跳过依赖安装。"
fi

# 使用 screen 启动项目。确保系统已安装 screen 工具（前面已检查）。
# 以下配置假设项目入口为 youknowhat.py，如有需要请修改
SCREEN_SESSION="youknowhat_app"

# 检查是否已经存在同名的 screen 会话，如果存在则退出，避免启动多个实例
if screen -list | grep -q "\.${SCREEN_SESSION}"; then
    echo "已存在名为 ${SCREEN_SESSION} 的 screen 会话，跳过启动。"
else
    echo "使用 screen 启动项目..."
    # -dmS 新建一个后台 screen 会话，名称为指定SESSION名称，执行 python3 youknowhat.py
    screen -dmS "${SCREEN_SESSION}" bash -c ". venv/bin/activate && python3 youknowhat.py"
    echo "项目已在 screen 会话 '${SCREEN_SESSION}' 中启动。"
    echo "你可以使用命令 'screen -r ${SCREEN_SESSION}' 来查看输出。"
fi

echo "部署完成！"
