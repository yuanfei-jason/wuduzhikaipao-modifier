@echo off
chcp 65001 >nul
rem =====================================================
rem  《我独自开炮》存档数值修改器 —— 一键打包为独立 exe
rem  用法：在 Windows 上双击运行（需已安装 Python 3.8+）
rem =====================================================

python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到 Python，请先安装 Python 3.8+ 并勾选 "Add to PATH"
    pause
    exit /b 1
)

echo [1/3] 安装 PyInstaller（仅需一次）...
python -m pip install --quiet pyinstaller

echo [2/3] 打包中，请稍等...
python -m PyInstaller --onefile --noconsole --name "我独自开炮存档修改器" sg_modifier.py

echo [3/3] 完成！
echo 输出位置: dist\我独自开炮存档修改器.exe
echo 使用时请右键该 exe，选择"以管理员身份运行"
pause
