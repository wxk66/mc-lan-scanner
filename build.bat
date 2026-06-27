@echo off
chcp 65001 >nul
REM ============================================================
REM  我的世界局域网扫描器 - 一键打包脚本
REM  生成单文件、无控制台窗口的 exe 到 dist\ 目录
REM ============================================================

echo [*] 检查 PyInstaller...
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo [!] 未安装 PyInstaller, 正在安装...
    python -m pip install -r requirements.txt
)

echo [*] 开始打包...
python -m PyInstaller ^
    --noconfirm ^
    --onefile ^
    --windowed ^
    --name "MC局域网扫描器" ^
    mc_gui.py

if errorlevel 1 (
    echo [!] 打包失败
    pause
    exit /b 1
)

echo.
echo [+] 打包完成: dist\MC局域网扫描器.exe
pause
