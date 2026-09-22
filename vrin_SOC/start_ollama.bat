@echo off
REM Vrindha AI SOC - Ollama Startup Script (Windows)
REM This ensures Ollama runs on Windows with proper NVIDIA CUDA support
REM WSL2 Vrindha connects to this server

echo ==========================================
echo  Vrindha AI SOC - Windows Ollama Startup
echo ==========================================

REM Check if Ollama is installed
where ollama >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Installing Ollama via winget...
    winget install Ollama.Ollama
    timeout /t 5
)

REM Check if qwen3.5:4b is pulled
ollama list 2>&1 | findstr "qwen3.5:4b" >nul
if %ERRORLEVEL% NEQ 0 (
    echo Pulling qwen3.5:4b model (3.4GB)...
    ollama pull qwen3.5:4b
)

REM Set environment variables for GPU
set CUDA_VISIBLE_DEVICES=0
set OLLAMA_GPU_OVERHEAD=0
set OLLAMA_MAX_LOADED_MODELS=1
set OLLAMA_KEEP_ALIVE=-1
set OLLAMA_NUM_PARALLEL=1
set OLLAMA_MAX_QUEUE=1

REM Kill existing taskkill /f /im ollama.exe >nul 2>&1
timeout /t 2

REM Start Ollama server
echo Starting Ollama with NVIDIA RTX 5060 GPU support...
start "" /min "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" serve

REM Wait for server
timeout /t 5

REM Verify
curl -s http://localhost:11434/api/tags | findstr "qwen3.5:4b" >nul
if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✓ Ollama is running with qwen3.5:4b!
    echo ✓ GPU: NVIDIA RTX 5060 (8GB VRAM)
    echo ✓ Endpoint: http://localhost:11434
    echo.
    echo You can now start Vrindha in WSL2:
    echo   .venv_kali/bin/python vrin_SOC/main.py
) else (
    echo.
    echo Ollama may still be starting. Wait 30 seconds.
    echo If it doesn't work, run: ollama serve
    echo Then in another terminal: ollama pull qwen3.5:4b
)

echo ==========================================
pause
