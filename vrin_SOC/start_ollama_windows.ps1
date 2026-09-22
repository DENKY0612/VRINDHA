# Vrindha AI SOC - Windows Ollama Startup Script
# This ensures Ollama runs on Windows with proper NVIDIA CUDA support

Write-Host "=== Vrindha AI SOC - Starting Windows Ollama ===" -ForegroundColor Cyan

# Check if Ollama is installed
$ollamaPath = "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe"
if (-not (Test-Path $ollamaPath)) {
    Write-Host "Ollama not found. Installing via winget..." -ForegroundColor Yellow
    winget install Ollama.Ollama
    Start-Sleep 5
}

# Check if qwen3.5:4b is pulled
$models = & ollama list 2>&1
if ($models -notmatch "qwen3.5:4b") {
    Write-Host "Pulling qwen3.5:4b model (3.4GB)..." -ForegroundColor Yellow
    & ollama pull qwen3.5:4b
}

# Set environment variables for GPU
$env:CUDA_VISIBLE_DEVICES = "0"
$env:OLLAMA_GPU_OVERHEAD = "0"
$env:OLLAMA_MAX_LOADED_MODELS = "1"
$env:OLLAMA_KEEP_ALIVE = "-1"
$env:OLLAMA_NUM_PARALLEL = "1"
$env:OLLAMA_MAX_QUEUE = "1"

# Start Ollama server
Write-Host "Starting Ollama server with NVIDIA RTX 5060 GPU support..." -ForegroundColor Green
Start-Process -FilePath $ollamaPath -ArgumentList "serve" -WindowStyle Hidden

Start-Sleep 3

# Verify
try {
    $response = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -TimeoutSec 10
    Write-Host "Ollama is running! Models: $($response.models.name -join ', ')" -ForegroundColor Green
    Write-Host "GPU: NVIDIA RTX 5060 (8GB VRAM)" -ForegroundColor Green
    Write-Host "Endpoint: http://localhost:11434" -ForegroundColor Green
} catch {
    Write-Host "Ollama may still be starting. Wait 30 seconds and try again." -ForegroundColor Yellow
}

Write-Host "=== Ollama Ready ===" -ForegroundColor Cyan
