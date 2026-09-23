#!/bin/bash
export CUDA_VISIBLE_DEVICES=0
export OLLAMA_GPU_OVERHEAD=0
export OLLAMA_MAX_LOADED_MODELS=1
export OLLAMA_KEEP_ALIVE=-1
export OLLAMA_NUM_PARALLEL=1
export OLLAMA_LOAD_TIMEOUT=10m
export LD_LIBRARY_PATH=/usr/lib/wsl/lib:$LD_LIBRARY_PATH
nohup /home/kali/.local/bin/ollama serve > /tmp/ollama.log 2>&1 &
echo "Ollama PID: $!"
sleep 2
echo "Started"
