#!/bin/bash
# ==============================================================================
# Script: logger.sh
# Descripcion: Utilidad centralizada para imprimir logs en pantalla.
# Uso: source path/to/logger.sh
# ==============================================================================

log_info() { 
    echo -e "[\e[34mINFO\e[0m] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_success() { 
    echo -e "[\e[32mOK\e[0m]   $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warn() { 
    echo -e "[\e[33mWARN\e[0m] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() { 
    echo -e "[\e[31mFAIL\e[0m] $(date '+%Y-%m-%d %H:%M:%S') - $1"
    exit 1
}
