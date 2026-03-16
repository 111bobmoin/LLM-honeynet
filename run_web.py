#!/usr/bin/env python3
"""
Launch script for LLM Honeynet Web Interface
"""
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import and run the API
from web.api import main

if __name__ == '__main__':
    main()
