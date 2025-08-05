# utils/parser.py

import pandas as pd
import re


def parse_log(file_path):
    """
    Fungsi untuk membaca file log dan mengubahnya menjadi DataFrame
    Format log yang umum: [timestamp] LEVEL message
    Contoh:
    [2025-08-05 20:22:00] INFO User X login from 192.168.1.2
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    log_entries = []
    for line in lines:
        match = re.match(r"\[(.*?)\]\s+(\w+)\s+(.*)", line)
        if match:
            timestamp, level, message = match.groups()
            log_entries.append({
                'timestamp': timestamp,
                'level': level,
                'message': message
            })

    df = pd.DataFrame(log_entries)
    return df
