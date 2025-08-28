import os
import pandas as pd
import json

def parse_log(file_path):
    """
    Parse berbagai jenis file log (.csv, .txt, .log, .json, .exe (dummy warning)) menjadi DataFrame.
    """
    ext = os.path.splitext(file_path)[-1].lower()

    if ext == '.csv':
        return pd.read_csv(file_path)
    
    elif ext in ['.txt', '.log']:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        return pd.DataFrame({'line': [line.strip() for line in lines]})
    
    elif ext == '.json':
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        if isinstance(data, list):
            return pd.DataFrame(data)
        elif isinstance(data, dict):
            return pd.json_normalize(data)
        else:
            raise ValueError("Format JSON tidak dikenali.")
    
    elif ext == '.exe':
        # Warning: EXE bukan file log yang bisa diparse sebagai teks
        raise ValueError("File .exe tidak bisa dianalisis langsung. Silakan unggah file log atau data dalam format teks.")
    
    else:
        raise ValueError(f"Format file {ext} tidak didukung.")

# Simpan ke file parser.py
parser_code = '''\
import os
import pandas as pd
import json

def parse_log(file_path):
    ext = os.path.splitext(file_path)[-1].lower()

    if ext == '.csv':
        return pd.read_csv(file_path)

    elif ext in ['.txt', '.log']:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        return pd.DataFrame({'line': [line.strip() for line in lines]})

    elif ext == '.json':
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        if isinstance(data, list):
            return pd.DataFrame(data)
        elif isinstance(data, dict):
            return pd.json_normalize(data)
        else:
            raise ValueError("Format JSON tidak dikenali.")

    elif ext == '.exe':
        raise ValueError("File .exe tidak bisa dianalisis langsung. Silakan unggah file log atau data dalam format teks.")

    else:
        raise ValueError(f"Format file {ext} tidak didukung.")
'''

with open('/mnt/data/parser.py', 'w', encoding='utf-8') as f:
    f.write(parser_code)

"/mnt/data/parser.py"
