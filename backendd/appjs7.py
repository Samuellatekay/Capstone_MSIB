import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import re
from datetime import datetime
import time
import json


def parse_log_line(line, is_sql_log=False):
    """Parse log untuk SQL Injection dan Brute Force dengan pengecekan log normal yang lebih baik"""
    # Pattern untuk log normal
    normal_patterns = [
        r'session (opened|closed) for user',
        r'New session',
        r'COMMAND=/usr',
        r'New seat',
        r'PAM adding faulty module',
        r'ROOT LOGIN'
    ]

    # Pattern untuk Brute Force
    brute_force_pattern = re.compile(r'Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)')

    # Pattern untuk SQL Injection
    sql_pattern = re.compile(r'POST /capstone/safelogs/index\.php/login.*|.*Mozilla/5\.0.*')

    # Ekstrak timestamp
    timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
    if not timestamp_match:
        return None

    timestamp = timestamp_match.group(1)

    # Deteksi Brute Force
    brute_match = brute_force_pattern.search(line)
    if brute_match:
        username, ip = brute_match.groups()
        return {
            'timestamp': timestamp,
            'ip': ip,
            'username': username,
            'raw_log': line.strip(),
            'attack_type': 'Brute Force',
            'failed_attempt': 1
        }

    # Deteksi SQL Injection hanya jika dalam log SQL Testing
    if is_sql_log and sql_pattern.search(line):
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        ip = ip_match.group(1) if ip_match else 'unknown'
        return {
            'timestamp': timestamp,
            'ip': ip,
            'username': 'none',
            'raw_log': line.strip(),
            'attack_type': 'SQL Injection',
            'failed_attempt': 0
        }

    # Verifikasi log normal
    is_normal = any(re.search(pattern, line) for pattern in normal_patterns)
    if is_normal:
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        return {
            'timestamp': timestamp,
            'ip': ip_match.group(1) if ip_match else 'localhost',
            'username': 'system',
            'raw_log': line.strip(),
            'attack_type': 'Normal',
            'failed_attempt': 0
        }

    return None


def process_logs(file_paths, is_sql_log=False):
    all_data = []
    ip_failed_attempts = {}

    for file_path in file_paths:
        print(f"\nMemproses file: {file_path}")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    parsed = parse_log_line(line, is_sql_log)
                    if parsed:
                        ip = parsed['ip']
                        if parsed['failed_attempt'] == 1:
                            ip_failed_attempts[ip] = ip_failed_attempts.get(ip, 0) + 1
                        parsed['total_failed_attempts'] = ip_failed_attempts.get(ip, 0)
                        parsed['source_file'] = file_path.split('/')[-1]
                        all_data.append(parsed)
        except Exception as e:
            print(f"Error membaca file {file_path}: {str(e)}")

    return pd.DataFrame(all_data)


def detect_attacks(df, brute_force_threshold=3):
    """Deteksi serangan dengan penanganan log normal yang lebih baik"""
    # Inisialisasi kolom is_attack sebagai False
    df['is_attack'] = False

    # Deteksi Brute Force
    brute_force_mask = (df['attack_type'] == 'Brute Force') & \
                      (df['total_failed_attempts'] >= brute_force_threshold)

    # Deteksi SQL Injection
    sql_injection_mask = df['attack_type'] == 'SQL Injection'

    # Gabungkan deteksi
    df.loc[brute_force_mask | sql_injection_mask, 'is_attack'] = True

    return df

try:
    while True:
        # Pisahkan file dataset dan testing
        dataset_files = [
            'log_sql.log',
            'log_bruteforce.log'
        ]

        test_files = [
            '/var/log/auth.log',
            '/var/log/apache2/access.log'  # File ini khusus untuk SQL Injection testing
        ]

        # Proses dataset untuk training
        print("Memproses file dataset...")
        df_train = process_logs(dataset_files)
        df_train = detect_attacks(df_train)

        # Proses file testing
        print("Memproses file testing...")
        df_test_auth = process_logs(['/var/log/auth.log'])
        df_test_sql = process_logs(['/var/log/apache2/access.log'], is_sql_log=True)

        # Gabungkan hasil testing untuk kedua jenis log
        df_test = pd.concat([df_test_auth, df_test_sql], ignore_index=True)
        df_test = detect_attacks(df_test)

        # Evaluasi hasil untuk training
        metrics_train = calculate_metrics(df_train)

        # Evaluasi hasil untuk testing
        metrics_test = calculate_metrics(df_test)

        # Simpan hasil evaluasi ke JSON
        hasil_evaluasi = {
            'metrics_train': metrics_train,
            'metrics_test': metrics_test
        }

        with open("hasil_evaluasi_model.json", "w") as json_file:
            json.dump(hasil_evaluasi, json_file, indent=4)

        time.sleep(10)  # Cek setiap 10 detik
except KeyboardInterrupt:
    print("Proses dihentikan oleh pengguna.")
