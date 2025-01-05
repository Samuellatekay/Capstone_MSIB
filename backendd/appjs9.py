import pandas as pd
import numpy as np
import re
from datetime import datetime
import time
import json


# Fungsi untuk memparsing setiap log
def parse_log_line(line):
    """Parse log untuk SQL Injection dan Brute Force dengan pengecekan regex yang lebih baik"""
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

    # Perbaikan pola SQL Injection
    sql_pattern = re.compile(
        r"(union.*select.*|select.*from.*|1=1.*|OR\s+1=1|.*admin.*--|information_schema.*)"
    )

    # Ekstrak timestamp dari log
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

    # Deteksi SQL Injection dengan regex yang diperbarui
    if sql_pattern.search(line):
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


# Proses untuk membaca semua log
def process_logs(file_paths):
    all_data = []
    ip_failed_attempts = {}

    for file_path in file_paths:
        print(f"\nMemproses file: {file_path}")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    parsed = parse_log_line(line)
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


# Deteksi Brute Force dan SQL Injection
def detect_attacks(df, brute_force_threshold=3):
    """Deteksi serangan dengan penanganan log normal yang lebih baik"""
    df['is_attack'] = False

    # Deteksi Brute Force
    brute_force_mask = (df['attack_type'] == 'Brute Force') & \
                      (df['total_failed_attempts'] >= brute_force_threshold)

    # Deteksi SQL Injection
    sql_injection_mask = df['attack_type'] == 'SQL Injection'

    df.loc[brute_force_mask | sql_injection_mask, 'is_attack'] = True

    return df


# Hitung metrik akurasi
def calculate_metrics(df):
    total_logs = len(df)

    categories = ['Normal', 'SQL Injection', 'Brute Force']
    log_distribution = [df[df['attack_type'] == category].shape[0] for category in categories]

    accuracy_metrics = {
        'Normal': {
            'total': len(df[df['attack_type'] == 'Normal']),
            'correct': len(df[(df['attack_type'] == 'Normal') & (df['is_attack'] == False)])
        },
        'SQL Injection': {
            'total': len(df[df['attack_type'] == 'SQL Injection']),
            'correct': len(df[(df['attack_type'] == 'SQL Injection') & (df['is_attack'] == True)])
        },
        'Brute Force': {
            'total': len(df[df['attack_type'] == 'Brute Force']),
            'correct': len(df[(df['attack_type'] == 'Brute Force') & (df['is_attack'] == True)])
        }
    }

    total_correct = sum(metric['correct'] for metric in accuracy_metrics.values())
    overall_accuracy = (total_correct / total_logs) * 100 if total_logs > 0 else 0

    return {
        'total_logs': total_logs,
        'distribution': log_distribution,
        'accuracy_metrics': accuracy_metrics,
        'overall_accuracy': overall_accuracy
    }


# Fungsi untuk mengkonversi kunci JSON
def convert_keys(d):
    if isinstance(d, dict):
        return {str(k): convert_keys(v) if isinstance(v, dict) else v for k, v in d.items()}
    return d


try:
    while True:
        # Proses dataset dan file log
        dataset_files = [
            'log_sql.log',
            'log_bruteforce.log'
        ]
        test_files = [
            '/var/log/auth.log',
            '/var/log/apache2/access.log'
        ]

        # Proses data training dan testing
        print("\nMemproses file dataset...")
        df_train = process_logs(dataset_files)
        df_train = detect_attacks(df_train)

        print("\nMemproses file testing...")
        df_test = process_logs(test_files)
        df_test = detect_attacks(df_test)

        # Evaluasi
        metrics_train = calculate_metrics(df_train)
        metrics_test = calculate_metrics(df_test)

        hasil_evaluasi = {
            'metrics_train': metrics_train,
            'metrics_test': metrics_test
        }

        # Simpan hasil evaluasi
        hasil_evaluasi = convert_keys(hasil_evaluasi)

        with open("hasil_evaluasi_model.json", "w") as json_file:
            json.dump(hasil_evaluasi, json_file, indent=4)

        print("Evaluasi selesai dan disimpan ke hasil_evaluasi_model.json")
        time.sleep(10)  # Tunggu 10 detik
except KeyboardInterrupt:
    print("\nProses dihentikan oleh pengguna.")
