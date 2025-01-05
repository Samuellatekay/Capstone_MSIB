import pandas as pd
import re
import json
from pathlib import Path
from collections import defaultdict
import numpy as np
import time 

# Path untuk dataset
SQL_INJECTION_FILE = Path('/var/www/html/capstone/backendd/SQL_Injection.log')
BRUTE_FORCE_FILE = Path('/var/www/html/capstone/backendd/brute_force.log')
XSS_FILE = Path('/var/www/html/capstone/backendd/XSS.log')
ACCESS_LOG_FILE = Path('/var/log/apache2/access.log')
AUTH_LOG_FILE = Path('/var/log/auth.log')  # Menambahkan auth.log sebagai data tes

def load_logs(file_path):
    if not file_path.exists():
        raise FileNotFoundError(f"{file_path} tidak ditemukan.")
    with file_path.open('r', encoding='utf-8') as file:
        logs = [line.strip() for line in file.readlines() if line.strip()]
    return pd.DataFrame({'log': logs})

def detect_sql_injection(log_df):
    sql_patterns = [
        r"union\s+select",
        r"select\s+\*.*from",
        r"1=1",
        r"or\s+1=1",
        r"drop\s+table",
        r"insert\s+into",
        r"' OR '1'='1"
    ]
    sql_regex = re.compile("|".join(sql_patterns), re.IGNORECASE)
    log_df['sql_injection_detected'] = log_df['log'].apply(lambda x: bool(sql_regex.search(x)))
    log_df['attack_type'] = log_df.apply(lambda row: 'SQL Injection' if row['sql_injection_detected'] else row.get('attack_type', None), axis=1)
    return log_df

def detect_brute_force(log_df):
    ip_regex = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
    log_df['IP'] = log_df['log'].apply(lambda x: ip_regex.search(x).group() if ip_regex.search(x) else None)
    ip_counts = log_df['IP'].value_counts().to_dict()
    log_df['brute_force_detected'] = log_df['IP'].apply(lambda x: ip_counts.get(x, 0) > 10 if x else False)
    log_df['attack_type'] = log_df.apply(lambda row: 'Brute Force' if row['brute_force_detected'] else row.get('attack_type', None), axis=1)
    return log_df

def detect_xss(log_df):
    xss_patterns = [
        r"<script.*?>",
        r"onerror\s*=",
        r"alert\s*\(",
        r"eval\s*\(",
        r"document\.location",
        r"javascript:",
        r"src\s*=\s*['\"]\s*data:",
    ]
    xss_regex = re.compile("|".join(xss_patterns), re.IGNORECASE)
    log_df['xss_detected'] = log_df['log'].apply(lambda x: bool(xss_regex.search(x)))
    log_df['attack_type'] = log_df.apply(lambda row: 'XSS' if row['xss_detected'] else row.get('attack_type', None), axis=1)
    return log_df

def calculate_metrics(log_df, label, detected_column):
    total_logs = len(log_df)
    total_attacks = log_df[detected_column].sum()

    if isinstance(total_logs, str):
        total_logs = 0  # Jika ternyata string, kita set menjadi 0
    if isinstance(total_attacks, str):
        total_attacks = 0  # Jika ternyata string, kita set menjadi 0
    
    accuracy = (total_attacks / total_logs) * 100 if total_logs > 0 else 0.0
    return {
        "total": total_logs,
        "correct": total_attacks
    }

def summarize_results(log_df, dataset_name):
    results = {}
    total_logs = len(log_df)

    # Pastikan kolom deteksi serangan berisi nilai boolean
    log_df['sql_injection_detected'] = log_df['sql_injection_detected'].fillna(False).astype(bool)
    log_df['brute_force_detected'] = log_df['brute_force_detected'].fillna(False).astype(bool)
    log_df['xss_detected'] = log_df['xss_detected'].fillna(False).astype(bool)

    # Menghitung jumlah serangan untuk masing-masing kategori
    sql_count = log_df['sql_injection_detected'].sum()
    brute_count = log_df['brute_force_detected'].sum()
    xss_count = log_df['xss_detected'].sum()

    # Menghitung jumlah log yang tidak terdeteksi serangan (Normal)
    normal_count = total_logs - (sql_count + brute_count + xss_count)

    # Menyusun distribusi berdasarkan jumlah masing-masing serangan
    results['distribution'] = [normal_count, sql_count, brute_count, xss_count]

    accuracy_metrics = {
        "Normal": calculate_metrics(log_df[~log_df['sql_injection_detected'] & ~log_df['brute_force_detected'] & ~log_df['xss_detected']], "Normal", "log"),
        "SQL Injection": calculate_metrics(log_df, "SQL Injection", "sql_injection_detected"),
        "Brute Force": calculate_metrics(log_df, "Brute Force", "brute_force_detected"),
        "XSS": calculate_metrics(log_df, "XSS", "xss_detected")
    }
    results["accuracy_metrics"] = accuracy_metrics

    correct_detections = sum([metric["correct"] for metric in accuracy_metrics.values()])
    overall_accuracy = (correct_detections / total_logs) * 100 if total_logs > 0 else 0.0
    results["overall_accuracy"] = overall_accuracy

    ip_analysis = defaultdict(int)
    top_attacker_ips = defaultdict(int)
    attacks_per_ip = defaultdict(int)

    for index, row in log_df.iterrows():
        ip = row['IP']
        attack_type = row['attack_type']
        if attack_type:
            ip_analysis[ip] += 1
            top_attacker_ips[ip] += 1
            attacks_per_ip[f"({ip}, {attack_type})"] += 1

    results["ip_analysis"] = {
        "unique_ips": len(ip_analysis),
        "top_attacker_ips": dict(top_attacker_ips),
        "attacks_per_ip": dict(attacks_per_ip)
    }

    return results

def convert_to_serializable(obj):
    if isinstance(obj, dict):
        return {key: convert_to_serializable(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_serializable(item) for item in obj]
    elif isinstance(obj, pd.Series):
        return obj.tolist()
    elif isinstance(obj, (np.int64, np.int32)):
        return int(obj)
    return obj


try:
    while True:
    # Load dataset training
        sql_injection_logs = load_logs(SQL_INJECTION_FILE)
        brute_force_logs = load_logs(BRUTE_FORCE_FILE)
        xss_logs = load_logs(XSS_FILE)

        # Gabungkan dataset training
        training_logs = pd.concat([sql_injection_logs, brute_force_logs, xss_logs], ignore_index=True)
        training_logs = detect_sql_injection(training_logs)
        training_logs = detect_brute_force(training_logs)
        training_logs = detect_xss(training_logs)

        # Load dataset testing (akses log hanya untuk SQL Injection dan XSS, auth log untuk Brute Force)
        access_logs = load_logs(ACCESS_LOG_FILE)
        auth_logs = load_logs(AUTH_LOG_FILE)

        # Deteksi serangan untuk access log (SQL Injection dan XSS)
        access_logs = detect_sql_injection(access_logs)
        access_logs = detect_xss(access_logs)

        # Deteksi serangan untuk auth log (Brute Force)
        auth_logs = detect_brute_force(auth_logs)

        # Gabungkan hasil tes (akses dan auth)
        combined_testing_logs = pd.concat([access_logs, auth_logs], ignore_index=True)

        # Ringkasan hasil
        training_results = summarize_results(training_logs, "Training")
        testing_results = summarize_results(combined_testing_logs, "Testing")

        # Ambil total_logs dari hasil ringkasan
        total_logs_train = training_results['distribution'][0] + training_results['distribution'][1] + training_results['distribution'][2] + training_results['distribution'][3]
        total_logs_test = testing_results['distribution'][0] + testing_results['distribution'][1] + testing_results['distribution'][2] + testing_results['distribution'][3]

        # Simpan hasil dalam file JSON
        result = {
            "metrics_train": training_results,
            "metrics_test": {
                "total_logs": total_logs_test,  # Pindahkan total_logs ke sini
                "distribution": testing_results['distribution'],
                "accuracy_metrics": testing_results['accuracy_metrics'],
                "overall_accuracy": testing_results['overall_accuracy'],
                "ip_analysis": testing_results['ip_analysis']
            }
        }

        # Mengonversi hasil menjadi serializable
        result = convert_to_serializable(result)

        output_file = Path('/var/www/html/capstone/backendd/hasil_evaluasi_model.json')
        with output_file.open('w', encoding='utf-8') as f:
            json.dump(result, f, indent=4)
        print(f"\nHasil deteksi telah disimpan di '{output_file}'")

        time.sleep(5) 

except Exception as e:
    print(f"Terjadi kesalahan: {e}")


