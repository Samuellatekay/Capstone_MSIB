import pandas as pd
import numpy as np
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import re
from datetime import datetime
import time
import json

def parse_log_line(line):
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
    sql_pattern = re.compile(r'.*SQL Injection.*|.*Input contains.*OR 1=1.*|.*SELECT \* FROM users WHERE.*')
    
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
    
    # Deteksi SQL Injection
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

def calculate_metrics(df):
    """Menghitung metrik akurasi deteksi"""
    # Hitung total log
    total_logs = len(df)
    
    # Hitung distribusi jenis log
    log_distribution = df['attack_type'].value_counts()
    
    # Hitung akurasi per kategori
    accuracy_metrics = {
        'Normal': {
            'total': len(df[df['attack_type'] == 'Normal']),
            'correct': len(df[(df['attack_type'] == 'Normal') & (df['is_attack'] == False)]),
        },
        'SQL Injection': {
            'total': len(df[df['attack_type'] == 'SQL Injection']),
            'correct': len(df[(df['attack_type'] == 'SQL Injection') & (df['is_attack'] == True)]),
        },
        'Brute Force': {
            'total': len(df[df['attack_type'] == 'Brute Force']),
            'correct': len(df[(df['attack_type'] == 'Brute Force') & (df['is_attack'] == True)]),
        }
    }
    
    # Hitung akurasi keseluruhan
    total_correct = sum(metric['correct'] for metric in accuracy_metrics.values())
    overall_accuracy = (total_correct / total_logs) * 100 if total_logs > 0 else 0
    
    # Tambahan analisis IP dan serangan
    ip_analysis = {
        'unique_ips': df['ip'].nunique(),
        'top_attacker_ips': df[df['is_attack'] == True]['ip'].value_counts().head(5).to_dict(),
        'attacks_per_ip': df[df['is_attack'] == True].groupby('ip')['attack_type'].value_counts().to_dict()
    }
    
    attack_analysis = {
        'attack_timeline': df[df['is_attack'] == True].groupby(['timestamp', 'attack_type']).size().to_dict(),
        'attack_patterns': df[df['is_attack'] == True]['attack_type'].value_counts().to_dict()
    }
    
    return {
        'total_logs': total_logs,
        'distribution': log_distribution,
        'accuracy_metrics': accuracy_metrics,
        'overall_accuracy': overall_accuracy,
        'ip_analysis': ip_analysis,
        'attack_analysis': attack_analysis
    }

# Pastikan metrics['distribution'] adalah list, bukan dictionary
def create_summary_tables(metrics, attack_characteristics):
    # Cek apakah 'accuracy' ada dalam metrics
    if 'accuracy' in metrics:
        accuracy = metrics['accuracy']
    else:
        accuracy = 'Data tidak tersedia'

    distribution_table = {
        'Kategori': attack_characteristics.keys(),
        'Jumlah': metrics['distribution']  # Sesuaikan dengan data Anda
    }

    accuracy_table = {
        'Model': ['Model 1', 'Model 2'],  # Sesuaikan dengan data Anda
        'Akurasi': accuracy
    }

    characteristics_table = {
        'Karakteristik': attack_characteristics.keys(),
        'Nilai': attack_characteristics.values()
    }

    ip_analysis_table = {
        'IP': ['IP1', 'IP2'],  # Sesuaikan dengan data Anda
        'Frekuensi': metrics['ip_analysis']
    }

    return distribution_table, accuracy_table, characteristics_table, ip_analysis_table



try:
    while True:
        # Pisahkan file dataset dan testing
        dataset_files = [
            'log_sql.log',
            'log_bruteforce.log'
        ]
        
        test_files = [
            'tidak.log'
        ]   
        
        # Proses dataset untuk training
        print("Memproses file dataset...")
        df_train = process_logs(dataset_files)
        df_train = detect_attacks(df_train)
        
        # Proses file testing
        print("Memproses file testing...")
        df_test = process_logs(test_files)
        df_test = detect_attacks(df_test)
        
        # Evaluasi hasil
        metrics = calculate_metrics(df_train)
        attack_characteristics = {
            'sql_patterns': df_train[df_train['attack_type'] == 'SQL Injection'].to_dict(orient='records'),  # Ubah ke format list of dicts
            'brute_force_ips': df_train[df_train['attack_type'] == 'Brute Force'].to_dict(orient='records')  # Ubah ke format list of dicts
        }
        
        # Simpan hasil evaluasi ke JSON
        hasil_evaluasi = {
            'metrics': metrics,
            'attack_characteristics': {
                'sql_patterns': attack_characteristics['sql_patterns'],
                'brute_force_ips': attack_characteristics['brute_force_ips']
            }
        }


        for key, value in hasil_evaluasi['metrics'].items():
            if isinstance(value, pd.Series):
                hasil_evaluasi['metrics'][key] = value.tolist()
                
        
        def convert_keys(d):
            if isinstance(d, dict):
                return {str(k): convert_keys(v) if isinstance(v, dict) else v for k, v in d.items()}
            return d

        # Pastikan seluruh kunci pada hasil_evaluasi adalah tipe data yang valid untuk JSON
        hasil_evaluasi = convert_keys(hasil_evaluasi)

        # Sekarang simpan hasil dalam format JSON
        with open("hasil_evaluasi_model.json", "w") as json_file:
            json.dump(hasil_evaluasi, json_file, indent=4)
        
        # Simpan tabel hasil ke Excel
        print("\nMenyimpan tabel hasil evaluasi...")
        distribution_table, accuracy_table, characteristics_table, ip_analysis_table = create_summary_tables(metrics, attack_characteristics)
        
        # Tampilkan tabel hasil
        print("\nDistribusi Log:")
        print(distribution_table)
        
        print("\nAkurasi per Kategori Serangan:")
        print(accuracy_table)
        
        print("\nKarakteristik Serangan:")
        print(characteristics_table)
        
        print("\nAnalisis Serangan per IP:")
        print(ip_analysis_table)
        
        time.sleep(60)  # Cek setiap 1 menit
except KeyboardInterrupt:
    print("Proses dihentikan oleh pengguna.")

