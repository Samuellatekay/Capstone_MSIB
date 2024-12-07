<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Top5 extends CI_Controller {

    public function __construct() {
        parent::__construct();
        // Load URL helper untuk redirect jika perlu
        $this->load->helper('url');
    }

    public function index() {
        // Path ke file JSON hasil evaluasi
        $json_file_path = 'C:\laragon\www\capstone\backendd\hasil_evaluasi_model.json'; // Sesuaikan dengan path sebenarnya

        if (file_exists($json_file_path)) {
            // Membaca isi file JSON
            $json_data = file_get_contents($json_file_path);
            $data = json_decode($json_data, true);

            // Ambil bagian 'ip_analysis' dari data dan memprosesnya
            $ip_analysis = isset($data['metrics']['ip_analysis']['attacks_per_ip']) ? $data['metrics']['ip_analysis']['attacks_per_ip'] : [];

            // Siapkan array untuk data yang akan ditampilkan
            $attack_data = [];
            foreach ($ip_analysis as $ip_attack => $attack_info) {
                list($ip, $attack_type) = explode(', ', trim($ip_attack, "(')"));
                $attack_data[] = [
                    'ip' => str_replace("'", "", $ip),
                    'attack_type' => str_replace("'", "", $attack_type),
                    'jumlah' => $attack_info
                ];
            }

            // Mengurutkan data berdasarkan jumlah serangan terbanyak ke terkecil
            usort($attack_data, function($a, $b) {
                return $b['jumlah'] - $a['jumlah']; // Mengurutkan secara menurun (dari terbesar ke terkecil)
            });

            // Ambil hanya 5 data teratas
            $attack_data = array_slice($attack_data, 0, 5);

            // Kirim data ke view
            $this->load->view('dashboard/v_top5', ['attack_data' => $attack_data]);
        } else {
            // Menangani jika file tidak ditemukan
            echo "File JSON tidak ditemukan.";
        }
    }
}
