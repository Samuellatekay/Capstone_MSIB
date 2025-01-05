<?php
class Distribusi extends CI_Controller {

        public $form_validation;
        public $session;
        public $simple_login;
        public $m_account;

    public function __construct() {
        parent::__construct();
        // Load URL helper untuk redirect jika perlu
        $this->load->helper('url');
    }

    // Method untuk membaca file JSON dan mengirim ke view
    public function index() {
        // Path ke file JSON hasil evaluasi
        $json_file_path = '/var/www/html/capstone/backendd/hasil_evaluasi_model.json'; // Sesuaikan dengan path sebenarnya

        if (file_exists($json_file_path)) {
            // Membaca isi file JSON
            $json_data = file_get_contents($json_file_path);
            $data = json_decode($json_data, true);

            // Mengecek jika data JSON dapat didekode
            $data = json_decode($json_data, true);
            if ($data === null) {
                // Jika JSON tidak valid
                log_message('error', 'Gagal mendekode data JSON: ' . json_last_error_msg());
                echo "Gagal mendekode data JSON.";
                return; // Menghentikan eksekusi jika data JSON tidak valid
            }

            // Ambil bagian 'accuracy_metrics' dan 'overall_accuracy' dari data
            $accuracy_metrics = isset($data['metrics_test']['accuracy_metrics']) ? $data['metrics_test']['accuracy_metrics'] : [];
            $overall_accuracy = isset($data['metrics_test']['overall_accuracy']) ? $data['metrics_test']['overall_accuracy'] : null;

            // Kirim data ke view
            $this->load->view('dashboard/v_akurasi', [
                'accuracy_metrics' => $accuracy_metrics,
                'overall_accuracy' => $overall_accuracy
            ]);
        } else {
            // Menangani jika file tidak ditemukan
            log_message('error', "File JSON tidak ditemukan atau tidak dapat dibaca: $json_file_path");
            echo "File JSON tidak ditemukan.";
        }
    }
}
