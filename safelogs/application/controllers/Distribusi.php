<?php
class Distribusi extends CI_Controller {

    public function __construct() {
        parent::__construct();
        // Load URL helper untuk redirect jika perlu
        $this->load->helper('url');
    }

    // Method untuk membaca file JSON dan mengirim ke view
    public function index() {
        // Path ke file JSON hasil evaluasi
        $json_file_path = 'C:\laragon\www\capstone\backendd\hasil_evaluasi_model.json'; // Sesuaikan dengan path sebenarnya

        if (file_exists($json_file_path)) {
            // Membaca isi file JSON
            $json_data = file_get_contents($json_file_path);
            $data = json_decode($json_data, true);

            // Ambil bagian 'accuracy_metrics' dan 'overall_accuracy' dari data
            $accuracy_metrics = isset($data['metrics']['accuracy_metrics']) ? $data['metrics']['accuracy_metrics'] : [];
            $overall_accuracy = isset($data['metrics']['overall_accuracy']) ? $data['metrics']['overall_accuracy'] : null;

            // Kirim data ke view
            $this->load->view('dashboard/v_akurasi', [
                'accuracy_metrics' => $accuracy_metrics,
                'overall_accuracy' => $overall_accuracy
            ]);
        } else {
            // Menangani jika file tidak ditemukan
            echo "File JSON tidak ditemukan.";
        }
    }
}
