<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Dashboard extends CI_Controller {

    public function __construct() {
        parent::__construct();
        // Pastikan user login terlebih dahulu
        if (!$this->session->userdata('username')) {
            redirect('login');
        }
    }

    public function index() {
        // Path file JSON
        $filePath = 'C:\laragon\www\capstone\backendd\hasil_evaluasi_model.json';

        // Inisialisasi default data
        $viewData = [
            'username' => ucfirst($this->session->userdata('username')),
            'total_logs' => 0,
            'log_data' => [
                'Normal' => 0,
                'SQL Injection' => 0,
                'Brute Force' => 0,
            ],
        ];

        // Cek apakah file JSON ada
        if (file_exists($filePath)) {
            // Baca file JSON
            $jsonData = file_get_contents($filePath);
            $data = json_decode($jsonData, true);

            // Update data jika file JSON valid
            if (!empty($data['metrics'])) {
                $viewData['total_logs'] = $data['metrics']['total_logs'] ?? 0;

                // Distribusi dalam bentuk array numerik
                $distribution = $data['metrics']['distribution'] ?? [];
                if (count($distribution) === 3) {
                    $viewData['log_data']['Normal'] = $distribution[0] ?? 0;
                    $viewData['log_data']['SQL Injection'] = $distribution[1] ?? 0;
                    $viewData['log_data']['Brute Force'] = $distribution[2] ?? 0;
                }
            }
        }

        // Load view dengan data
        $this->load->view('dashboard/v_dashboard', $viewData);
    }
}
