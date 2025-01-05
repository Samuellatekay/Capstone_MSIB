<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Dashboard extends CI_Controller {
    public $form_validation;
    public $session;
    public $simple_login;
    public $m_account;

    public function __construct() {
        parent::__construct();
        // Pastikan user login terlebih dahulu
        if (!$this->session->userdata('username')) {
            redirect('login');
        }
    }

    public function index() {
        // Path file JSON
        $filePath = '/var/www/html/capstone/backendd/hasil_evaluasi_model.json';

        // Inisialisasi default data
        $viewData = [
            'username' => ucfirst($this->session->userdata('username')),
            'total_logs' => 0,
            'log_data' => [
                'Normal' => 0,
                'SQL Injection' => 0,
                'XSS' => 0,
                'Brute Force' => 0,
            ],
        ];

        // Cek apakah file JSON ada
        if (file_exists($filePath)) {
            // Baca file JSON
            $jsonData = file_get_contents($filePath);
            $data = json_decode($jsonData, true);

            // Update data jika file JSON valid
            if (!empty($data['metrics_test'])) {
                $viewData['total_logs'] = $data['metrics_test']['total_logs'] ?? 0;
                $distribution = $data['metrics_test']['distribution'] ?? [];

                // Memetakan distribusi sesuai kategori
                if (count($distribution) === 4) {
                    $viewData['log_data']['Normal'] = $distribution[0] ?? 0;        // Normal logs
                    $viewData['log_data']['SQL Injection'] = $distribution[1] ?? 0; // SQL Injection logs
                    $viewData['log_data']['Brute Force'] = $distribution[2] ?? 0;   // Brute Force logs
                    $viewData['log_data']['XSS'] = $distribution[3] ?? 0;          // XSS logs
                    $viewData['total_logs'] = array_sum($distribution);            // Total log
                }
            }
        }

        // Load view dengan data
        $this->load->view('dashboard/v_dashboard', $viewData);
    }
}
