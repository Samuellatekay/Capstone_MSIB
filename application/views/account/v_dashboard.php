<?php defined('BASEPATH') OR exit('No direct script access allowed'); ?>
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SafeLogs</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.1/css/all.min.css" integrity="sha512-5Hs3dF2AEPkpNAR7UiOHba+lRSJNeM2ECkwxUIxC1Q/FLycGTbNapWXB4tP889k5T5Ju8fs4b1P5z/iB4nMfSQ==" crossorigin="anonymous" referrerpolicy="no-referrer" />
  <style>
        body {
            background-color: #f8f9fa;
        }
        .sidebar {
            height: 200vh;
            background-color: #343a40;
            color: white;
        }
        .sidebar a {
            color: white;
            text-decoration: none;
            padding: 10px 15px;
            display: block;
        }
        .sidebar a:hover {
            background-color: #495057;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <nav class="col-md-2 d-none d-md-block sidebar">
                <div class="sidebar-sticky">
                    <h3 class="text-center py-3">SafeLogs</h3>
                    <ul class="nav flex-column">
                        <li class="nav-item">
                            <h5><a href="#" class="logout-link">Dashboard</a></h5>
                        </li>
                        <li class="nav-item">
                            <h5><a href="<?php echo site_url('login/logout'); ?>" class="logout-link">Keluar</a></h5>
                        </li>
                        <li class="nav-item">
                        </li>
                    </ul>
                </div>
            </nav>

            <!-- Main Content -->
            <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4">
                <!-- Dashboard Cards -->
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">Selamat datang di halaman dashboard, <strong><?php echo ucfirst($this->session->userdata('username')); ?></strong>!</h1>
                </div>
                <div class="row">
                    <div class="col-md-4">
                        <div class="card mb-3">
                            <div class="card-body">
                                <h5 class="card-title">Normal</h5>
                                <i class="fa-solid fa-user float-end" style="font-size: 50px;"></i>
                                <p class="card-text">120</p>
                                <a href="#" class="btn btn-primary">View</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card mb-3">
                            <div class="card-body">
                                <h5 class="card-title">SQLI</h5>
                                <i class="fa-solid fa-box float-end" style="font-size: 50px;"></i>
                                <p class="card-text">20</p>
                                <a href="#" class="btn btn-primary">View</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card mb-3">
                            <div class="card-body">
                                <h5 class="card-title">Brute Force</h5>
                                <i class="fa-solid fa-chart-line float-end" style="font-size: 50px;"></i>
                                <p class="card-text">30</p>
                                <a href="#" class="btn btn-primary">View</a>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Distribusi Log Table -->
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-5 pb-2 mb-3 border-bottom">
                    <h1 class="h2">Distribusi Log</h1>
                </div>
                <div class="table-responsive">
                    <table class="table table-striped table-hover">
                        <thead class="table-dark">
                            <tr>
                                <th>#</th>
                                <th>Log ID</th>
                                <th>Type</th>
                                <th>Timestamp</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>1</td>
                                <td>LOG12345</td>
                                <td>Normal</td>
                                <td>2024-12-01 14:23:00</td>
                                <td><span class="badge bg-success">Processed</span></td>
                            </tr>
                            <tr>
                                <td>2</td>
                                <td>LOG12346</td>
                                <td>SQLI</td>
                                <td>2024-12-01 14:25:00</td>
                                <td><span class="badge bg-danger">Failed</span></td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <!-- Top 5 IP Penyerang Table -->
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-5 pb-2 mb-3 border-bottom">
                    <h1 class="h2">Top 5 IP Penyerang</h1>
                </div>
                <div class="table-responsive">
                    <table class="table table-striped table-hover">
                        <thead class="table-dark">
                            <tr>
                                <th>#</th>
                                <th>IP Address</th>
                                <th>Attempts</th>
                                <th>Last Attack</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>1</td>
                                <td>192.168.1.1</td>
                                <td>150</td>
                                <td>2024-12-01 13:45:00</td>
                            </tr>
                            <tr>
                                <td>2</td>
                                <td>203.0.113.5</td>
                                <td>120</td>
                                <td>2024-12-01 13:50:00</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </main>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>

