<?php defined('BASEPATH') OR exit('No direct script access allowed'); ?>
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SafeLogs</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.1/css/all.min.css" crossorigin="anonymous" referrerpolicy="no-referrer" />
  <style>
    body {
      background-color: #f8f9fa;
      margin: 0;
      padding: 0;
    }
    .sidebar {
      position: relative;
      height: 100vh;
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
      border-radius: 5px;
    }
    .logout-link {
      position: absolute;
      bottom: 20px;
      width: 90%;
    }
    canvas {
      margin: 20px auto;
      display: block;
    }
  </style>
</head>
<body>
  <div class="container-fluid">
    <div class="row">
      <nav class="col-md-2 d-none d-md-block sidebar">
        <div class="sidebar-sticky">
          <h3 class="text-center py-3">SafeLogs</h3>
          <ul class="nav flex-column">
            <li class="nav-item"><h5><a href="#">Dashboard</a></h5></li>
            <li class="nav-item"><h5><a href="<?php echo site_url('distribusi'); ?>">Metrik Akurasi</a></h5></li>
            <li class="nav-item"><h5><a href="<?php echo site_url('top5'); ?>">Top 5 IP</a></h5></li>
          </ul>
          <h5 class="logout-link"><a href="<?php echo site_url('login/logout'); ?>">Keluar</a></h5>
        </div>
      </nav>
      <main class="col-md-10 ms-sm-auto col-lg-10 px-md-4">
        <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
          <h1 class="h2">Selamat datang di halaman dashboard, <strong><?php echo ucfirst($this->session->userdata('username')); ?></strong>!</h1>
        </div>
        <!-- Grid untuk Card Statistik -->
        <div class="row">
          <div class="col-md-3">
            <div class="card mb-3">
              <div class="card-body">
                <h5 class="card-title">Normal</h5>
                <i class="fa-solid fa-user float-end" style="font-size: 50px;"></i>
                <p class="display-5 card-text"><?= $log_data['Normal']; ?></p>
              </div>
            </div>
          </div>
          <div class="col-md-3">
            <div class="card mb-3">
              <div class="card-body">
                <h5 class="card-title">SQLI</h5>
                <img width="48" height="48" src="https://img.icons8.com/external-outline-black-m-oki-orlando/32/external-sql-injection-cyber-security-outline-outline-black-m-oki-orlando.png" class="float-end">
                <p class="display-5 card-text"><?= $log_data['SQL Injection']; ?></p>
              </div>
            </div>
          </div>
          <div class="col-md-3">
            <div class="card mb-3">
              <div class="card-body">
                <h5 class="card-title">XSS</h5>
                <img width="58" height="58" src="https://img.icons8.com/external-linear-outline-icons-papa-vector/78/external-XSS-hacker-attack-linear-outline-icons-papa-vector.png" alt="xss" class="float-end"/>
                <p class="display-5 card-text"><?= $log_data['XSS']; ?></p>
              </div>
            </div>
          </div>
          <div class="col-md-3">
            <div class="card mb-3">
              <div class="card-body">
                <h5 class="card-title">Brute Force</h5>
                <img width="58" height="58" src="https://img.icons8.com/quill/100/unlock-2.png" alt="unlock-2" class="float-end">
                <p class="display-5 card-text"><?= $log_data['Brute Force']; ?></p>
              </div>
            </div>
          </div>
          <div class="col-md-3">
            <div class="card mb-3">
              <div class="card-body">
                <h5 class="card-title">Total Log</h5>
                <img width="50" height="50" src="https://img.icons8.com/isometric-line/50/edit-property.png" alt="edit-property" class="float-end">
                <p class="display-5 card-text"><?= $total_logs; ?></p>
              </div>
            </div>
          </div>
        </div>
        <!-- Grid untuk Pie Chart -->
        <div class="row">
          <div class="col-md-4">
            <div class="card">
              <div class="card-body">
                <h5 class="card-title">Distribusi Log</h5>
                <canvas id="logPieChart"></canvas>
                
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script>
    const ctx = document.getElementById('logPieChart').getContext('2d');
    const data = {
      labels: ['Normal', 'SQL Injection','XSS', 'Brute Force'],
      datasets: [{
        label: 'Distribusi Log',
        data: [<?= $log_data['Normal']; ?>, <?= $log_data['SQL Injection']; ?>,<?= $log_data['XSS']; ?>, <?= $log_data['Brute Force']; ?>],
        backgroundColor: ['#FCC737', '#F26B0F', '#E73879','#7E1891'],
        borderColor: ['#FCC737', '#F26B0F', '#E73879','#7E1891'],
        borderWidth: 1
      }]
    };
    const config = {
      type: 'pie',
      data: data,
      options: {
        responsive: true,
        plugins: {
          legend: {
            position: 'bottom',  // Menempatkan legenda di bawah pie chart
            labels: {
              boxWidth: 10,      // Ukuran kotak label
              padding: 10        // Jarak antar label
            }
          }
        }
      }
    };
    new Chart(ctx, config);

  </script>
</body>
</html>
