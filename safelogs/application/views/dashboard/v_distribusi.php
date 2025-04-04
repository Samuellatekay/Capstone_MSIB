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
      margin: 0;
      padding: 0;
    }
    .sidebar {
      position: relative;
      height: 100vh;
      background-color: #343a40;
      color: white;
      overflow: hidden;
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
  </style>
  
</head>
<body>
  <div class="container-fluid">
    <div class="row">
      <nav class="col-md-2 d-none d-md-block sidebar">
        <div class="sidebar-sticky">
          <h3 class="text-center py-3">SafeLogs</h3>
          <ul class="nav flex-column">
            <li class="nav-item">
              <h5><a href="<?php echo site_url('dashboard'); ?>">Dashboard</a></h5>
            </li>
            <li class="nav-item">
              <h5><a href="#">Metrik Akurasi</a></h5>
            </li>
            <li class="nav-item">
              <h5><a href="<?php echo site_url('top5'); ?>">Top 5 IP</a></h5>
            </li>
          </ul>
          <h5 class="logout-link"><a href="<?php echo site_url('login/logout'); ?>">Keluar</a></h5>
        </div>
      </nav>
            <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">Selamat datang di halaman dashboard, <strong><?php echo ucfirst($this->session->userdata('username')); ?></strong>!</h1>
                </div>

                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-5 pb-2 mb-3 border-bottom">
                    <h1 class="h2">Metrik Akurasi</h1>
                </div>
                <div class="table-responsive">
                    <table class="table table-striped table-hover">
                        <thead class="table-dark">
                            <tr>
                                <th>#</th>
                                <th>Kategori</th>
                                <th>Total Log</th>
                                <th>Terdeteksi Benar</th>
                                <th>Akurasi</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>1</td>
                                <td>Normal</td>
                                <td>83</td>
                                <td>84</td>
                                <td>100%</td>
                            </tr>
                            <tr>
                                <td>2</td>
                                <td>Brute force</td>
                                <td>2</td>
                                <td>0</td>
                                <td>%</td>
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

