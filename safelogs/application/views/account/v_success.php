<?php defined('BASEPATH') OR exit('No direct script access allowed'); ?>
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Notifikasi</title>

  <!-- Mengimpor Bootstrap dari CDN -->
  <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      background-color: #f8f9fa;
      font-family: 'Arial', sans-serif;
    }

    .notification-container {
      margin-top: 80px;
      padding: 40px;
      background-color: #ffffff;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
      border-radius: 10px;
      max-width: 600px;
      margin-left: auto;
      margin-right: auto;
    }

    h3 {
      color: #007bff;
      margin-bottom: 30px;
      font-weight: bold;
    }

    .btn-back {
      background-color: #007bff;
      color: white;
      border-radius: 5px;
    }

    .btn-back:hover {
      background-color: #0056b3;
      text-decoration: none;
    }
  </style>
</head>
<body>

  <!-- Kontainer utama untuk halaman notifikasi -->
  <div class="container notification-container">
    <h3 class="text-center"><?php echo $message; ?></h3>

    <!-- Tombol Kembali ke Login -->
    <p class="text-center">
      <a href="<?php echo site_url('login'); ?>" class="btn btn-back px-4 py-2">Kembali ke Login</a>
    </p>
  </div>

  <!-- Mengimpor JavaScript dan jQuery dari CDN -->
  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
  <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.bundle.min.js"></script>

</body>
</html>
