<?php defined('BASEPATH') OR exit('No direct script access allowed'); ?>
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Pendaftaran Akun</title>

  <!-- Mengimpor Bootstrap dari CDN -->
  <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
  <style>
      body {
          background-color: #f8f9fa;
      }
      .register-container {
          margin-top: 50px;
          margin-bottom: 50px;
          padding: 40px;
          background-color: #ffffff;
          box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
          border-radius: 10px;
      }
      h2 {
          color: #007bff;
      }
      .form-group label {
          font-weight: bold;
      }
  </style>
</head>
<body>

  <!-- Kontainer utama dengan padding dan margin -->
  <div class="container register-container">
    <h2 class="text-center">Pendaftaran Akun</h2>

    <!-- Menampilkan pesan notifikasi jika ada flashdata -->
    <?php if($this->session->flashdata('error')): ?>
      <div class="alert alert-danger" role="alert">
        <?php echo $this->session->flashdata('error'); ?>
      </div>
    <?php endif; ?>

    <!-- Form pendaftaran menggunakan form_open() dari CodeIgniter -->
    <?php echo form_open('register'); ?>
    <div class="form-group">
      <label for="name">Nama:</label>
      <input type="text" class="form-control" name="name" id="name" value="<?php echo set_value('name'); ?>" placeholder="Masukkan nama lengkap">
      <?php echo form_error('name', '<small class="text-danger">', '</small>'); ?>
    </div>

    <div class="form-group">
      <label for="username">Username:</label>
      <input type="text" class="form-control" name="username" id="username" value="<?php echo set_value('username'); ?>" placeholder="Masukkan username">
      <?php echo form_error('username', '<small class="text-danger">', '</small>'); ?>
    </div>

    <div class="form-group">
      <label for="email">Email:</label>
      <input type="email" class="form-control" name="email" id="email" value="<?php echo set_value('email'); ?>" placeholder="Masukkan email">
      <?php echo form_error('email', '<small class="text-danger">', '</small>'); ?>
    </div>

    <div class="form-group">
      <label for="password">Password:</label>
      <input type="password" class="form-control" name="password" id="password" value="<?php echo set_value('password'); ?>" placeholder="Masukkan password">
      <?php echo form_error('password', '<small class="text-danger">', '</small>'); ?>
    </div>

    <div class="form-group">
      <label for="password_conf">Konfirmasi Password:</label>
      <input type="password" class="form-control" name="password_conf" id="password_conf" value="<?php echo set_value('password_conf'); ?>" placeholder="Konfirmasi password">
      <?php echo form_error('password_conf', '<small class="text-danger">', '</small>'); ?>
    </div>

    <button type="submit" class="btn btn-primary btn-block">Daftar</button>
    <?php echo form_close(); ?>

    <!-- Link untuk kembali ke halaman beranda -->
    <p class="text-center mt-3">
      Sudah punya akun? <a href="<?php echo site_url('login'); ?>">Klik di sini untuk Masuk</a>
    </p>

    <!-- Link kembali ke beranda -->
    <p class="text-center">
      Kembali ke beranda, Silakan klik <?php echo anchor(site_url().'/beranda','di sini..'); ?>
    </p>
  </div>

  <!-- Mengimpor JavaScript dan jQuery dari CDN -->
  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
  <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.bundle.min.js"></script>

</body>
</html>
