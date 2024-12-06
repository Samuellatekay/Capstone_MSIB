<?php
defined('BASEPATH') OR exit('No direct script access allowed');
?><!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SafeLogs - Beranda</title>
  <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
  <style>
      body {
          background-color: #f3f6f9;
          font-family: 'Arial', sans-serif;
          display: flex;
          flex-direction: column;
          min-height: 100vh;
          margin: 0;
      }
      .main-container {
          flex: 1;
          margin-top: 50px; 
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 20px 0;
      }
      .main-text {
          max-width: 50%;
      }
      h1 {
          color: #0056b3;
          font-weight: bold;
      }
      p.lead {
          color: #333;
          margin-top: 20px;
      }
      .btn-primary {
          background-color: #0056b3;
          border: none;
      }
      .btn-primary:hover {
          background-color: #003d82;
      }
      .btn-success {
          background-color: #28a745;
          border: none;
      }
      .btn-success:hover {
          background-color: #218838;
      }
      .img-container {
          max-width: 40%;
          text-align: center;
      }
      .img-container img {
          width: 300px;
          height: 300px;
          border-radius: 50%; 
          object-fit: cover; 
          box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
      }
      footer {
          background-color: #343a40;
          color: #fff;
          text-align: center;
          padding: 15px 0;
          margin-top: auto;
      }
      footer p {
          margin: 0;
      }
  </style>
</head>
<body>

  <nav class="navbar navbar-expand-lg navbar-light bg-white shadow-sm">
    <div class="container">
      <a class="navbar-brand font-weight-bold text-primary" href="#">SafeLogs</a>
      <div class="ml-auto">
        <a href="<?php echo site_url('login'); ?>" class="btn btn-primary mr-2">Masuk</a>
        <a href="<?php echo site_url('register'); ?>" class="btn btn-success">Daftar</a>
      </div>
    </div>
  </nav>

  <div class="container main-container">
    <div class="main-text">
      <h1>Selamat Datang di SafeLogs!</h1>
      <p class="lead">SafeLogs adalah platform log monitoring yang dirancang untuk membantu mengelola, menganalisis, dan melindungi data log dengan mudah dan aman.</p>
      <p>Dengan teknologi canggih dan antarmuka yang ramah pengguna, SafeLogs menjadi solusi ideal bagi organisasi Anda untuk meningkatkan keamanan dan efisiensi operasional.</p>
    </div>

    <div class="img-container">
      <img src="https://www.how2shout.com/wp-content/uploads/2019/10/PAst-SSH-records-of-login-in-CentOS.jpg" alt="SafeLogs Image">
    </div>
  </div>

  <footer>
    <div class="container">
        <p>&copy; 2024 SafeLogs. Semua hak dilindungi.</p>
        <p>Keamanan Anda adalah prioritas kami.</p>
    </div>
  </footer>

  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
  <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.bundle.min.js"></script>
  
</body>
</html>
