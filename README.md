A. Untuk Backend
1. menyalakan environment di folder backendd

   source myenv/bin/activate
   
4. Install pandas
  
   pip install pandas

B. Untuk frontend
1. Masuk dalam database dan Buat database

   mysql -u root -p
   
   CREATE DATABASE dbci3;
   
3. Buat tabel yang bernama users

      CREATE TABLE users (
       id INT AUTO_INCREMENT PRIMARY KEY,
       nama VARCHAR(100) NOT NULL,
       username VARCHAR(50) NOT NULL UNIQUE,
       email VARCHAR(100) NOT NULL UNIQUE,
       password VARCHAR(255) NOT NULL,
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
   );


4. Ganti Ip
    pada bagian safelogs/application/config/config.php ganti ipnya dengan ip server kalian
    
    $config['base_url'] = 'http://(Ip server)/capstone/safelogs/';
