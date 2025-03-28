A. Untuk Backend
1. menyalakan environment di folder backendd 
   source myenv/bin/activate
   
3. Install pandas
    pip install pandas

B. Untuk frontend
1. Masuk dalam database dan Buat database

   mysql -u root -p
   
   CREATE DATABASE dbci3;

2. Ganti Ip
    pada bagian safelogs/application/config/config.php ganti ipnya dengan ip server kalian
    
    $config['base_url'] = 'http://(Ip server)/capstone/safelogs/';
