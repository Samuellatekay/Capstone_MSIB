<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Metrik Akurasi</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center mb-4">Metrik Akurasi Testing</h1>
        <table class="table table-striped table-hover">
            <thead class="table-dark">
                <tr>
                    <th>#</th>
                    <th>Kategori</th>
                    <th>Total Log</th>
                    <th>Terdeteksi Benar</th>
                    <th>Akurasi (%)</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($metrics as $index => $metric): ?>
                    <tr>
                        <td><?= $index + 1; ?></td>
                        <td><?= $metric['kategori']; ?></td>
                        <td><?= $metric['total_log']; ?></td>
                        <td><?= $metric['terdeteksi_benar']; ?></td>
                        <td><?= $metric['akurasi']; ?>%</td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</body>
</html>
