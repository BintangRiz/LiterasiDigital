<?php
// Konfigurasi database
$host = "localhost";
$dbname = "ondkos";
$username = "root";
$password = "";

// Menghubungkan ke database
$conn = new mysqli($host, $username, $password, $dbname);

// Cek koneksi
if ($conn->connect_error) {
    die("Koneksi gagal: " . $conn->connect_error);
}

// Validasi data dari form
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim($_POST["username"]);
    $nama = trim($_POST["nama"]);
    $no_handphone = trim($_POST["no_handphone"]);
    $alamat = trim($_POST["alamat"]);
    $email = trim($_POST["email"]);
    $password = trim($_POST["password"]);

    // Validasi input
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        die("Email tidak valid! <a href='register.html'>Kembali ke Form Registrasi</a>");
    }

    if (!preg_match("/^[0-9]{10,15}$/", $no_handphone)) {
        die("Nomor handphone tidak valid! <a href='register.html'>Kembali ke Form Registrasi</a>");
    }

    if (strlen($password) < 8) {
        die("Password harus minimal 8 karakter! <a href='register.html'>Kembali ke Form Registrasi</a>");
    }

    // Cek apakah email sudah terdaftar
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        echo "Email sudah terdaftar! <a href='register.html'>Kembali ke Form Registrasi</a>";
    } else {
        // Enkripsi password
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Masukkan data ke database
        $stmt = $conn->prepare("INSERT INTO users (username, nama, no_handphone, alamat, email, password) 
                                VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("ssssss", $username, $nama, $no_handphone, $alamat, $email, $hashed_password);

        if ($stmt->execute()) {
            echo "Registrasi berhasil! <a href='/Login/login.php'>Kembali ke Halaman Utama</a>";
        } else {
            error_log("Error: " . $stmt->error);
            echo "Terjadi kesalahan saat memproses data. Silakan coba lagi nanti.";
        }
    }
    $stmt->close();
}

// Tutup koneksi
$conn->close();
?>
