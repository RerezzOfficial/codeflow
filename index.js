const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt'); // Untuk hashing password
const session = require('express-session'); // Untuk sesi pengguna

// Inisialisasi express
const app = express();

// Middleware untuk parsing body request
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Middleware untuk sesi
app.use(
  session({
    secret: 'your_secret_key', 
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }, // Ubah ke `true` jika menggunakan HTTPS
  })
);

// Path file JSON
const akunFile = path.join(__dirname, 'akun.json');

function readAkunFile() {
  if (!fs.existsSync(akunFile)) {
    fs.writeFileSync(akunFile, JSON.stringify([])); 
  }
  const data = fs.readFileSync(akunFile, 'utf8');
  return JSON.parse(data);
}

function writeAkunFile(data) {
  fs.writeFileSync(akunFile, JSON.stringify(data, null, 2));
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/user-count', (req, res) => {
  try {
    const data = readAkunFile();
    res.json({ count: data.length });
  } catch (err) {
    console.error('Error saat membaca jumlah pengguna:', err);
    res.status(500).json({ error: 'Gagal mengambil jumlah pengguna' });
  }
});

// Route untuk proses daftar
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Username dan password harus diisi!');
  }

  try {
    const data = readAkunFile();

    // Cek apakah username sudah ada
    const existingUser = data.find((user) => user.username === username);
    if (existingUser) {
      return res.status(400).send('Username sudah terdaftar!');
    }

    // Hash password sebelum menyimpannya
    const hashedPassword = await bcrypt.hash(password, 10);

    // Menyimpan akun baru
    data.push({ username, password: hashedPassword });
    writeAkunFile(data);

    res.redirect('/auth/login.html');
  } catch (err) {
    console.error('Error saat proses daftar:', err);
    res.status(500).send('Gagal mendaftarkan pengguna');
  }
});

// Route untuk proses login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Username dan password harus diisi!');
  }

  try {
    const data = readAkunFile();

    // Cek apakah username ada di database
    const user = data.find((user) => user.username === username);
    if (!user) {
      return res.status(401).send('Username atau password salah!');
    }

    // Bandingkan password dengan hash yang disimpan
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).send('Username atau password salah!');
    }

    // Set session
    req.session.user = { username: user.username };

    res.redirect('/dashboard.html'); // Setelah login berhasil
  } catch (err) {
    console.error('Error saat proses login:', err);
    res.status(500).send('Gagal memproses login');
  }
});

// Route untuk logout
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Gagal logout:', err);
      return res.status(500).send('Gagal logout');
    }
    res.redirect('/');
  });
});

// Jalankan server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});
