const express = require("express");
const app = express();
const session = require("express-session");
const path = require("path");
const bcrypt = require("bcrypt");
const multer = require("multer");
const fs = require("fs"); 
const db = require("./config/db");
const { requireAdmin, requirePelanggan } = require("./middleware/auth");

// --- [BARU] Import Library untuk Email & Token ---
const nodemailer = require("nodemailer");
const crypto = require("crypto"); 
// -------------------------------------------------

// ==============================================
// 1. MIDDLEWARE & KONFIGURASI UTAMA
// ==============================================

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Konfigurasi Session
app.use(session({
    secret: "rahasia-kurnia-super-aman",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 Hari
}));

// Folder Public
app.use(express.static(path.join(__dirname, "public")));

// --- [BARU] KONFIGURASI PENGIRIM EMAIL (NODEMAILER) ---
// PENTING: Ganti dengan Email & App Password Gmail Anda
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'debbygusdiahkbar205@gmail.com',  // <--- GANTI EMAIL ANDA
        pass: 'bhhpqcrtlmtblpfu'    // <--- GANTI APP PASSWORD GMAIL (Bukan password login biasa)
    }
});
// ------------------------------------------------------

// --- MIDDLEWARE GLOBAL: MENGHITUNG KERANJANG & WISHLIST ---
const getGlobalCounts = (req, res, next) => {
    res.locals.cartCount = 0;
    res.locals.wishlistCount = 0;
    res.locals.user = req.session.user || null;

    if (req.session.user && req.session.user.role === 'pelanggan') {
        const userId = req.session.user.id;
        
        const sqlCart = "SELECT SUM(quantity) as itemCount FROM cart_items WHERE user_id = ?";
        const sqlWish = "SELECT COUNT(*) as wishCount FROM wishlist WHERE user_id = ?";

        db.query(sqlCart, [userId], (err, cartRes) => {
            if (!err && cartRes[0]) {
                res.locals.cartCount = cartRes[0].itemCount || 0;
            }
            
            db.query(sqlWish, [userId], (err, wishRes) => {
                if (!err && wishRes[0]) {
                    res.locals.wishlistCount = wishRes[0].wishCount || 0;
                }
                next();
            });
        });
    } else {
        next();
    }
};
app.use(getGlobalCounts); 

// View Engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));


// ==============================================
// 2. KONFIGURASI UPLOAD GAMBAR (MULTER)
// ==============================================

const uploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    if (allowedTypes.test(file.mimetype) && allowedTypes.test(path.extname(file.originalname).toLowerCase())) {
        return cb(null, true);
    }
    cb('Error: Hanya file gambar yang diperbolehkan!');
};

const upload = multer({ 
    storage: storage, 
    limits: { fileSize: 5 * 1024 * 1024 }, 
    fileFilter: fileFilter 
});

const uploadMultiple = upload.fields([
    { name: 'image', maxCount: 1 },
    { name: 'image2', maxCount: 1 },
    { name: 'image3', maxCount: 1 },
    { name: 'image4', maxCount: 1 }
]);


// ==============================================
// 3. ROUTE PUBLIK
// ==============================================

app.get("/", (req, res) => {
    db.query("SELECT * FROM products ORDER BY created_at DESC LIMIT 6", (err, results) => {
        res.render("index", { products: err ? [] : results });
    });
});

app.get("/katalog", (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    const category = req.query.kategori;

    let params = [];
    let countParams = [];
    let countSql = "SELECT COUNT(*) AS total FROM products";
    let sql = "SELECT * FROM products";

    if (category) {
        countSql += " WHERE category = ?";
        sql += " WHERE category = ?";
        params.push(category);
        countParams.push(category);
    }

    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?";
    params.push(limit, offset);
    
    db.query(countSql, countParams, (err, countRes) => {
        if (err) return res.render("katalog", { products: [], currentPage: 1, totalPages: 0, currentCategory: 'Semua', wishlistIds: [] });
        
        const totalItems = countRes[0].total;
        const totalPages = Math.ceil(totalItems / limit);
        
        db.query(sql, params, (err, results) => {
            let wishlistIds = [];
            if (req.session.user) {
                db.query("SELECT product_id FROM wishlist WHERE user_id = ?", [req.session.user.id], (err, wRes) => {
                    if (!err) wishlistIds = wRes.map(w => w.product_id);
                    res.render("katalog", { 
                        products: results, currentPage: page, totalPages: totalPages,
                        currentCategory: category || 'Semua', wishlistIds: wishlistIds
                    });
                });
            } else {
                res.render("katalog", { 
                    products: results, currentPage: page, totalPages: totalPages,
                    currentCategory: category || 'Semua', wishlistIds: []
                });
            }
        });
    });
});

app.get("/produk/:id", (req, res) => {
    const productId = req.params.id;
    db.query("SELECT * FROM products WHERE id = ?", [productId], (err, results) => {
        if (err || results.length === 0) return res.redirect("/katalog");
        res.render("detail-produk", { product: results[0] });
    });
});


// ==============================================
// 4. ROUTE AUTENTIKASI
// ==============================================

app.get("/login", (req, res) => {
    if (req.session.user) {
        return res.redirect(req.session.user.role === 'admin' ? "/admin/dashboard" : "/pelanggan/dashboard");
    }
    res.render("login");
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;
    db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
        if (err || results.length === 0) return res.redirect("/login?error=user_not_found");
        
        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.redirect("/login?error=wrong_password");
        
        req.session.user = { 
            id: user.id, username: user.username, email: user.email, role: user.role 
        };
        
        res.redirect(user.role === "admin" ? "/admin/dashboard" : "/pelanggan/dashboard");
    });
});

app.get("/register", (req, res) => {
    if (req.session.user) return res.redirect("/");
    res.render("register");
});

app.post("/register", async (req, res) => {
    const { username, email, password, confirm_password } = req.body;
    if (password !== confirm_password) return res.send('<script>alert("Password tidak cocok!"); window.history.back();</script>');
    
    try {
        const [checkUser] = await db.promise().query("SELECT id FROM users WHERE username = ? OR email = ?", [username, email]);
        if (checkUser.length > 0) return res.send('<script>alert("Username/Email sudah terdaftar!"); window.history.back();</script>');
        
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.promise().query("INSERT INTO users (username, email, password, full_name, role) VALUES (?, ?, ?, ?, 'pelanggan')", [username, email, hashedPassword, username]);
        
        res.send('<script>alert("Registrasi Berhasil! Silakan Login."); window.location.href = "/login";</script>');
    } catch (error) { res.status(500).send("Error Server"); }
});

app.get("/logout", (req, res) => {
    req.session.destroy(() => res.redirect("/login"));
});

// ==============================================
// [BARU] LOGIKA RESET PASSWORD (DENGAN EMAIL)
// ==============================================

// 1. Halaman Input Email Lupa Password
app.get("/forgot-password", (req, res) => res.render("forgot-password"));

// 2. Proses Kirim Email Link Reset
app.post("/forgot-password", async (req, res) => {
    const { email } = req.body;

    try {
        // Cek Email di Database
        const [users] = await db.promise().query("SELECT * FROM users WHERE email = ?", [email]);
        
        if (users.length === 0) {
            return res.send('<script>alert("Email tidak ditemukan di sistem kami."); window.history.back();</script>');
        }

        // Generate Token
        const token = crypto.randomBytes(32).toString("hex");
        const expireTime = new Date(Date.now() + 3600000); // 1 Jam dari sekarang

        // Simpan Token ke Database
        await db.promise().query("UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE email = ?", [token, expireTime, email]);

        // Buat Link Reset
        const resetLink = `http://localhost:3000/reset-password/${token}`;

        // Konfigurasi Email
        const mailOptions = {
            from: '"Kurnia Store" <no-reply@kurniastore.com>',
            to: email,
            subject: 'Permintaan Reset Password - Kurnia Store',
            html: `
                <h3>Permintaan Reset Password</h3>
                <p>Silakan klik link di bawah ini untuk mereset password Anda:</p>
                <a href="${resetLink}" style="padding:10px 20px; background:blue; color:white; text-decoration:none; border-radius:5px;">Reset Password</a>
                <p>Atau klik link ini: <a href="${resetLink}">${resetLink}</a></p>
                <p>Link ini berlaku selama 1 jam.</p>
            `
        };

        // Kirim Email
        await transporter.sendMail(mailOptions);
        res.send('<script>alert("Link reset password telah dikirim ke email Anda! Silakan cek Inbox/Spam."); window.location.href = "/login";</script>');

    } catch (err) {
        console.error("Error Email:", err);
        res.send('<script>alert("Gagal mengirim email. Pastikan koneksi internet lancar atau hubungi admin."); window.history.back();</script>');
    }
});

// 3. Halaman Form Password Baru (Verifikasi Token)
app.get("/reset-password/:token", async (req, res) => {
    const { token } = req.params;

    // Cari user dengan token yang valid dan belum expired
    const [users] = await db.promise().query(
        "SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > NOW()", 
        [token]
    );

    if (users.length === 0) {
        return res.send('<script>alert("Link reset password tidak valid atau sudah kadaluarsa!"); window.location.href = "/forgot-password";</script>');
    }

    // Render file view 'reset-password.ejs' (Pastikan file ini dibuat)
    res.render("reset-password", { token }); 
});

// 4. Proses Update Password Baru ke Database
app.post("/reset-password/:token", async (req, res) => {
    const { token } = req.params;
    const { password, confirm_password } = req.body;

    if (password !== confirm_password) {
        return res.send('<script>alert("Password dan Konfirmasi Password tidak cocok!"); window.history.back();</script>');
    }

    try {
        // Cek Token Sekali Lagi (Security)
        const [users] = await db.promise().query(
            "SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > NOW()", 
            [token]
        );

        if (users.length === 0) {
            return res.send('<script>alert("Token expired atau tidak valid."); window.location.href = "/forgot-password";</script>');
        }

        const user = users[0];
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update Password & Hapus Token (Supaya tidak bisa dipakai lagi)
        await db.promise().query(
            "UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?", 
            [hashedPassword, user.id]
        );

        res.send('<script>alert("Password berhasil diubah! Silakan login dengan password baru."); window.location.href = "/login";</script>');

    } catch (err) {
        console.error("Error Reset DB:", err);
        res.send('<script>alert("Terjadi kesalahan sistem saat mereset password."); window.history.back();</script>');
    }
});

// ==============================================
// AKHIR LOGIKA RESET PASSWORD
// ==============================================


// ==============================================
// 5. FITUR PELANGGAN
// ==============================================

app.get("/pelanggan/dashboard", requirePelanggan, async (req, res) => {
    const userId = req.session.user.id;
    try {
        const [totalOrderRes, shippedOrderRes, wishlistRes, recentOrdersRes] = await Promise.all([
            db.promise().query("SELECT COUNT(*) as count FROM orders WHERE user_id = ?", [userId]),
            db.promise().query("SELECT COUNT(*) as count FROM orders WHERE user_id = ? AND status = 'Shipped'", [userId]),
            db.promise().query("SELECT COUNT(*) as count FROM wishlist WHERE user_id = ?", [userId]),
            db.promise().query("SELECT * FROM orders WHERE user_id = ? ORDER BY order_date DESC LIMIT 3", [userId])
        ]);

        res.render("pelanggan-dashboard", { 
            user: req.session.user,
            stats: {
                totalOrders: totalOrderRes[0][0].count,
                shippedOrders: shippedOrderRes[0][0].count,
                totalWishlist: wishlistRes[0][0].count
            },
            recentOrders: recentOrdersRes[0]
        });
    } catch (err) {
        console.error("Error dashboard:", err);
        res.render("pelanggan-dashboard", { 
            user: req.session.user,
            stats: { totalOrders: 0, shippedOrders: 0, totalWishlist: 0 },
            recentOrders: []
        });
    }
});

app.get("/pelanggan/profil", requirePelanggan, (req, res) => {
    let success_msg = req.query.success === 'data' ? "Data profil berhasil diperbarui!" : (req.query.success === 'pass' ? "Password berhasil diubah!" : null);
    let error_msg = req.query.error === 'data_sama' ? "Username/Email sudah digunakan!" : (req.query.error === 'pass_lama' ? "Password lama salah!" : null);

    db.query("SELECT * FROM users WHERE id = ?", [req.session.user.id], (err, results) => {
        if (err || results.length === 0) return res.redirect("/pelanggan/dashboard");
        res.render("pelanggan-profil", { userData: results[0], success_msg, error_msg });
    });
});

app.post("/pelanggan/profil/data", requirePelanggan, async (req, res) => {
    const { full_name, username, email, phone_number } = req.body;
    const userId = req.session.user.id;
    try {
        const [check] = await db.promise().query("SELECT id FROM users WHERE (username=? OR email=?) AND id!=?", [username, email, userId]);
        if (check.length > 0) return res.redirect("/pelanggan/profil?error=data_sama");
        
        await db.promise().query("UPDATE users SET full_name=?, username=?, email=?, phone_number=? WHERE id=?", [full_name, username, email, phone_number, userId]);
        req.session.user.username = username; 
        req.session.user.email = email;
        res.redirect("/pelanggan/profil?success=data");
    } catch (err) { res.redirect("/pelanggan/profil"); }
});

app.post("/pelanggan/profil/password", requirePelanggan, async (req, res) => {
    const { old_password, new_password, confirm_password } = req.body;
    const userId = req.session.user.id;
    try {
        const [resUser] = await db.promise().query("SELECT password FROM users WHERE id=?", [userId]);
        const isMatch = await bcrypt.compare(old_password, resUser[0].password);
        if (!isMatch) return res.redirect("/pelanggan/profil?error=pass_lama");
        if (new_password !== confirm_password) return res.redirect("/pelanggan/profil?error=pass_cocok");
        
        const hashed = await bcrypt.hash(new_password, 10);
        await db.promise().query("UPDATE users SET password=? WHERE id=?", [hashed, userId]);
        res.redirect("/pelanggan/profil?success=pass");
    } catch (err) { res.redirect("/pelanggan/profil"); }
});

app.get("/pelanggan/pesanan", requirePelanggan, (req, res) => {
    db.query("SELECT * FROM orders WHERE user_id = ? ORDER BY order_date DESC", [req.session.user.id], (err, results) => {
        res.render("pelanggan-pesanan", { orders: results || [], user: req.session.user });
    });
});

app.get("/pelanggan/pesanan/detail/:id", requirePelanggan, (req, res) => {
    const orderId = req.params.id;
    const userId = req.session.user.id;
    db.query("SELECT id FROM orders WHERE id = ? AND user_id = ?", [orderId, userId], (err, orders) => {
        if (err || orders.length === 0) return res.status(404).json({ error: "Not Found" });
        const sql = `SELECT oi.*, p.name, p.image_url FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?`;
        db.query(sql, [orderId], (err, items) => {
            if (err) return res.status(500).json({ error: "Server Error" });
            res.json(items);
        });
    });
});

app.get("/pelanggan/pesanan/cancel/:id", requirePelanggan, (req, res) => {
    db.query("UPDATE orders SET status = 'Cancelled' WHERE id = ? AND user_id = ? AND status = 'Pending'", [req.params.id, req.session.user.id], () => {
        res.redirect("/pelanggan/pesanan");
    });
});

// --- Route Hapus Pesanan (Hanya untuk Status Cancelled) ---
app.get("/pelanggan/pesanan/hapus/:id", requirePelanggan, (req, res) => {
    const orderId = req.params.id;
    const userId = req.session.user.id;

    // 1. Cek dulu apakah pesanan ini milik user DAN statusnya 'Cancelled'
    // Ini penting untuk keamanan agar user tidak bisa menghapus pesanan orang lain
    // atau menghapus pesanan yang masih berjalan.
    const sqlCheck = "SELECT * FROM orders WHERE id = ? AND user_id = ? AND status = 'Cancelled'";

    db.query(sqlCheck, [orderId, userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.redirect("/pelanggan/pesanan");
        }

        // Jika tidak ketemu atau status bukan Cancelled
        if (results.length === 0) {
            return res.send('<script>alert("Gagal menghapus! Pesanan tidak ditemukan atau status bukan Dibatalkan."); window.location.href="/pelanggan/pesanan";</script>');
        }

        // 2. Jika valid, hapus dari database
        // (Item di order_items akan otomatis terhapus jika Anda setting ON DELETE CASCADE di database,
        // jika tidak, query ini tetap akan menghapus header ordernya saja atau error tergantung setting DB)
        const sqlDelete = "DELETE FROM orders WHERE id = ?";
        db.query(sqlDelete, [orderId], (err) => {
            if (err) console.error(err);
            res.redirect("/pelanggan/pesanan");
        });
    });
});


// ==============================================
// 6. FITUR KERANJANG & CHECKOUT
// ==============================================

app.get("/keranjang", requirePelanggan, (req, res) => {
    const sql = `SELECT ci.id as cart_item_id, ci.quantity, p.* FROM cart_items ci JOIN products p ON ci.product_id = p.id WHERE ci.user_id = ?`;
    db.query(sql, [req.session.user.id], (err, items) => {
        if (err) return res.render("keranjang", { cartItems: [], subtotal: 0, total: 0 });
        let subtotal = 0;
        items.forEach(item => subtotal += item.price * item.quantity);
        res.render("keranjang", { cartItems: items, subtotal, total: subtotal });
    });
});

app.post("/keranjang/tambah", requirePelanggan, (req, res) => {
    const { product_id, quantity } = req.body;
    const qty = parseInt(quantity) || 1;
    const sql = `INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE quantity = quantity + ?`;
    db.query(sql, [req.session.user.id, product_id, qty, qty], (err) => {
        if (err) return res.send('<script>alert("Gagal tambah keranjang"); window.history.back();</script>');
        res.redirect("/keranjang");
    });
});

app.post("/keranjang/update/:id", requirePelanggan, (req, res) => {
    const newQty = parseInt(req.body.quantity);
    if (newQty <= 0) return res.redirect(`/keranjang/hapus/${req.params.id}`);
    db.query("UPDATE cart_items SET quantity = ? WHERE id = ? AND user_id = ?", [newQty, req.params.id, req.session.user.id], () => {
        res.redirect("/keranjang");
    });
});

app.get("/keranjang/hapus/:id", requirePelanggan, (req, res) => {
    db.query("DELETE FROM cart_items WHERE id = ? AND user_id = ?", [req.params.id, req.session.user.id], () => {
        res.redirect("/keranjang");
    });
});

app.get("/checkout", requirePelanggan, (req, res) => {
    const userId = req.session.user.id;
    const sql = `
        SELECT c.*, p.name, p.price, p.image_url 
        FROM cart_items c 
        JOIN products p ON c.product_id = p.id 
        WHERE c.user_id = ?
    `;
    db.query(sql, [userId], (err, items) => {
        if (err || items.length === 0) return res.redirect("/keranjang");
        
        let subtotal = 0;
        items.forEach(item => subtotal += item.price * item.quantity);
        res.render("checkout", { cartItems: items, subtotal, total: subtotal, user: req.session.user });
    });
});

app.post("/checkout", requirePelanggan, (req, res) => {
    const uploadSingle = upload.single('payment_proof');

    uploadSingle(req, res, async (err) => {
        if (err) {
            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.send('<script>alert("Gagal: Ukuran file bukti pembayaran terlalu besar! Maksimal 5MB."); window.history.back();</script>');
            }
            return res.send(`<script>alert("Gagal upload file: ${err.message}"); window.history.back();</script>`);
        }

        const userId = req.session.user.id;
        const { shipping_address, payment_method } = req.body; 
        
        if (!req.file) {
            return res.send('<script>alert("Harap upload bukti pembayaran!"); window.history.back();</script>');
        }

        const proofPath = '/uploads/' + req.file.filename;

        try {
            const [cartItems] = await db.promise().query(
                `SELECT c.*, p.price FROM cart_items c JOIN products p ON c.product_id = p.id WHERE c.user_id = ?`, 
                [userId]
            );

            if (cartItems.length === 0) return res.send('<script>alert("Keranjang kosong!"); window.location.href="/keranjang";</script>');

            let totalPrice = 0;
            cartItems.forEach(item => totalPrice += item.price * item.quantity);

            const [orderResult] = await db.promise().query(
                `INSERT INTO orders (user_id, total_price, status, shipping_address, payment_method, payment_proof) VALUES (?, ?, 'Pending', ?, ?, ?)`,
                [userId, totalPrice, shipping_address, payment_method, proofPath]
            );
            const orderId = orderResult.insertId;

            const orderItemsValues = cartItems.map(item => [orderId, item.product_id, item.quantity, item.price]);
            if (orderItemsValues.length > 0) {
                await db.promise().query(
                    `INSERT INTO order_items (order_id, product_id, quantity, price) VALUES ?`,
                    [orderItemsValues]
                );
            }

            await db.promise().query(`DELETE FROM cart_items WHERE user_id = ?`, [userId]);

            res.send('<script>alert("Pesanan Berhasil Dibuat! Bukti pembayaran telah dikirim."); window.location.href="/pelanggan/pesanan";</script>');
        } catch (err) {
            console.error("Checkout Error:", err);
            res.send('<script>alert("Terjadi kesalahan saat memproses checkout."); window.history.back();</script>');
        }
    });
});


// ==============================================
// 7. FITUR WISHLIST (LOVE)
// ==============================================

app.get("/wishlist", requirePelanggan, (req, res) => {
    const sql = `SELECT w.id as wishlist_id, p.* FROM wishlist w JOIN products p ON w.product_id = p.id WHERE w.user_id = ? ORDER BY w.created_at DESC`;
    db.query(sql, [req.session.user.id], (err, results) => {
        res.render("wishlist", { wishlistItems: results || [] });
    });
});

app.post("/wishlist/toggle", requirePelanggan, (req, res) => {
    const { product_id } = req.body;
    const userId = req.session.user.id;
    db.query("SELECT id FROM wishlist WHERE user_id = ? AND product_id = ?", [userId, product_id], (err, results) => {
        if (results.length > 0) {
            db.query("DELETE FROM wishlist WHERE id = ?", [results[0].id], () => res.json({ status: 'removed' }));
        } else {
            db.query("INSERT INTO wishlist (user_id, product_id) VALUES (?, ?)", [userId, product_id], () => res.json({ status: 'added' }));
        }
    });
});

app.get("/wishlist/hapus/:id", requirePelanggan, (req, res) => {
    db.query("DELETE FROM wishlist WHERE id = ? AND user_id = ?", [req.params.id, req.session.user.id], () => res.redirect("/wishlist"));
});


// ==============================================
// 8. FITUR ADMIN: PRODUK (CRUD + Multi Image)
// ==============================================

app.get("/admin/dashboard", requireAdmin, async (req, res) => {
    try {
        const [financialRes] = await db.promise().query(`
            SELECT 
                COUNT(*) as total_count, 
                SUM(total_price) as total_revenue 
            FROM orders 
            WHERE status = 'Completed'
        `);

        const totalSalesCount = financialRes[0].total_count || 0;
        const totalRevenue = financialRes[0].total_revenue || 0;
        const totalProfit = totalRevenue * 0.3; 

        const [topProducts] = await db.promise().query(`
            SELECT p.name, p.price, p.stock, SUM(oi.quantity) as total_sold 
            FROM order_items oi
            JOIN orders o ON oi.order_id = o.id
            JOIN products p ON oi.product_id = p.id
            WHERE o.status = 'Completed'
            GROUP BY p.id
            ORDER BY total_sold DESC
            LIMIT 5
        `);

        res.render("admin-dashboard", { 
            user: req.session.user,
            stats: {
                salesCount: totalSalesCount,
                revenue: totalRevenue,
                profit: totalProfit
            },
            topProducts: topProducts
        });

    } catch (err) {
        console.error("Error admin dashboard:", err);
        res.render("admin-dashboard", { 
            user: req.session.user,
            stats: { salesCount: 0, revenue: 0, profit: 0 },
            topProducts: []
        });
    }
});

app.get("/admin/products", requireAdmin, (req, res) => {
    db.query("SELECT * FROM products ORDER BY created_at DESC", (err, results) => {
        res.render("admin-products", { products: err ? [] : results, user: req.session.user });
    });
});

app.get("/admin/products/add", requireAdmin, (req, res) => {
    res.render("admin-add-product", { user: req.session.user });
});

app.post("/admin/products/add", requireAdmin, uploadMultiple, (req, res) => {
    const { name, description, price, category, stock } = req.body;
    
    if (!req.files || !req.files['image']) return res.send('<script>alert("Wajib upload gambar utama!"); window.history.back();</script>');

    const img1 = '/uploads/' + req.files['image'][0].filename;
    const img2 = req.files['image2'] ? '/uploads/' + req.files['image2'][0].filename : null;
    const img3 = req.files['image3'] ? '/uploads/' + req.files['image3'][0].filename : null;
    const img4 = req.files['image4'] ? '/uploads/' + req.files['image4'][0].filename : null;

    const sql = `INSERT INTO products (name, description, price, stock, category, image_url, image_url_2, image_url_3, image_url_4) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    db.query(sql, [name, description, price, stock, category, img1, img2, img3, img4], (err) => {
        if (err) return res.send('<script>alert("Error DB"); window.history.back();</script>');
        res.send('<script>alert("Produk Ditambahkan!"); window.location.href = "/admin/products";</script>');
    });
});

app.get("/admin/products/edit/:id", requireAdmin, (req, res) => {
    db.query("SELECT * FROM products WHERE id = ?", [req.params.id], (err, result) => {
        if (err || result.length === 0) return res.redirect("/admin/products");
        res.render("admin-edit-product", { product: result[0], user: req.session.user });
    });
});

app.post("/admin/products/edit/:id", requireAdmin, uploadMultiple, (req, res) => {
    const productId = req.params.id;
    const { name, description, price, category, stock } = req.body;

    db.query("SELECT * FROM products WHERE id = ?", [productId], (err, results) => {
        if (err || results.length === 0) return res.redirect("/admin/products");
        const oldData = results[0];

        const handleImg = (field, col) => {
            if (req.files && req.files[field]) {
                if (oldData[col] && fs.existsSync(path.join(__dirname, 'public', oldData[col]))) {
                    fs.unlink(path.join(__dirname, 'public', oldData[col]), (err) => { if(err) console.error("Gagal hapus:", err)});
                }
                return '/uploads/' + req.files[field][0].filename;
            }
            return oldData[col];
        };

        const img1 = handleImg('image', 'image_url');
        const img2 = handleImg('image2', 'image_url_2');
        const img3 = handleImg('image3', 'image_url_3');
        const img4 = handleImg('image4', 'image_url_4');

        const sql = `UPDATE products SET name=?, description=?, price=?, stock=?, category=?, image_url=?, image_url_2=?, image_url_3=?, image_url_4=? WHERE id=?`;
        db.query(sql, [name, description, price, stock, category, img1, img2, img3, img4, productId], (err) => {
            res.send('<script>alert("Produk Diperbarui!"); window.location.href = "/admin/products";</script>');
        });
    });
});

app.get("/admin/products/delete/:id", requireAdmin, (req, res) => {
    const pid = req.params.id;
    db.query("SELECT * FROM products WHERE id = ?", [pid], (err, results) => {
        if (results.length > 0) {
            const p = results[0];
            [p.image_url, p.image_url_2, p.image_url_3, p.image_url_4].forEach(img => {
                if (img && fs.existsSync(path.join(__dirname, 'public', img))) {
                    fs.unlink(path.join(__dirname, 'public', img), () => {});
                }
            });
        }
        db.query("DELETE FROM products WHERE id = ?", [pid], () => res.redirect("/admin/products"));
    });
});


// ==============================================
// 9. FITUR ADMIN: KELOLA PESANAN (CRUD LENGKAP)
// ==============================================

app.get("/admin/orders", requireAdmin, (req, res) => {
    const sql = `
        SELECT orders.*, users.username, users.full_name 
        FROM orders 
        JOIN users ON orders.user_id = users.id 
        ORDER BY orders.order_date DESC
    `;
    db.query(sql, (err, results) => {
        if (err) {
            console.error("Error fetch orders:", err);
            return res.render("admin-orders", { orders: [], user: req.session.user });
        }
        res.render("admin-orders", { orders: results, user: req.session.user });
    });
});

app.post("/admin/orders/update-status", requireAdmin, (req, res) => {
    const { order_id, status } = req.body;
    
    const sql = "UPDATE orders SET status = ? WHERE id = ?";
    db.query(sql, [status, order_id], (err, result) => {
        if (err) {
            console.error("Error update status:", err);
            return res.send('<script>alert("Gagal update status."); window.history.back();</script>');
        }
        res.redirect("/admin/orders");
    });
});

app.get("/admin/orders/delete/:id", requireAdmin, (req, res) => {
    const orderId = req.params.id;
    const sql = "DELETE FROM orders WHERE id = ?";
    db.query(sql, [orderId], (err, result) => {
        if (err) {
            console.error("Error delete order:", err);
            return res.send('<script>alert("Gagal menghapus pesanan."); window.history.back();</script>');
        }
        res.redirect("/admin/orders");
    });
});


// ==============================================
// 10. JALANKAN SERVER
// ==============================================
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server KURNIA berjalan di http://localhost:${PORT}`);
});