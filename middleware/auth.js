function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.redirect("/login");
  }
  next();
}

function requirePelanggan(req, res, next) {
  if (!req.session.user || req.session.user.role !== "pelanggan") {
    return res.redirect("/login");
  }
  next();
}

module.exports = { requireLogin, requireAdmin, requirePelanggan };
