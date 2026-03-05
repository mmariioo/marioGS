// ══════════════════════════════════════════════════════════
//  NEXUS Store — script.js
//  Carrito aislado por usuario · Sistema de saldo · Seguridad XSS
// ══════════════════════════════════════════════════════════

const API      = "http://localhost:3000/api";
const PASS_MIN = 8;
const PASS_MAX = 16;

// ── Estado de sesión ──────────────────────────────────────
// El carrito se guarda en memoria indexado por userId
// → cada usuario tiene su propio carrito totalmente aislado
let token     = null;   // solo en memoria, no persiste entre recargas
let userId    = null;   // extraído del JWT, nunca del localStorage
let userAlias = null;
let userSaldo = 0;
let carts     = {};     // { [userId]: [ {id, nombre, precio, imagen_url}, … ] }

// ── Carrito del usuario actual ────────────────────────────
function getCart() {
    if (!userId) return [];
    if (!carts[userId]) carts[userId] = [];
    return carts[userId];
}
function setCart(items) {
    if (!userId) return;
    carts[userId] = items;
}

// ══════════════════════════════════════════════════════════
//  SEGURIDAD — helpers
// ══════════════════════════════════════════════════════════

/** Escapa HTML para prevenir XSS al insertar datos en el DOM. */
function esc(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/** Valida contraseña en cliente (el servidor también valida — defensa en profundidad). */
function validatePassword(p) {
    if (p.length < PASS_MIN) return `Mínimo ${PASS_MIN} caracteres.`;
    if (p.length > PASS_MAX) return `Máximo ${PASS_MAX} caracteres.`;
    if (!/[A-Z]/.test(p)) return "Debe contener al menos una letra mayúscula.";
    if (!/[a-z]/.test(p)) return "Debe contener al menos una letra minúscula.";
    if (!/[0-9]/.test(p)) return "Debe contener al menos un número.";
    if (!/[^A-Za-z0-9]/.test(p)) return "Debe contener al menos un carácter especial (ej. @$!%*?&).";
    return null;
}

/** Fuerza de contraseña: devuelve 1–5. */
function passStrength(p) {
    let s = 0;
    if (p.length >= PASS_MIN)                           s++;
    if (p.length >= 12)                                 s++;
    if (/[A-Z]/.test(p) && /[a-z]/.test(p))            s++;
    if (/[0-9]/.test(p))                                s++;
    if (/[^A-Za-z0-9]/.test(p))                        s++;
    return Math.min(s, 5);
}

/** Extrae el payload de un JWT sin verificar firma (solo para UI). */
function parseJwt(tok) {
    try { return JSON.parse(atob(tok.split(".")[1])); }
    catch { return null; }
}

// ══════════════════════════════════════════════════════════
//  UI — helpers
// ══════════════════════════════════════════════════════════

let _toastTimer = null;
function showToast(msg, type = "success") {
    const t  = document.getElementById("toast");
    const ic = document.getElementById("toast-icon");
    document.getElementById("toast-msg").textContent = msg;
    t.className = `toast t-${type} show`;
    ic.className = type === "error"   ? "bi bi-exclamation-circle-fill"
                 : type === "warning" ? "bi bi-exclamation-triangle-fill"
                 :                     "bi bi-check-circle-fill";
    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(() => t.classList.remove("show"), 3400);
}

function setLoading(btnId, on) {
    const btn = document.getElementById(btnId);
    if (!btn) return;
    if (on) {
        btn._orig    = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner"></span>`;
    } else {
        btn.disabled  = false;
        btn.innerHTML = btn._orig || btn.innerHTML;
    }
}

function showErr(elId, msg) {
    const el = document.getElementById(elId);
    if (!el) return;
    el.textContent   = msg;
    el.style.display = msg ? "block" : "none";
}

/** fetch con JWT automático; cierra sesión si 401. */
async function apiFetch(endpoint, opts = {}) {
    const headers = { "Content-Type": "application/json" };
    if (token) headers["Authorization"] = `Bearer ${token}`;
    let res, data;
    try {
        res  = await fetch(`${API}${endpoint}`, { headers, ...opts });
        data = await res.json();
    } catch {
        return { ok: false, status: 0, data: { error: "Error de conexión con el servidor." } };
    }
    if (res.status === 401) {
        clearSession();
        showToast("Sesión expirada. Vuelve a iniciar sesión.", "warning");
        showSection("auth-section");
    }
    return { ok: res.ok, status: res.status, data };
}

/** Limpia TODA la sesión del usuario actual. */
function clearSession() {
    token     = null;
    userId    = null;
    userAlias = null;
    userSaldo = 0;
    // nada que limpiar en localStorage
}

/** Limpia campos de contraseña para no dejarlos visibles tras un error. */
function clearPassFields() {
    ["login-password","reg-password","reg-confirm"]
        .forEach(id => { const el = document.getElementById(id); if (el) el.value = ""; });
    updateStrength("");
}

// ══════════════════════════════════════════════════════════
//  NAVEGACIÓN
// ══════════════════════════════════════════════════════════

function showSection(id) {
    ["auth-section","catalog-section","cart-section","dashboard-section"]
        .forEach(s => { document.getElementById(s).style.display = "none"; });
    document.getElementById(id).style.display = "";
    updateNav();
    window.scrollTo({ top: 0, behavior: "smooth" });
}

function updateNav() {
    const nav  = document.getElementById("nav-links");
    const cart = getCart();
    if (token && userId) {
        nav.innerHTML = `
          <li><a href="#" onclick="loadCatalog()"><i class="bi bi-grid-1x2"></i> Catálogo</a></li>
          <li><a href="#" onclick="openCart()">
              <i class="bi bi-bag"></i> Bolsa
              <span class="nav-badge">${cart.length}</span>
          </a></li>
          <li><a href="#" onclick="openDashboard()"><i class="bi bi-person-workspace"></i> Panel</a></li>
          <li><span class="nav-saldo-chip"><i class="bi bi-wallet2"></i> ${fmt(userSaldo)}</span></li>
          <li><span class="nav-user-chip"><i class="bi bi-person-circle"></i> ${esc(userAlias)}</span></li>
          <li><a href="#" onclick="logout()" class="logout-link"><i class="bi bi-box-arrow-right"></i> Salir</a></li>`;
    } else {
        nav.innerHTML = `
          <li><a href="#" onclick="showSection('auth-section')"><i class="bi bi-person"></i> Acceder</a></li>`;
    }
}

function goHome() { token ? loadCatalog() : showSection("auth-section"); }

function fmt(n) { return Number(n).toFixed(2) + " €"; }

// ══════════════════════════════════════════════════════════
//  AUTH TABS
// ══════════════════════════════════════════════════════════

function switchTab(tab) {
    showErr("login-error", ""); showErr("reg-error", "");
    clearPassFields();
    const ind  = document.getElementById("tab-indicator");
    const btns = document.querySelectorAll(".tab-btn");
    if (tab === "login") {
        document.getElementById("login-form").style.display    = "";
        document.getElementById("register-form").style.display = "none";
        btns[0].classList.add("active"); btns[1].classList.remove("active");
        ind.classList.remove("right");
    } else {
        document.getElementById("login-form").style.display    = "none";
        document.getElementById("register-form").style.display = "";
        btns[0].classList.remove("active"); btns[1].classList.add("active");
        ind.classList.add("right");
    }
}

function togglePassword(inputId, btn) {
    const el     = document.getElementById(inputId);
    const showing = el.type === "text";
    el.type      = showing ? "password" : "text";
    btn.querySelector("i").className = showing ? "bi bi-eye" : "bi bi-eye-slash";
}

function updateStrength(p) {
    const bar   = document.getElementById("pass-strength-bar");
    const lbl   = document.getElementById("pass-strength-label");
    const wrap  = document.getElementById("pass-strength");
    if (!bar) return;
    if (!p)   { bar.style.cssText = ""; if (lbl) lbl.textContent = ""; return; }
    const lvls = [
        { w:"20%", c:"#ff4757", t:"Muy débil"  },
        { w:"40%", c:"#ff6b35", t:"Débil"      },
        { w:"60%", c:"#ffa502", t:"Regular"    },
        { w:"80%", c:"#7bed9f", t:"Fuerte"     },
        { w:"100%",c:"#2ed573", t:"Muy fuerte" },
    ];
    const l = lvls[Math.max(0, passStrength(p) - 1)];
    bar.style.setProperty("--sw", l.w);
    bar.style.setProperty("--sc", l.c);
    if (wrap) wrap.style.setProperty("--sc", l.c);
    if (lbl)  lbl.textContent = l.t;
}

document.getElementById("reg-password").addEventListener("input", function() {
    updateStrength(this.value);
});

// ══════════════════════════════════════════════════════════
//  AUTH — LOGIN
// ══════════════════════════════════════════════════════════

document.getElementById("login-form").addEventListener("submit", async e => {
    e.preventDefault();
    showErr("login-error", "");

    const email    = document.getElementById("login-email").value.trim();
    const password = document.getElementById("login-password").value;

    if (!email || !password)
        return showErr("login-error", "Completa todos los campos.");
    if (password.length > PASS_MAX)
        return showErr("login-error", `Máximo ${PASS_MAX} caracteres.`);

    setLoading("login-btn", true);
    const { ok, data } = await apiFetch("/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password })
    });
    setLoading("login-btn", false);
    document.getElementById("login-password").value = "";

    if (!ok) return showErr("login-error", data.error || "Error al iniciar sesión.");

    token     = data.token;
    userAlias = data.alias;
    userSaldo = data.saldo;
    const pay = parseJwt(token);
    userId    = pay ? String(pay.id) : null;

    if (!userId) { clearSession(); return showErr("login-error", "Error de autenticación."); }

    // token solo en memoria, no se persiste en localStorage
    showToast(`¡Bienvenido, ${esc(userAlias)}! Saldo: ${fmt(userSaldo)}`);
    loadCatalog();
});

// ══════════════════════════════════════════════════════════
//  AUTH — REGISTRO
// ══════════════════════════════════════════════════════════

document.getElementById("register-form").addEventListener("submit", async e => {
    e.preventDefault();
    showErr("reg-error", "");

    const email    = document.getElementById("reg-email").value.trim();
    const password = document.getElementById("reg-password").value;
    const confirm  = document.getElementById("reg-confirm").value;

    if (!email || !password || !confirm)
        return showErr("reg-error", "Completa todos los campos.");

    const passErr = validatePassword(password);
    if (passErr) return showErr("reg-error", passErr);

    if (password !== confirm) {
        clearPassFields();
        return showErr("reg-error", "Las contraseñas no coinciden.");
    }

    setLoading("reg-btn", true);
    const { ok, data } = await apiFetch("/auth/register", {
        method: "POST",
        body: JSON.stringify({ email, password, confirm })
    });
    setLoading("reg-btn", false);
    clearPassFields();

    if (!ok) return showErr("reg-error", data.error || "Error al registrarse.");

    token     = data.token;
    userAlias = data.alias;
    userSaldo = data.saldo;
    const pay = parseJwt(token);
    userId    = pay ? String(pay.id) : null;

    if (!userId) { clearSession(); return showErr("reg-error", "Error de autenticación."); }

    // token solo en memoria, no se persiste en localStorage
    showToast(`¡Bienvenido a NEXUS, ${esc(userAlias)}! Tienes ${fmt(userSaldo)} de saldo.`);
    loadCatalog();
});

// ══════════════════════════════════════════════════════════
//  AUTH — LOGOUT
// ══════════════════════════════════════════════════════════

function logout() {
    clearSession();
    clearPassFields();
    showSection("auth-section");
    updateNav();
}

// ══════════════════════════════════════════════════════════
//  CATÁLOGO
// ══════════════════════════════════════════════════════════

async function loadCatalog() {
    showSection("catalog-section");
    const container = document.getElementById("products-container");
    container.innerHTML = `<div class="loading-overlay"><span class="spinner-accent"></span> Cargando productos…</div>`;

    const { ok, data } = await apiFetch("/products");

    if (!ok) {
        container.innerHTML = `<div class="loading-overlay">Error al cargar productos. Inténtalo de nuevo.</div>`;
        return;
    }

    // Actualizar saldo desde el servidor en cada carga del catálogo
    refreshSaldo();

    container.innerHTML = "";

    if (!data.productos || data.productos.length === 0) {
        container.innerHTML = `<div class="loading-overlay"><i class="bi bi-inbox" style="font-size:2rem"></i>&nbsp; No hay productos todavía.</div>`;
        return;
    }

    const myCart = getCart();

    data.productos.forEach(prod => {
        const esPropio   = prod.vendedor === userAlias;
        const enCarrito  = myCart.some(i => i.id === prod.id);
        const card       = document.createElement("article");
        card.className   = "product-card";
        card.dataset.id  = prod.id;

        // Imagen — URL validada en backend (solo https://)
        const imgWrap = document.createElement("div");
        imgWrap.className = "product-img-wrap";
        if (prod.imagen_url) {
            const img    = document.createElement("img");
            img.src      = prod.imagen_url;
            img.alt      = "";
            img.loading  = "lazy";
            img.onerror  = () => {
                imgWrap.innerHTML = `<div class="product-img-placeholder"><i class="bi bi-image"></i></div>`;
            };
            imgWrap.appendChild(img);
        } else {
            imgWrap.innerHTML = `<div class="product-img-placeholder"><i class="bi bi-image"></i></div>`;
        }

        // Cuerpo — textContent en todos los datos de usuario para evitar XSS
        const body   = document.createElement("div");
        body.className = "product-body";

        const name   = document.createElement("div");
        name.className   = "product-name";
        name.textContent = prod.nombre;

        const seller = document.createElement("div");
        seller.className = "product-seller";
        seller.innerHTML = `<i class="bi bi-person"></i> `;
        seller.appendChild(document.createTextNode(prod.vendedor));

        const desc   = document.createElement("p");
        desc.className   = "product-desc";
        desc.textContent = prod.descripcion;

        const footer = document.createElement("div");
        footer.className = "product-footer";

        const price  = document.createElement("div");
        price.className = "product-price";
        price.innerHTML = `${parseFloat(prod.precio).toFixed(2)} <span>€</span>`;

        let action;
        if (esPropio) {
            action = document.createElement("span");
            action.className   = "own-badge";
            action.textContent = "Tu producto";
        } else if (enCarrito) {
            action = document.createElement("button");
            action.className = "btn-add";
            action.disabled  = true;
            action.innerHTML = `<i class="bi bi-check2"></i> Añadido`;
        } else {
            action = document.createElement("button");
            action.className = "btn-add";
            action.innerHTML = `<i class="bi bi-bag-plus"></i> Añadir`;
            action.dataset.productId    = prod.id;
            action.dataset.productName  = prod.nombre;
            action.dataset.productPrice = prod.precio;
            action.dataset.productImg   = prod.imagen_url || "";
            action.addEventListener("click", function () {
                addToCart(
                    parseInt(this.dataset.productId, 10),
                    this.dataset.productName,
                    parseFloat(this.dataset.productPrice),
                    this.dataset.productImg
                );
                // Marcar botón como añadido sin recargar todo
                this.disabled = true;
                this.innerHTML = `<i class="bi bi-check2"></i> Añadido`;
            });
        }

        footer.appendChild(price);
        footer.appendChild(action);
        body.appendChild(name);
        body.appendChild(seller);
        body.appendChild(desc);
        body.appendChild(footer);
        card.appendChild(imgWrap);
        card.appendChild(body);
        container.appendChild(card);
    });
}

/** Refresca el saldo del usuario actual desde la API. */
async function refreshSaldo() {
    const { ok, data } = await apiFetch("/auth/me");
    if (ok) {
        userSaldo = data.saldo;
        updateNav();
    }
}

// ══════════════════════════════════════════════════════════
//  CARRITO — aislado por userId
// ══════════════════════════════════════════════════════════

function addToCart(id, nombre, precio, imagen_url) {
    const cart = getCart();

    // Validaciones de cliente
    if (cart.find(i => i.id === id)) {
        showToast(`"${nombre}" ya está en tu bolsa.`, "warning"); return;
    }
    if (cart.length >= 50) {
        showToast("Máximo 50 artículos en el carrito.", "warning"); return;
    }

    cart.push({ id, nombre, precio, imagen_url });
    setCart(cart);
    updateNav();
    showToast(`"${nombre}" añadido a tu bolsa.`);
}

function openCart() {
    showSection("cart-section");
    renderCart();
}

function renderCart() {
    const container = document.getElementById("cart-items");
    const btn       = document.getElementById("checkout-btn");
    const warn      = document.getElementById("saldo-warning");
    const warnMsg   = document.getElementById("saldo-warning-msg");
    const saldoRow  = document.querySelector(".saldo-row");
    const cart      = getCart();

    container.innerHTML = "";
    let total = 0;

    if (cart.length === 0) {
        container.innerHTML = `
            <div class="empty-cart">
                <i class="bi bi-bag-x"></i>
                <p>Tu bolsa está vacía.</p>
            </div>`;
        btn.disabled = true;
        warn.style.display = "none";
        document.getElementById("cart-subtotal").textContent = fmt(0);
        document.getElementById("cart-total").textContent    = fmt(0);
        document.getElementById("cart-saldo-display").textContent = fmt(userSaldo);
        return;
    }

    cart.forEach((item, i) => {
        total += item.precio;

        const row = document.createElement("div");
        row.className = "cart-item";

        // Imagen
        if (item.imagen_url) {
            const img     = document.createElement("img");
            img.src       = item.imagen_url;
            img.className = "cart-item-img";
            img.alt       = "";
            img.onerror   = () => { img.style.display = "none"; };
            row.appendChild(img);
        } else {
            const ph = document.createElement("div");
            ph.className = "cart-item-img";
            ph.style.cssText = "display:flex;align-items:center;justify-content:center;color:var(--text-muted)";
            ph.innerHTML = `<i class="bi bi-image"></i>`;
            row.appendChild(ph);
        }

        const info = document.createElement("div");
        info.className = "cart-item-info";
        const n = document.createElement("div"); n.className = "cart-item-name"; n.textContent = item.nombre;
        const p = document.createElement("div"); p.className = "cart-item-price"; p.textContent = fmt(item.precio);
        info.appendChild(n); info.appendChild(p);

        const del = document.createElement("button");
        del.className = "btn-danger-ghost";
        del.innerHTML = `<i class="bi bi-trash3"></i>`;
        del.dataset.idx = i;
        del.addEventListener("click", function () { removeFromCart(parseInt(this.dataset.idx, 10)); });

        row.appendChild(info);
        row.appendChild(del);
        container.appendChild(row);
    });

    total = parseFloat(total.toFixed(2));
    document.getElementById("cart-subtotal").textContent     = fmt(total);
    document.getElementById("cart-total").textContent        = fmt(total);
    document.getElementById("cart-saldo-display").textContent = fmt(userSaldo);

    // ── Validación de saldo ──────────────────────────────
    const saldoSuficiente = userSaldo >= total;

    if (saldoRow) saldoRow.classList.toggle("insuficiente", !saldoSuficiente);

    if (!saldoSuficiente) {
        const falta = (total - userSaldo).toFixed(2);
        warnMsg.textContent = `Saldo insuficiente. Te faltan ${falta} € para completar esta compra.`;
        warn.style.display  = "flex";
        btn.disabled        = true;
    } else {
        warn.style.display = "none";
        btn.disabled       = false;
    }
}

function removeFromCart(idx) {
    const cart    = getCart();
    const removed = cart.splice(idx, 1)[0];
    setCart(cart);
    renderCart();
    updateNav();
    if (removed) showToast(`"${removed.nombre}" eliminado de la bolsa.`);
}

async function checkout() {
    const cart = getCart();
    if (!cart.length) return;

    // Validación de saldo antes de enviar
    const total = parseFloat(cart.reduce((s, i) => s + i.precio, 0).toFixed(2));
    if (userSaldo < total) {
        showToast(`Saldo insuficiente. Necesitas ${fmt(total)} pero tienes ${fmt(userSaldo)}.`, "error");
        renderCart();
        return;
    }

    setLoading("checkout-btn", true);
    const { ok, data } = await apiFetch("/orders", {
        method: "POST",
        body: JSON.stringify({ items: cart.map(i => ({ producto_id: i.id })) })
    });
    setLoading("checkout-btn", false);

    if (!ok) {
        showToast(data.error || "Error al procesar el pedido.", "error");
        // Si el error es de saldo, actualizar el saldo mostrado
        if (data.error && data.error.includes("Saldo")) {
            await refreshSaldo();
            renderCart();
        }
        return;
    }

    // Actualizar saldo con el valor devuelto por el servidor
    userSaldo = data.saldo;
    setCart([]);
    updateNav();
    showToast(`¡Pedido #${data.pedido_id} completado! Total: ${fmt(data.total)}. Saldo restante: ${fmt(data.saldo)}`);
    loadCatalog();
}

// ══════════════════════════════════════════════════════════
//  DASHBOARD
// ══════════════════════════════════════════════════════════

async function openDashboard() {
    showSection("dashboard-section");
    loadMyProducts();
    loadMyOrders();
}

async function loadMyProducts() {
    const list = document.getElementById("my-products-list");
    list.innerHTML = `<li class="empty-state"><span class="spinner-accent"></span></li>`;

    const { ok, data } = await apiFetch("/products/mine");
    list.innerHTML = "";

    if (!ok || !data.productos || data.productos.length === 0) {
        list.innerHTML = `<li class="empty-state"><i class="bi bi-box"></i><span>No has publicado productos.</span></li>`;
        return;
    }

    data.productos.forEach(p => {
        const li   = document.createElement("li");
        li.className = "my-product-item";

        const info = document.createElement("div"); info.className = "my-product-info";
        const nm   = document.createElement("div"); nm.className = "my-product-name"; nm.textContent = p.nombre;
        const pr   = document.createElement("div"); pr.className = "my-product-price"; pr.textContent = fmt(p.precio);
        info.appendChild(nm); info.appendChild(pr);

        const btn  = document.createElement("button");
        btn.className = "btn-danger-ghost";
        btn.innerHTML = `<i class="bi bi-trash3"></i>`;
        btn.dataset.id = p.id;
        btn.addEventListener("click", function () { deleteProduct(parseInt(this.dataset.id, 10), this); });

        li.appendChild(info); li.appendChild(btn);
        list.appendChild(li);
    });
}

async function deleteProduct(id, btn) {
    if (!confirm("¿Eliminar este producto del catálogo?")) return;
    btn.disabled = true;
    const { ok, data } = await apiFetch(`/products/${id}`, { method: "DELETE" });
    if (!ok) { showToast(data.error || "Error al eliminar.", "error"); btn.disabled = false; return; }
    showToast("Producto eliminado.");
    loadMyProducts();
}

async function loadMyOrders() {
    const list = document.getElementById("my-orders-list");
    list.innerHTML = `<li class="empty-state"><span class="spinner-accent"></span></li>`;

    const { ok, data } = await apiFetch("/orders/mine");
    list.innerHTML = "";

    if (!ok || !data.pedidos || data.pedidos.length === 0) {
        list.innerHTML = `<li class="empty-state"><i class="bi bi-bag-x"></i><span>Aún no has comprado nada.</span></li>`;
        return;
    }

    data.pedidos.forEach(o => {
        const li    = document.createElement("li");
        li.className = "order-item";
        const fecha  = new Date(o.fecha).toLocaleDateString("es-ES", { day:"2-digit", month:"short", year:"numeric" });
        const left  = document.createElement("span"); left.textContent  = `#${o.id} · ${fecha} · ${o.num_items} art.`;
        const right = document.createElement("span"); right.className   = "order-item-price"; right.textContent = fmt(o.total);
        li.appendChild(left); li.appendChild(right);
        list.appendChild(li);
    });
}

document.getElementById("create-product-form").addEventListener("submit", async function (e) {
    e.preventDefault();
    showErr("prod-error", "");

    const nombre      = document.getElementById("prod-name").value.trim();
    const descripcion = document.getElementById("prod-desc").value.trim();
    const precio      = document.getElementById("prod-price").value;
    const imagen_url  = document.getElementById("prod-image").value.trim();

    if (!nombre || !descripcion || !precio)
        return showErr("prod-error", "Nombre, descripción y precio son obligatorios.");

    setLoading("prod-btn", true);
    const { ok, data } = await apiFetch("/products", {
        method: "POST",
        body: JSON.stringify({ nombre, descripcion, precio, imagen_url })
    });
    setLoading("prod-btn", false);

    if (!ok) return showErr("prod-error", data.error || "Error al publicar.");

    this.reset();
    showToast(`"${nombre}" publicado en el catálogo.`);
    loadMyProducts();
    setTimeout(() => loadCatalog(), 400);
});

// ══════════════════════════════════════════════════════════
//  INIT — restaurar sesión desde token guardado
// ══════════════════════════════════════════════════════════
(function init() {
    if (!token) { showSection("auth-section"); updateNav(); return; }

    const pay = parseJwt(token);
    if (!pay || !pay.id || !pay.exp) {
        clearSession(); showSection("auth-section"); updateNav(); return;
    }

    // Comprobar expiración del token en cliente
    const now = Math.floor(Date.now() / 1000);
    if (pay.exp <= now) {
        clearSession(); showSection("auth-section");
        showToast("Tu sesión expiró. Vuelve a iniciar sesión.", "warning");
        updateNav(); return;
    }

    userId    = String(pay.id);
    userAlias = pay.alias || "Usuario";

    // Refrescar saldo desde servidor antes de mostrar catálogo
    refreshSaldo().then(() => loadCatalog());
})();