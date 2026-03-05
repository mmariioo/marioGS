# =============================================================
#  NEXUS Store — Backend API  (Flask/Python)
#  Flask + SQLite + JWT + bcrypt + flask-limiter + flask-cors
#  Incluye: sistema de saldo, seed de 12 productos, validaciones
# =============================================================

import os
import re
import sqlite3
import bcrypt
import jwt

from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ─── CONFIGURACIÓN ───────────────────────────────────────────
app = Flask(__name__)

SECRET_KEY  = os.environ.get("JWT_SECRET", "dev_secret_cambia_en_produccion")
DB_PATH     = os.path.join(os.path.dirname(__file__), "data", "nexus.db")
PASS_MIN    = 8
PASS_MAX    = 16
SALDO_INIT  = 3000.00   # Saldo inicial que recibe cada usuario al registrarse
EMAIL_RE    = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')

# ─── CORS ────────────────────────────────────────────────────
CORS(app, resources={
    r"/api/*": {
        "origins":      ["http://localhost:8080", "http://127.0.0.1:8080"],
        "methods":      ["GET", "POST", "DELETE"],
        "allow_headers":["Content-Type", "Authorization"]
    }
})

# ─── CABECERAS DE SEGURIDAD ──────────────────────────────────
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-XSS-Protection"]       = "1; mode=block"
    response.headers["Referrer-Policy"]        = "no-referrer"
    response.headers["Cache-Control"]          = "no-store"
    response.headers.pop("Server", None)
    return response

# ─── RATE LIMITING ───────────────────────────────────────────
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri="memory://"
)

# ════════════════════════════════════════════════════════════
#  BASE DE DATOS
# ════════════════════════════════════════════════════════════

def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# ─── PRODUCTOS DE MUESTRA ────────────────────────────────────
PRODUCTOS_SEED = [
    (
        "MacBook Pro M3 14\"",
        "Chip M3, CPU 8 núcleos, GPU 10 núcleos. 18 GB RAM unificada, 512 GB SSD. Hasta 22 h de batería. El portátil definitivo para desarrollo.",
        2199.00,
        "https://images.unsplash.com/photo-1517336714731-489689fd1ca8?auto=format&fit=crop&w=800&q=80"
    ),
    (
        "Dell XPS 15 OLED",
        "Pantalla OLED 3.5K 120 Hz. Core i7-13700H, 32 GB DDR5, RTX 4060. Perfecta para diseño y desarrollo fullstack exigente.",
        1749.00,
        "https://images.unsplash.com/photo-1593642632559-0c6d3fc62b89?auto=format&fit=crop&w=800&q=80"
    ),
    (
        "Teclado Mecánico Keychron Q1",
        "Aluminio CNC, switches Gateron Pro Red, hot-swap, RGB por tecla. Inalámbrico 2.4 GHz y Bluetooth 5.1.",
        185.00,
        "https://images.unsplash.com/photo-1595225476474-87563907a212?auto=format&fit=crop&w=800&q=80"
    ),
    (
        "Ratón Logitech MX Master 3S",
        "Sensor Darkfield 8000 DPI, scroll electromagnético MagSpeed, 70 días de batería. Precisión quirúrgica para largas sesiones.",
        109.99,
        "https://images.unsplash.com/photo-1527864550417-7fd91fc51a46?auto=format&fit=crop&w=800&q=80"
    ),
    (
        "Monitor LG UltraWide 34\"",
        "Panel IPS 3440×1440, 144 Hz, 1 ms, HDR400. Curvo 1900R. Espacio para código, terminal y docs a la vez.",
        549.00,
        "https://images.unsplash.com/photo-1527443224154-c4a3942d3acf?auto=format&fit=crop&w=800&q=80"
    ),
    (
        "Samsung Odyssey G9 49\"",
        "49\" curvo DQHD 5120×1440 a 240 Hz. Panel VA 1000R, HDR1000. Dos monitores en uno. Para los que no tienen límites.",
        1299.00,
        "https://images.unsplash.com/photo-1612198273689-a4781ead8bb8?auto=format&fit=crop&w=800&q=80"
    ),
    (
        "Sony WH-1000XM5",
        "Cancelación activa de ruido de referencia. 30 h de batería, carga rápida. Convierte cualquier lugar en tu oficina privada.",
        349.00,
        "https://images.unsplash.com/photo-1546435770-a3e426bf472b?auto=format&fit=crop&w=800&q=80"
    ),
    (
        "Micrófono Blue Yeti X",
        "Condensador USB profesional, 4 patrones polares. Para reuniones, grabaciones y streaming. Calidad de estudio en tu escritorio.",
        169.00,
        "https://images.unsplash.com/photo-1590602847861-f357a9332bbc?auto=format&fit=crop&w=800&q=80"
    ),
    (
        "Silla Ergonómica HM Aeron",
        "La silla de referencia para programadores. Soporte lumbar PostureFit SL, 8 zonas de ajuste, malla transpirable.",
        1450.00,
        "https://images.unsplash.com/photo-1505843490538-5133c6c7d0e1?auto=format&fit=crop&w=800&q=80"
    ),
    (
        "Mesa Elevable FlexiSpot E7",
        "Standing desk eléctrico. Motor dual silencioso, altura 60–125 cm, tablero 160×80 cm bambú. Anti-fatiga garantizada.",
        589.00,
        "https://images.unsplash.com/photo-1593642533144-3d62aa4783ec?auto=format&fit=crop&w=800&q=80"
    ),
    (
        "Cafetera De'Longhi Dedica",
        "Espresso compacto 15 bar, cappuccinatore manual, 1350 W. El combustible del programador, en su versión premium.",
        249.00,
        "https://images.unsplash.com/photo-1495474472287-4d71bcdd2085?auto=format&fit=crop&w=800&q=80"
    ),
    (
        "Raspberry Pi 5 (8 GB)",
        "BCM2712 quad-core 2.4 GHz, 8 GB LPDDR4X, PCIe 2.0. Monta tu propio servidor, NAS o laboratorio de hacking ético.",
        89.95,
        "https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=800&q=80"
    ),
]

def init_db():
    """Crea tablas, añade columnas nuevas si faltan y carga el seed."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")

    # ── Crear tablas ─────────────────────────────────────────
    con.executescript("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            email      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            alias      TEXT    NOT NULL,
            password   TEXT    NOT NULL,
            saldo      REAL    NOT NULL DEFAULT 3000.00,
            created_at TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS productos (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            vendedor_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            nombre      TEXT    NOT NULL,
            descripcion TEXT    NOT NULL DEFAULT '',
            precio      REAL    NOT NULL CHECK(precio > 0),
            imagen_url  TEXT,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS pedidos (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            comprador_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            total        REAL    NOT NULL,
            fecha        TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS pedido_items (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            pedido_id   INTEGER NOT NULL REFERENCES pedidos(id)   ON DELETE CASCADE,
            producto_id INTEGER NOT NULL REFERENCES productos(id) ON DELETE CASCADE,
            nombre_snap TEXT    NOT NULL,
            precio_snap REAL    NOT NULL
        );
    """)

    # ── Migración: añadir columna saldo si la BD ya existía sin ella ──
    cols = [row[1] for row in con.execute("PRAGMA table_info(usuarios)").fetchall()]
    if "saldo" not in cols:
        con.execute(f"ALTER TABLE usuarios ADD COLUMN saldo REAL NOT NULL DEFAULT {SALDO_INIT}")

    # ── Seed: usuario sistema + 12 productos ─────────────────
    existing = con.execute(
        "SELECT id FROM usuarios WHERE email = 'nexus@tienda.com'"
    ).fetchone()

    if not existing:
        hashed     = bcrypt.hashpw(b"Nexus@Store2024!", bcrypt.gensalt(rounds=12))
        cur        = con.execute(
            "INSERT INTO usuarios (email, alias, password, saldo) VALUES (?, ?, ?, ?)",
            ("nexus@tienda.com", "NEXUS", hashed.decode("utf-8"), 0.0)
        )
        sistema_id = cur.lastrowid

        for nombre, desc, precio, img in PRODUCTOS_SEED:
            con.execute(
                "INSERT INTO productos (vendedor_id, nombre, descripcion, precio, imagen_url) "
                "VALUES (?, ?, ?, ?, ?)",
                (sistema_id, nombre, desc, precio, img)
            )
        print("✅  12 productos de muestra cargados.")

    con.commit()
    con.close()

# ════════════════════════════════════════════════════════════
#  HELPERS
# ════════════════════════════════════════════════════════════

def api_error(status: int, msg: str):
    """Respuesta de error — sin stack traces ni rutas internas."""
    return jsonify({"ok": False, "error": msg}), status

def sanitize(value) -> str:
    """Elimina caracteres de control. NO usar en contraseñas."""
    if not isinstance(value, str):
        return ""
    return re.sub(r'[\x00-\x1F\x7F]', '', value).strip()

def email_to_alias(email: str) -> str:
    return email.split("@")[0][:30]

def make_token(user_id: int, alias: str) -> str:
    payload = {
        "id":    user_id,
        "alias": alias,
        "exp":   datetime.now(tz=timezone.utc) + timedelta(hours=8)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def require_auth(f):
    """Decorador que verifica el JWT."""
    @wraps(f)
    def decorated(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return api_error(401, "Autenticación requerida.")
        try:
            g.current_user = jwt.decode(
                header[7:], SECRET_KEY, algorithms=["HS256"]
            )
        except jwt.ExpiredSignatureError:
            return api_error(401, "Sesión expirada. Vuelve a iniciar sesión.")
        except jwt.InvalidTokenError:
            return api_error(401, "Token inválido. Vuelve a iniciar sesión.")
        return f(*args, **kwargs)
    return decorated

def check_size(max_bytes=10_240):
    ln = request.content_length
    if ln and ln > max_bytes:
        return api_error(413, "Petición demasiado grande.")
    return None

# ════════════════════════════════════════════════════════════
#  AUTH
# ════════════════════════════════════════════════════════════

@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("10 per 15 minutes")
def register():
    err = check_size(); 
    if err: return err

    body     = request.get_json(silent=True) or {}
    email    = sanitize(body.get("email", ""))
    password = body.get("password", "")
    confirm  = body.get("confirm",  "")
    if not isinstance(password, str): password = ""
    if not isinstance(confirm,  str): confirm  = ""

    if not email or not password or not confirm:
        return api_error(400, "Todos los campos son obligatorios.")
    if not EMAIL_RE.match(email):
        return api_error(400, "Formato de email inválido.")
    if len(email) > 254:
        return api_error(400, "Email demasiado largo.")
    if len(password) < PASS_MIN:
        return api_error(400, f"La contraseña debe tener al menos {PASS_MIN} caracteres.")
    if len(password) > PASS_MAX:
        return api_error(400, f"La contraseña no puede superar {PASS_MAX} caracteres.")
        if not re.search(r'[A-Z]', password):
        return api_error(400, "La contraseña debe contener al menos una mayúscula.")
    if not re.search(r'[a-z]', password):
        return api_error(400, "La contraseña debe contener al menos una minúscula.")
    if not re.search(r'[0-9]', password):
        return api_error(400, "La contraseña debe contener al menos un número.")
    if not re.search(r'[^A-Za-z0-9]', password):
        return api_error(400, "La contraseña debe contener al menos un carácter especial (ej. @$!%*?&).")
    if password != confirm:
        return api_error(400, "Las contraseñas no coinciden.")

    db = get_db()
    if db.execute("SELECT id FROM usuarios WHERE email = ?", (email,)).fetchone():
        return api_error(409, "El email ya está registrado.")

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
    alias  = email_to_alias(email)
    cur    = db.execute(
        "INSERT INTO usuarios (email, alias, password, saldo) VALUES (?, ?, ?, ?)",
        (email, alias, hashed.decode("utf-8"), SALDO_INIT)
    )
    db.commit()

    token = make_token(cur.lastrowid, alias)
    return jsonify({"ok": True, "token": token, "alias": alias, "saldo": SALDO_INIT}), 201


@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per 15 minutes")
def login():
    err = check_size()
    if err: return err

    body     = request.get_json(silent=True) or {}
    email    = sanitize(body.get("email", ""))
    password = body.get("password", "")
    if not isinstance(password, str): password = ""

    if not email or not password:
        return api_error(400, "Email y contraseña son obligatorios.")
    if len(password) > PASS_MAX:
        return api_error(400, "Contraseña demasiado larga.")

    db   = get_db()
    user = db.execute(
        "SELECT id, alias, password, saldo FROM usuarios WHERE email = ?", (email,)
    ).fetchone()

    # Mismo mensaje si no existe o contraseña incorrecta → evita user enumeration
    if not user or not bcrypt.checkpw(
        password.encode("utf-8"), user["password"].encode("utf-8")
    ):
        return api_error(401, "Credenciales incorrectas.")

    token = make_token(user["id"], user["alias"])
    return jsonify({"ok": True, "token": token, "alias": user["alias"], "saldo": user["saldo"]})


@app.route("/api/auth/me", methods=["GET"])
@require_auth
def me():
    """Devuelve alias y saldo del usuario autenticado."""
    db   = get_db()
    user = db.execute(
        "SELECT alias, saldo FROM usuarios WHERE id = ?", (g.current_user["id"],)
    ).fetchone()
    if not user:
        return api_error(404, "Usuario no encontrado.")
    return jsonify({"ok": True, "alias": user["alias"], "saldo": user["saldo"]})


# ════════════════════════════════════════════════════════════
#  PRODUCTOS
# ════════════════════════════════════════════════════════════

@app.route("/api/products", methods=["GET"])
def get_products():
    """Lista todos los productos. Devuelve alias, NUNCA email."""
    db   = get_db()
    rows = db.execute("""
        SELECT p.id, p.nombre, p.descripcion, p.precio, p.imagen_url, p.created_at,
               u.alias AS vendedor
        FROM   productos p
        JOIN   usuarios  u ON u.id = p.vendedor_id
        ORDER  BY p.created_at ASC
    """).fetchall()
    return jsonify({"ok": True, "productos": [dict(r) for r in rows]})


@app.route("/api/products", methods=["POST"])
@require_auth
def create_product():
    err = check_size()
    if err: return err

    body        = request.get_json(silent=True) or {}
    nombre      = sanitize(body.get("nombre",      ""))
    descripcion = sanitize(body.get("descripcion", ""))
    imagen_url  = sanitize(body.get("imagen_url",  ""))

    try:
        precio = float(body.get("precio", 0))
    except (ValueError, TypeError):
        return api_error(400, "El precio debe ser un número.")

    if not nombre:
        return api_error(400, "El nombre es obligatorio.")
    if len(nombre) > 120:
        return api_error(400, "Nombre demasiado largo (máx. 120 caracteres).")
    if not descripcion:
        return api_error(400, "La descripción es obligatoria.")
    if len(descripcion) > 500:
        return api_error(400, "Descripción demasiado larga (máx. 500 caracteres).")
    if precio <= 0:
        return api_error(400, "El precio debe ser un número positivo.")
    if precio > 999_999:
        return api_error(400, "Precio demasiado alto.")
    if imagen_url and not re.match(r'^https://.+', imagen_url):
        return api_error(400, "La URL de imagen debe comenzar con https://")
    if len(imagen_url) > 500:
        return api_error(400, "URL de imagen demasiado larga.")

    db  = get_db()
    cur = db.execute(
        "INSERT INTO productos (vendedor_id, nombre, descripcion, precio, imagen_url) VALUES (?, ?, ?, ?, ?)",
        (g.current_user["id"], nombre, descripcion, precio, imagen_url or None)
    )
    db.commit()

    nuevo = db.execute(
        "SELECT id, nombre, descripcion, precio, imagen_url, created_at FROM productos WHERE id = ?",
        (cur.lastrowid,)
    ).fetchone()
    return jsonify({"ok": True, "producto": dict(nuevo)}), 201


@app.route("/api/products/<int:pid>", methods=["DELETE"])
@require_auth
def delete_product(pid):
    if pid <= 0:
        return api_error(400, "ID inválido.")

    db   = get_db()
    prod = db.execute("SELECT id, vendedor_id FROM productos WHERE id = ?", (pid,)).fetchone()

    if not prod:
        return api_error(404, "Producto no encontrado.")
    if prod["vendedor_id"] != g.current_user["id"]:
        return api_error(403, "No tienes permiso para eliminar este producto.")

    db.execute("DELETE FROM productos WHERE id = ?", (pid,))
    db.commit()
    return jsonify({"ok": True, "mensaje": "Producto eliminado."})


@app.route("/api/products/mine", methods=["GET"])
@require_auth
def get_my_products():
    db   = get_db()
    rows = db.execute(
        "SELECT id, nombre, descripcion, precio, imagen_url, created_at "
        "FROM productos WHERE vendedor_id = ? ORDER BY created_at DESC",
        (g.current_user["id"],)
    ).fetchall()
    return jsonify({"ok": True, "productos": [dict(r) for r in rows]})


# ════════════════════════════════════════════════════════════
#  PEDIDOS
# ════════════════════════════════════════════════════════════

@app.route("/api/orders", methods=["POST"])
@require_auth
def create_order():
    """
    Finaliza la compra. Validaciones:
      1. Carrito no vacío, máx. 50 ítems
      2. IDs de producto válidos y existentes
      3. El usuario no compra sus propios productos
      4. Saldo suficiente
      5. Descuento atómico del saldo (transacción SQLite)
    """
    err = check_size()
    if err: return err

    body  = request.get_json(silent=True) or {}
    items = body.get("items", [])

    if not isinstance(items, list) or len(items) == 0:
        return api_error(400, "El carrito está vacío.")
    if len(items) > 50:
        return api_error(400, "Demasiados artículos en el carrito (máx. 50).")

    # Validar IDs
    try:
        ids = [int(i["producto_id"]) for i in items]
        if any(i <= 0 for i in ids):
            raise ValueError
    except (KeyError, ValueError, TypeError):
        return api_error(400, "IDs de producto inválidos.")

    # IDs duplicados
    if len(ids) != len(set(ids)):
        return api_error(400, "No puedes añadir el mismo producto dos veces.")

    db = get_db()

    # Obtener precios REALES de la BD — nunca confiar en el frontend
    placeholders = ",".join("?" * len(ids))
    prods = db.execute(
        f"SELECT id, nombre, precio, vendedor_id FROM productos WHERE id IN ({placeholders})",
        ids
    ).fetchall()

    if len(prods) != len(ids):
        return api_error(404, "Uno o más productos no existen.")

    # No comprar productos propios
    propio = next((p for p in prods if p["vendedor_id"] == g.current_user["id"]), None)
    if propio:
        return api_error(400, "No puedes comprar tus propios productos.")

    total = round(sum(p["precio"] for p in prods), 2)

    # Verificar saldo (primera comprobación — la BD también lo hace atómicamente)
    user = db.execute(
        "SELECT saldo FROM usuarios WHERE id = ?", (g.current_user["id"],)
    ).fetchone()
    if not user:
        return api_error(404, "Usuario no encontrado.")
    if user["saldo"] < total:
        return api_error(
            402,
            f"Saldo insuficiente. Necesitas {total:.2f} € pero tienes {user['saldo']:.2f} €."
        )

    # Transacción atómica: crear pedido + descontar saldo
    try:
        cur = db.execute(
            "INSERT INTO pedidos (comprador_id, total) VALUES (?, ?)",
            (g.current_user["id"], total)
        )
        pedido_id = cur.lastrowid

        for prod in prods:
            db.execute(
                "INSERT INTO pedido_items (pedido_id, producto_id, nombre_snap, precio_snap) "
                "VALUES (?, ?, ?, ?)",
                (pedido_id, prod["id"], prod["nombre"], prod["precio"])
            )

        # Descontar saldo — con comprobación a nivel BD para evitar race conditions
        result = db.execute(
            "UPDATE usuarios SET saldo = saldo - ? WHERE id = ? AND saldo >= ?",
            (total, g.current_user["id"], total)
        )
        if result.rowcount == 0:
            raise ValueError("Saldo insuficiente en BD")  # No debería ocurrir, pero por si acaso

        db.commit()
    except Exception:
        db.rollback()
        return api_error(500, "Error al procesar el pedido. Inténtalo de nuevo.")

    # Devolver saldo actualizado
    nuevo_saldo = db.execute(
        "SELECT saldo FROM usuarios WHERE id = ?", (g.current_user["id"],)
    ).fetchone()["saldo"]

    return jsonify({
        "ok":        True,
        "pedido_id": pedido_id,
        "total":     total,
        "saldo":     round(nuevo_saldo, 2)
    }), 201


@app.route("/api/orders/mine", methods=["GET"])
@require_auth
def get_my_orders():
    db   = get_db()
    rows = db.execute("""
        SELECT p.id, p.total, p.fecha,
               COUNT(pi.id) AS num_items
        FROM   pedidos p
        JOIN   pedido_items pi ON pi.pedido_id = p.id
        WHERE  p.comprador_id = ?
        GROUP  BY p.id
        ORDER  BY p.fecha DESC
    """, (g.current_user["id"],)).fetchall()
    return jsonify({"ok": True, "pedidos": [dict(r) for r in rows]})


# ════════════════════════════════════════════════════════════
#  AUXILIARES
# ════════════════════════════════════════════════════════════

@app.route("/api/health")
def health():
    return jsonify({"ok": True})

@app.errorhandler(404)
def not_found(e):
    return api_error(404, "Recurso no encontrado.")

@app.errorhandler(405)
def method_not_allowed(e):
    return api_error(405, "Método no permitido.")

@app.errorhandler(429)
def too_many_requests(e):
    return api_error(429, "Demasiados intentos. Espera un momento.")

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error("Error interno: %s", str(e))
    return api_error(500, "Error interno del servidor.")


# ════════════════════════════════════════════════════════════
#  ARRANQUE
# ════════════════════════════════════════════════════════════
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 3000))
    print(f"✅  NEXUS API (Flask) → http://localhost:{port}")
    print(f"💰  Saldo inicial por usuario: {SALDO_INIT} €")
    print(f"🔑  Contraseña: {PASS_MIN}–{PASS_MAX} caracteres")
    app.run(host="0.0.0.0", port=port, debug=False)