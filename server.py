#!/usr/bin/env python3
"""
FloraFlow - Backend server (Python standard library only, nothing to pip install).

 * SQLite database : floraflow.db (created + seeded automatically on first run)
 * Separate logins : Customer portal, Administrator portal, Staff/Delivery portal
 * Passwords       : salted PBKDF2 hashes, never sent to the browser
 * Sessions        : HttpOnly cookie
 * Role rules      : enforced here on the server (the browser cannot bypass them)

Run:  python server.py     ->  http://localhost:8000
Env : PORT (default 8000), DB_PATH (default ./floraflow.db; point it at a persistent disk when hosting)
"""
import json, os, re, secrets, hashlib, sqlite3, threading, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http import cookies
from urllib.parse import urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "floraflow.db"))
SEED_PATH = os.path.join(BASE, "seed.json")
PORT = int(os.environ.get("PORT", 8000))
SESSION_TTL = 8 * 3600
PUBLIC_FILES = {"index.html", "login.html", "auth.js", "favicon.ico"}   # only these are ever served

SESSIONS = {}          # token -> (role, id, expires)
LOCK = threading.RLock()
FAILS = {}             # ip -> (count, first_time)   simple brute-force throttle

PORTALS = {"customer": {"Customer"}, "admin": {"Administrator"}, "staff": {"Staff", "DeliveryPerson"}}
STATUSES = ["Order Placed", "Payment Confirmed", "Preparing", "Ready", "Out for Delivery", "Delivered", "Cancelled"]
DELIVERY_FLOW = {"Out for Delivery", "Delivered"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS customers(
    customer_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, salt TEXT NOT NULL,
    phone TEXT, address TEXT);
CREATE TABLE IF NOT EXISTS staff(
    staff_id INTEGER PRIMARY KEY, name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('Staff','DeliveryPerson','Administrator')),
    email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, salt TEXT NOT NULL,
    phone TEXT, vehicle TEXT);
CREATE TABLE IF NOT EXISTS categories(category_id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT);
CREATE TABLE IF NOT EXISTS suppliers(supplier_id INTEGER PRIMARY KEY, name TEXT NOT NULL, contact TEXT, address TEXT, rating REAL);
CREATE TABLE IF NOT EXISTS flowers(
    flower_id INTEGER PRIMARY KEY, category_id INTEGER, supplier_id INTEGER, name TEXT NOT NULL,
    color TEXT, price REAL NOT NULL, stock_qty INTEGER NOT NULL DEFAULT 0, occasion TEXT, image TEXT, description TEXT);
CREATE TABLE IF NOT EXISTS coupons(code TEXT PRIMARY KEY, discount REAL, min_order REAL);
CREATE TABLE IF NOT EXISTS orders(
    order_id INTEGER PRIMARY KEY, customer_id INTEGER NOT NULL, order_date TEXT, delivery_date TEXT,
    delivery_time TEXT, delivery_address TEXT, status TEXT, subtotal REAL, delivery_charge REAL,
    discount REAL, total_amount REAL, assigned_staff_id INTEGER,
    FOREIGN KEY(customer_id) REFERENCES customers(customer_id));
CREATE TABLE IF NOT EXISTS order_items(
    item_id INTEGER, order_id INTEGER NOT NULL, flower_id INTEGER, quantity INTEGER, unit_price REAL,
    PRIMARY KEY(order_id, item_id), FOREIGN KEY(order_id) REFERENCES orders(order_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS payments(
    payment_id TEXT PRIMARY KEY, order_id INTEGER NOT NULL, method TEXT, amount REAL, status TEXT, paid_on TEXT,
    FOREIGN KEY(order_id) REFERENCES orders(order_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS deliveries(
    delivery_id TEXT PRIMARY KEY, order_id INTEGER NOT NULL, staff_id INTEGER, address TEXT, status TEXT, delivered_on TEXT,
    FOREIGN KEY(order_id) REFERENCES orders(order_id) ON DELETE CASCADE);
"""

# ------------------------------------------------------------------ database helpers
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con

def hash_pw(password, salt=None):
    salt = salt or secrets.token_hex(16)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 150_000).hex(), salt

def verify_pw(password, h, salt):
    return secrets.compare_digest(hash_pw(password, salt)[0], h)

def rows(con, sql, *a):
    return [dict(r) for r in con.execute(sql, a)]

def cols(con, table):
    return [r[1] for r in con.execute(f"PRAGMA table_info({table})")]

def insert_dict(con, table, d, replace=False):
    c = [k for k in cols(con, table) if k in d]
    con.execute(f"INSERT OR {'REPLACE' if replace else 'ABORT'} INTO {table}({','.join(c)}) VALUES({','.join('?'*len(c))})",
                [d[k] for k in c])

def init_db(reset=False):
    with LOCK:
        con = db()
        if reset:
            for t in ("deliveries", "payments", "order_items", "orders", "coupons", "flowers",
                      "suppliers", "categories", "staff", "customers"):
                con.execute(f"DROP TABLE IF EXISTS {t}")
        con.executescript(SCHEMA)
        if con.execute("SELECT COUNT(*) FROM staff").fetchone()[0] == 0:
            seed = json.load(open(SEED_PATH, encoding="utf-8"))
            for t in ("categories", "suppliers", "flowers", "coupons"):
                for r in seed[t]:
                    insert_dict(con, t, r)
            for t in ("customers", "staff"):
                for r in seed[t]:
                    r = dict(r); r["password_hash"], r["salt"] = hash_pw(r.pop("password"))
                    insert_dict(con, t, r)
            for t in ("orders", "order_items", "payments", "deliveries"):
                for r in seed[t]:
                    insert_dict(con, t, r)
        con.commit(); con.close()

PUBLIC_CUST = "customer_id,name,email,phone,address"
PUBLIC_STAFF = "staff_id,name,role,email,phone,vehicle"

def whoami(con, role, uid):
    if role == "Customer":
        r = con.execute("SELECT * FROM customers WHERE customer_id=?", (uid,)).fetchone()
        return {"id": r["customer_id"], "name": r["name"], "email": r["email"], "role": "Customer",
                "phone": r["phone"], "address": r["address"]} if r else None
    r = con.execute("SELECT * FROM staff WHERE staff_id=?", (uid,)).fetchone()
    return {"id": r["staff_id"], "name": r["name"], "email": r["email"], "role": r["role"],
            "phone": r["phone"], "address": ""} if r else None

def build_state(me):
    """The same `db` shape the front-end already uses, filtered to what this role may see."""
    con = db()
    try:
        role, uid = me["role"], me["id"]
        S = {"categories": rows(con, "SELECT * FROM categories ORDER BY category_id"),
             "flowers": rows(con, "SELECT * FROM flowers ORDER BY flower_id"),
             "coupons": rows(con, "SELECT * FROM coupons")}
        if role in ("Administrator", "Staff"):
            S["customers"] = rows(con, f"SELECT {PUBLIC_CUST} FROM customers ORDER BY customer_id")
            S["staff"] = rows(con, f"SELECT {PUBLIC_STAFF} FROM staff ORDER BY staff_id")
            S["suppliers"] = rows(con, "SELECT * FROM suppliers ORDER BY supplier_id")
            S["orders"] = rows(con, "SELECT * FROM orders ORDER BY order_id DESC")
        elif role == "DeliveryPerson":
            S["suppliers"] = []
            S["orders"] = rows(con, "SELECT * FROM orders WHERE assigned_staff_id=? OR status='Out for Delivery' "
                                    "ORDER BY order_id DESC", uid)
            ids = {o["customer_id"] for o in S["orders"]} or {-1}
            S["customers"] = rows(con, f"SELECT {PUBLIC_CUST} FROM customers WHERE customer_id IN ({','.join('?'*len(ids))})", *ids)
            S["staff"] = rows(con, f"SELECT {PUBLIC_STAFF} FROM staff WHERE staff_id=?", uid)
        else:  # Customer
            S["suppliers"] = []
            S["customers"] = rows(con, f"SELECT {PUBLIC_CUST} FROM customers WHERE customer_id=?", uid)
            S["staff"] = []
            S["orders"] = rows(con, "SELECT * FROM orders WHERE customer_id=? ORDER BY order_id DESC", uid)
        oids = [o["order_id"] for o in S["orders"]] or [-1]
        q = ",".join("?" * len(oids))
        for t in ("order_items", "payments", "deliveries"):
            S[t] = rows(con, f"SELECT * FROM {t} WHERE order_id IN ({q})", *oids)
        S["meta"] = {"next_order_id": con.execute("SELECT COALESCE(MAX(order_id),1000) FROM orders").fetchone()[0] + 1}
        return S
    finally:
        con.close()

# ------------------------------------------------------------------ applying changes (role rules live here)
class Denied(Exception):
    pass

def place_order(con, me, ch):
    """A customer is placing an order. Prices, stock and totals are recomputed here, never trusted from the browser."""
    o = ch["orders"]["upsert"][0]
    items_in = ch.get("order_items", {}).get("upsert", [])
    if o.get("customer_id") != me["id"]:
        raise Denied("You can only place orders for your own account.")
    if not items_in:
        raise Denied("The order has no items.")
    subtotal, items = 0, []
    for n, it in enumerate(items_in, 1):
        f = con.execute("SELECT * FROM flowers WHERE flower_id=?", (it.get("flower_id"),)).fetchone()
        qty = int(it.get("quantity", 0))
        if not f or qty < 1:
            raise Denied("Invalid item in order.")
        if qty > f["stock_qty"]:
            raise Denied(f"Sorry, only {f['stock_qty']} of '{f['name']}' are left in stock.")
        subtotal += f["price"] * qty
        items.append((f, qty))
    discount = float(o.get("discount") or 0)
    if discount:
        ok = con.execute("SELECT 1 FROM coupons WHERE discount=? AND min_order<=?", (discount, subtotal)).fetchone()
        if not ok:
            discount = 0
    delivery = 50
    total = max(0, subtotal + delivery - discount)
    pay_in = (ch.get("payments", {}).get("upsert") or [{}])[0]
    cod = "cash" in str(pay_in.get("method", "")).lower()
    paid = (not cod) and pay_in.get("status") == "Paid"
    oid = con.execute("SELECT COALESCE(MAX(order_id),1000)+1 FROM orders").fetchone()[0]
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    staff_id = o.get("assigned_staff_id")
    if not con.execute("SELECT 1 FROM staff WHERE staff_id=? AND role='DeliveryPerson'", (staff_id,)).fetchone():
        staff_id = None
    insert_dict(con, "orders", {
        "order_id": oid, "customer_id": me["id"], "order_date": now, "delivery_date": o.get("delivery_date"),
        "delivery_time": o.get("delivery_time"), "delivery_address": str(o.get("delivery_address", ""))[:300],
        "status": "Payment Confirmed" if paid else "Order Placed", "subtotal": subtotal,
        "delivery_charge": delivery, "discount": discount, "total_amount": total, "assigned_staff_id": staff_id})
    for n, (f, qty) in enumerate(items, 1):
        insert_dict(con, "order_items", {"item_id": n, "order_id": oid, "flower_id": f["flower_id"],
                                         "quantity": qty, "unit_price": f["price"]})
        con.execute("UPDATE flowers SET stock_qty=stock_qty-? WHERE flower_id=?", (qty, f["flower_id"]))
    insert_dict(con, "payments", {"payment_id": f"PAY-{oid}-{secrets.token_hex(2).upper()}", "order_id": oid,
                                  "method": "Cash on Delivery" if cod else "Online Payment (Card)", "amount": total,
                                  "status": "Paid" if paid else "Pending", "paid_on": now if paid else None})
    insert_dict(con, "deliveries", {"delivery_id": f"DEL-{oid}", "order_id": oid, "staff_id": staff_id,
                                    "address": str(o.get("delivery_address", ""))[:300], "status": "Scheduled", "delivered_on": None})
    return oid

def apply_changes(me, ch):
    role, uid = me["role"], me["id"]
    con = db()
    try:
        con.execute("BEGIN")
        result = {}
        up = lambda t: ch.get(t, {}).get("upsert", [])
        dl = lambda t: ch.get(t, {}).get("delete", [])
        new_orders = [o for o in up("orders") if not con.execute("SELECT 1 FROM orders WHERE order_id=?", (o["order_id"],)).fetchone()]

        # ---------- CUSTOMER: may only place a new order for themselves
        if role == "Customer":
            for t in ch:
                if t not in ("orders", "order_items", "payments", "deliveries", "flowers", "customers", "meta"):
                    raise Denied("Not allowed.")
            if len(new_orders) == 1 and len(up("orders")) == 1:
                result["order_id"] = place_order(con, me, ch)
            elif up("orders") or dl("orders") or dl("flowers"):
                raise Denied("Customers can only place new orders.")
            # stock/customers changes from the browser are ignored: the server already reduced stock itself
            con.commit()
            return result

        # ---------- STAFF / DELIVERY / ADMIN : updates to existing orders
        for o in up("orders"):
            cur = con.execute("SELECT * FROM orders WHERE order_id=?", (o["order_id"],)).fetchone()
            if not cur:
                raise Denied("Unknown order.")
            if role == "DeliveryPerson":
                if not (cur["assigned_staff_id"] == uid or cur["status"] == "Out for Delivery"):
                    raise Denied("That order is not assigned to you.")
                if o.get("status") not in DELIVERY_FLOW:
                    raise Denied("Couriers can only start a run or mark an order delivered.")
            elif o.get("status") not in STATUSES:
                raise Denied("Invalid order status.")
            sid = o.get("assigned_staff_id") if role != "DeliveryPerson" else cur["assigned_staff_id"]
            if sid is not None and not con.execute("SELECT 1 FROM staff WHERE staff_id=? AND role='DeliveryPerson'", (sid,)).fetchone():
                sid = None
            con.execute("UPDATE orders SET status=?, assigned_staff_id=? WHERE order_id=?", (o["status"], sid, o["order_id"]))
        for d in up("deliveries"):
            cur = con.execute("SELECT o.* FROM orders o WHERE o.order_id=?", (d["order_id"],)).fetchone()
            if not cur:
                continue
            if role == "DeliveryPerson" and not (cur["assigned_staff_id"] == uid or cur["status"] in DELIVERY_FLOW):
                continue
            con.execute("UPDATE deliveries SET status=?, delivered_on=?, staff_id=? WHERE order_id=?",
                        (d.get("status"), d.get("delivered_on"), cur["assigned_staff_id"], d["order_id"]))
        for p in up("payments"):                       # cash on delivery is marked paid when the courier delivers
            cur = con.execute("SELECT * FROM payments WHERE order_id=?", (p["order_id"],)).fetchone()
            ord_ = con.execute("SELECT status FROM orders WHERE order_id=?", (p["order_id"],)).fetchone()
            if cur and p.get("status") == "Paid" and cur["status"] != "Paid" and ord_ and ord_["status"] == "Delivered":
                con.execute("UPDATE payments SET status='Paid', paid_on=? WHERE order_id=?", (p.get("paid_on"), p["order_id"]))

        # ---------- flowers
        for f in up("flowers"):
            cur = con.execute("SELECT * FROM flowers WHERE flower_id=?", (f["flower_id"],)).fetchone()
            if role == "Administrator":
                if not str(f.get("name", "")).strip() or float(f.get("price", -1)) < 0 or int(f.get("stock_qty", -1)) < 0:
                    raise Denied("Flower needs a name, a valid price and stock.")
                insert_dict(con, "flowers", f, replace=True)
            elif role == "Staff" and cur and int(f["stock_qty"]) >= cur["stock_qty"]:
                con.execute("UPDATE flowers SET stock_qty=? WHERE flower_id=?", (int(f["stock_qty"]), f["flower_id"]))
            elif cur and int(f.get("stock_qty", 0)) != cur["stock_qty"]:
                raise Denied("You are not allowed to change stock.")
        if dl("flowers"):
            if role != "Administrator":
                raise Denied("Only administrators can delete flowers.")
            for fid in dl("flowers"):
                con.execute("DELETE FROM flowers WHERE flower_id=?", (fid,))

        # ---------- categories (admin only)
        if up("categories") or dl("categories"):
            if role != "Administrator":
                raise Denied("Only administrators can change categories.")
            for c in up("categories"):
                insert_dict(con, "categories", c, replace=True)
            for cid in dl("categories"):
                con.execute("DELETE FROM categories WHERE category_id=?", (cid,))
        con.commit()
        return result
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()

# ------------------------------------------------------------------ HTTP
MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8", ".ico": "image/x-icon"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

class Handler(BaseHTTPRequestHandler):
    server_version = "FloraFlow/2.0"
    def log_message(self, *a): pass

    def session(self):
        c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        tok = c["ff_sid"].value if "ff_sid" in c else None
        with LOCK:
            s = SESSIONS.get(tok)
            if not s or s[2] < time.time():
                SESSIONS.pop(tok, None); return None
            SESSIONS[tok] = (s[0], s[1], time.time() + SESSION_TTL)
        con = db()
        try:
            return whoami(con, s[0], s[1])
        finally:
            con.close()

    def send_json(self, obj, code=200, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)

    def read_json(self):
        n = int(self.headers.get("Content-Length", 0))
        if n > 2_000_000: raise ValueError("too large")
        return json.loads(self.rfile.read(n) or b"{}")

    def cookie_header(self, value, max_age):
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
        return f"ff_sid={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"

    # ---- GET
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/me":
            me = self.session()
            return self.send_json({"user": me}) if me else self.send_json({"error": "Not signed in"}, 401)
        if path == "/api/state":
            me = self.session()
            return self.send_json(build_state(me)) if me else self.send_json({"error": "Not signed in"}, 401)
        if path == "/api/admin/ping":                       # used by the in-app test suite (TC12)
            me = self.session()
            if not me: return self.send_json({"error": "Not signed in"}, 401)
            return self.send_json({"ok": True}) if me["role"] == "Administrator" else self.send_json({"error": "Access denied"}, 403)
        self.static(path)

    # ---- POST
    def do_POST(self):
        path = urlparse(self.path).path
        try: data = self.read_json()
        except Exception: return self.send_json({"error": "Bad request"}, 400)
        if path == "/api/login": return self.api_login(data)
        if path == "/api/register": return self.api_register(data)
        if path == "/api/logout":
            c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            if "ff_sid" in c:
                with LOCK: SESSIONS.pop(c["ff_sid"].value, None)
            return self.send_json({"ok": True}, headers={"Set-Cookie": self.cookie_header("", 0)})
        me = self.session()
        if not me: return self.send_json({"error": "Not signed in"}, 401)
        if path == "/api/changes":
            try:
                with LOCK: res = apply_changes(me, data)
                return self.send_json({"ok": True, **res})
            except Denied as e:
                return self.send_json({"error": str(e)}, 403)
            except Exception as e:
                return self.send_json({"error": f"Could not save: {e}"}, 400)
        if path == "/api/reset":
            if me["role"] != "Administrator": return self.send_json({"error": "Administrator only"}, 403)
            with LOCK: init_db(reset=True)
            return self.send_json({"ok": True})
        self.send_json({"error": "Not found"}, 404)

    def api_login(self, d):
        ip = self.client_address[0]
        with LOCK:
            n, t0 = FAILS.get(ip, (0, time.time()))
            if time.time() - t0 > 300: n, t0 = 0, time.time()
            if n >= 8:
                return self.send_json({"error": "Too many attempts. Please wait a few minutes."}, 429)
        email, pw, portal = str(d.get("email", "")).strip(), str(d.get("password", "")), d.get("portal", "customer")
        con = db()
        try:
            row, role, uid = con.execute("SELECT * FROM customers WHERE email=?", (email,)).fetchone(), "Customer", None
            if row: uid = row["customer_id"]
            else:
                row = con.execute("SELECT * FROM staff WHERE email=?", (email,)).fetchone()
                if row: role, uid = row["role"], row["staff_id"]
            if not row or not verify_pw(pw, row["password_hash"], row["salt"]):
                with LOCK: FAILS[ip] = (n + 1, t0)
                time.sleep(0.4)
                return self.send_json({"error": "Invalid email or password."}, 401)
            if role not in PORTALS.get(portal, set()):
                where = {"Customer": "Customer", "Administrator": "Administrator"}.get(role, "Staff / Delivery")
                return self.send_json({"error": f"This account can't sign in here. Please use the {where} login."}, 403)
            me = whoami(con, role, uid)
        finally:
            con.close()
        with LOCK: FAILS.pop(ip, None)
        tok = secrets.token_urlsafe(32)
        with LOCK: SESSIONS[tok] = (role, uid, time.time() + SESSION_TTL)
        self.send_json({"user": me}, headers={"Set-Cookie": self.cookie_header(tok, SESSION_TTL)})

    def api_register(self, d):
        name, email, pw = str(d.get("name", "")).strip(), str(d.get("email", "")).strip(), str(d.get("password", ""))
        address = str(d.get("address", "")).strip()
        if len(name) < 2 or not EMAIL_RE.match(email) or len(pw) < 6 or not address:
            return self.send_json({"error": "Enter your name, a valid email, an address and a password of 6+ characters."}, 400)
        con = db()
        try:
            if con.execute("SELECT 1 FROM staff WHERE email=?", (email,)).fetchone():
                return self.send_json({"error": "That email is already registered."}, 409)
            h, salt = hash_pw(pw)
            con.execute("INSERT INTO customers(name,email,password_hash,salt,phone,address) VALUES(?,?,?,?,?,?)",
                        (name, email, h, salt, str(d.get("phone", "")).strip() or "+91 98765 00000", address))
            con.commit()
        except sqlite3.IntegrityError:
            return self.send_json({"error": "That email is already registered."}, 409)
        finally:
            con.close()
        self.send_json({"ok": True}, 201)

    # ---- static (only a fixed whitelist of files is ever served)
    def static(self, path):
        name = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
        if name == "index.html" and not self.session():
            self.send_response(302); self.send_header("Location", "/login.html"); self.end_headers(); return
        if name not in PUBLIC_FILES:
            return self.send_json({"error": "Not found"}, 404)
        full = os.path.join(BASE, name)
        if not os.path.isfile(full):
            return self.send_json({"error": "Not found"}, 404)
        body = open(full, "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", MIME.get(os.path.splitext(name)[1], "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers(); self.wfile.write(body)

if __name__ == "__main__":
    init_db()
    print(f"\n  FloraFlow running ->  http://localhost:{PORT}\n  Database: {DB_PATH}\n  Press Ctrl+C to stop.\n")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
