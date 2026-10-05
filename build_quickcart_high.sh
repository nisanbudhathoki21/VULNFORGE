#!/usr/bin/env bash
set -euo pipefail

ROOT="labs/high/authorization/quickcart"

echo "[+] Creating QuickCart HIGH lab..."

mkdir -p "$ROOT"/{templates,static/css,static/js,tests}

cat > "$ROOT/requirements.txt" <<'EOF'
Flask>=3.0,<4
Werkzeug>=3.0,<4
pytest>=8,<9
EOF

cat > "$ROOT/app.py" <<'PY'
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from functools import wraps
from pathlib import Path
import re
import secrets

from flask import (
    Flask, abort, flash, jsonify, redirect, render_template,
    request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash


BASE = Path(__file__).resolve().parent

app = Flask(
    __name__,
    template_folder=str(BASE / "templates"),
    static_folder=str(BASE / "static"),
)

app.config["SECRET_KEY"] = "quickcart-local-lab-secret"
app.config["TESTING"] = False


# ============================================================
# DATA
# ============================================================

PRODUCTS = {
    1: {
        "id": 1,
        "name": "Aero Runner",
        "category": "Footwear",
        "price": Decimal("129.00"),
        "stock": 18,
        "description": "Lightweight everyday running shoes.",
    },
    2: {
        "id": 2,
        "name": "Urban Hoodie",
        "category": "Clothing",
        "price": Decimal("74.00"),
        "stock": 24,
        "description": "Heavyweight cotton everyday hoodie.",
    },
    3: {
        "id": 3,
        "name": "Classic Chrono",
        "category": "Accessories",
        "price": Decimal("189.00"),
        "stock": 8,
        "description": "Minimal stainless steel chronograph.",
    },
    4: {
        "id": 4,
        "name": "Trail Pack 28L",
        "category": "Bags",
        "price": Decimal("99.00"),
        "stock": 15,
        "description": "Weather-resistant commuter backpack.",
    },
    5: {
        "id": 5,
        "name": "Essential Tee",
        "category": "Clothing",
        "price": Decimal("34.00"),
        "stock": 50,
        "description": "Premium heavyweight cotton T-shirt.",
    },
    6: {
        "id": 6,
        "name": "City Jacket",
        "category": "Outerwear",
        "price": Decimal("159.00"),
        "stock": 11,
        "description": "Water-resistant urban shell jacket.",
    },
    7: {
        "id": 7,
        "name": "Studio Headphones",
        "category": "Electronics",
        "price": Decimal("219.00"),
        "stock": 12,
        "description": "Closed-back wireless headphones.",
    },
    8: {
        "id": 8,
        "name": "Everyday Cap",
        "category": "Accessories",
        "price": Decimal("29.00"),
        "stock": 40,
        "description": "Structured cotton everyday cap.",
    },
}


USERS = {
    "alice@example.com": {
        "id": 1,
        "name": "Alice Morgan",
        "email": "alice@example.com",
        "password": generate_password_hash("Alice@12345!"),
        "role": "customer",
        "verified": True,
        "phone": "9812345678",
    },
    "admin@example.com": {
        "id": 2,
        "name": "Admin User",
        "email": "admin@example.com",
        "password": generate_password_hash("Admin@12345!"),
        "role": "admin",
        "verified": True,
        "phone": "9800000000",
    },
}


ORDERS = []
COUPONS = {
    "WELCOME10": {
        "discount": Decimal("10.00"),
        "type": "percent",
        "active": True,
    },
}


# ============================================================
# VALIDATION
# ============================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]*@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z '\-]{1,79}$")
PHONE_RE = re.compile(r"^[0-9]{10,15}$")


def normalize_email(value):
    if not isinstance(value, str):
        raise ValueError("Invalid email address.")

    value = value.strip().lower()

    if len(value) > 254 or not EMAIL_RE.fullmatch(value):
        raise ValueError("Use a valid email address.")

    return value


def validate_name(value):
    if not isinstance(value, str):
        raise ValueError("Invalid name.")

    value = " ".join(value.strip().split())

    if not NAME_RE.fullmatch(value):
        raise ValueError("Use a valid name.")

    return value


def validate_phone(value):
    if not isinstance(value, str):
        raise ValueError("Invalid phone number.")

    value = value.strip()

    if not PHONE_RE.fullmatch(value):
        raise ValueError("Use a valid phone number.")

    return value


def validate_password(value):
    if not isinstance(value, str) or not 10 <= len(value) <= 128:
        raise ValueError("Password must contain 10-128 characters.")

    return value


def parse_positive_int(value, field="quantity"):
    try:
        if isinstance(value, bool):
            raise ValueError
        number = int(str(value).strip())
    except (ValueError, TypeError):
        raise ValueError(f"{field} must be a whole number.")

    if number < 1:
        raise ValueError(f"{field} must be at least 1.")

    if number > 99:
        raise ValueError(f"{field} is too large.")

    return number


def money(value):
    return Decimal(value).quantize(
        Decimal("0.01"),
        rounding=ROUND_HALF_UP,
    )


def server_product(product_id):
    try:
        product_id = int(product_id)
    except (TypeError, ValueError):
        abort(404)

    product = PRODUCTS.get(product_id)

    if not product:
        abort(404)

    return product


# ============================================================
# AUTH
# ============================================================

def current_user():
    email = session.get("email")

    if not email:
        return None

    return USERS.get(email)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("signin", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()

        if not user:
            return redirect(url_for("signin"))

        if user.get("role") != "admin":
            abort(403)

        return view(*args, **kwargs)

    return wrapped


# ============================================================
# CART
# ============================================================

def get_cart():
    cart = session.get("cart", {})

    if not isinstance(cart, dict):
        cart = {}

    clean = {}

    for product_id, quantity in cart.items():
        try:
            pid = int(product_id)
            qty = parse_positive_int(quantity)
        except ValueError:
            continue

        if pid in PRODUCTS:
            clean[str(pid)] = min(qty, PRODUCTS[pid]["stock"])

    return clean


def calculate_cart(cart):
    lines = []
    subtotal = Decimal("0.00")

    for product_id, quantity in cart.items():
        product = server_product(product_id)

        # SECURITY: price always comes from trusted server-side data.
        price = product["price"]

        line_total = money(price * quantity)
        subtotal += line_total

        lines.append({
            "product": product,
            "quantity": quantity,
            "price": price,
            "total": line_total,
        })

    subtotal = money(subtotal)

    discount = Decimal("0.00")
    coupon = session.get("coupon")

    if coupon in COUPONS and COUPONS[coupon]["active"]:
        rule = COUPONS[coupon]

        if rule["type"] == "percent":
            discount = money(subtotal * rule["discount"] / Decimal("100"))

    shipping = Decimal("0.00") if subtotal >= Decimal("100.00") else Decimal("8.00")
    tax = money((subtotal - discount) * Decimal("0.13"))
    total = money(subtotal - discount + shipping + tax)

    return {
        "lines": lines,
        "subtotal": subtotal,
        "discount": discount,
        "shipping": shipping,
        "tax": tax,
        "total": total,
    }


# ============================================================
# PUBLIC
# ============================================================

@app.context_processor
def inject_globals():
    return {
        "current_user": current_user(),
        "cart_count": sum(get_cart().values()),
    }


@app.route("/")
def home():
    return render_template(
        "index.html",
        products=list(PRODUCTS.values()),
    )


@app.route("/products")
def products():
    category = request.args.get("category", "").strip()

    items = list(PRODUCTS.values())

    if category:
        items = [
            product
            for product in items
            if product["category"].lower() == category.lower()
        ]

    return render_template(
        "products.html",
        products=items,
        category=category,
    )


@app.route("/products/<int:product_id>")
def product(product_id):
    item = server_product(product_id)
    return render_template("product.html", product=item)


# ============================================================
# AUTHENTICATION
# ============================================================

@app.route("/account/signin", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        try:
            email = normalize_email(request.form.get("email", ""))
            password = request.form.get("password", "")

            user = USERS.get(email)

            if not user or not check_password_hash(
                user["password"],
                password,
            ):
                raise ValueError("Invalid email or password.")

            if not user["verified"]:
                raise ValueError("Verify your email before signing in.")

            session.clear()
            session["email"] = email
            session["cart"] = {}

            return redirect(url_for("account"))

        except ValueError as exc:
            flash(str(exc), "error")

    return render_template("signin.html")


@app.route("/account/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        try:
            name = validate_name(request.form.get("name", ""))
            email = normalize_email(request.form.get("email", ""))
            password = validate_password(request.form.get("password", ""))
            confirmation = request.form.get("confirmation", "")

            if password != confirmation:
                raise ValueError("Passwords do not match.")

            if email in USERS:
                raise ValueError("An account with this email already exists.")

            USERS[email] = {
                "id": max(user["id"] for user in USERS.values()) + 1,
                "name": name,
                "email": email,
                "password": generate_password_hash(password),
                "role": "customer",
                "verified": True,
                "phone": "",
            }

            flash("Account created successfully.", "success")
            return redirect(url_for("signin"))

        except ValueError as exc:
            flash(str(exc), "error")

    return render_template("signup.html")


@app.route("/account/signout")
def signout():
    session.clear()
    return redirect(url_for("home"))


# ============================================================
# ACCOUNT
# ============================================================

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    user = current_user()

    if request.method == "POST":
        try:
            name = validate_name(request.form.get("name", ""))
            phone = validate_phone(request.form.get("phone", ""))

            user["name"] = name
            user["phone"] = phone

            flash("Profile updated.", "success")

        except ValueError as exc:
            flash(str(exc), "error")

    return render_template("account.html", user=user)


# ============================================================
# CART
# ============================================================

@app.route("/cart")
def cart():
    return render_template(
        "cart.html",
        summary=calculate_cart(get_cart()),
    )


@app.route("/api/cart/add", methods=["POST"])
def add_cart():
    data = request.get_json(silent=True) or {}

    try:
        product_id = int(data.get("product_id"))
        quantity = parse_positive_int(data.get("quantity", 1))

        product = server_product(product_id)

        if quantity > product["stock"]:
            raise ValueError("Requested quantity exceeds available stock.")

        cart = get_cart()
        new_quantity = cart.get(str(product_id), 0) + quantity

        if new_quantity > product["stock"]:
            raise ValueError("Requested quantity exceeds available stock.")

        cart[str(product_id)] = new_quantity
        session["cart"] = cart

        return jsonify({
            "ok": True,
            "cart_count": sum(cart.values()),
        })

    except (ValueError, TypeError):
        return jsonify({
            "ok": False,
            "error": "Invalid product or quantity.",
        }), 400


@app.route("/api/cart/update", methods=["POST"])
def update_cart():
    data = request.get_json(silent=True) or {}

    try:
        product_id = int(data.get("product_id"))
        quantity = parse_positive_int(data.get("quantity"))

        product = server_product(product_id)

        if quantity > product["stock"]:
            raise ValueError("Quantity exceeds stock.")

        cart = get_cart()
        cart[str(product_id)] = quantity
        session["cart"] = cart

        return jsonify({"ok": True})

    except (ValueError, TypeError):
        return jsonify({
            "ok": False,
            "error": "Invalid quantity.",
        }), 400


@app.route("/api/cart/remove", methods=["POST"])
def remove_cart():
    data = request.get_json(silent=True) or {}

    try:
        product_id = int(data.get("product_id"))
        server_product(product_id)

        cart = get_cart()
        cart.pop(str(product_id), None)
        session["cart"] = cart

        return jsonify({"ok": True})

    except (ValueError, TypeError):
        return jsonify({
            "ok": False,
            "error": "Invalid product.",
        }), 400


# ============================================================
# COUPON
# ============================================================

@app.route("/api/coupon", methods=["POST"])
@login_required
def coupon():
    data = request.get_json(silent=True) or {}

    code = data.get("code", "")

    if not isinstance(code, str):
        return jsonify({
            "ok": False,
            "error": "Invalid coupon.",
        }), 400

    code = code.strip().upper()

    if not re.fullmatch(r"[A-Z0-9]{4,32}", code):
        return jsonify({
            "ok": False,
            "error": "Invalid coupon.",
        }), 400

    if code not in COUPONS or not COUPONS[code]["active"]:
        return jsonify({
            "ok": False,
            "error": "Coupon is not valid.",
        }), 400

    session["coupon"] = code

    return jsonify({
        "ok": True,
        "coupon": code,
    })


# ============================================================
# CHECKOUT
# ============================================================

@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    cart = get_cart()

    if not cart:
        flash("Your cart is empty.", "error")
        return redirect(url_for("cart"))

    summary = calculate_cart(cart)

    if request.method == "POST":
        try:
            name = validate_name(request.form.get("name", ""))
            phone = validate_phone(request.form.get("phone", ""))
            address = request.form.get("address", "").strip()

            if not 10 <= len(address) <= 200:
                raise ValueError("Use a valid delivery address.")

            # SECURITY:
            # Never trust client-supplied subtotal/discount/tax/total.
            # Everything is recalculated from trusted server-side data.
            summary = calculate_cart(cart)

            order_id = 1000 + len(ORDERS) + 1

            order = {
                "id": order_id,
                "user_id": current_user()["id"],
                "items": [
                    {
                        "product_id": line["product"]["id"],
                        "quantity": line["quantity"],
                        "price": str(line["price"]),
                    }
                    for line in summary["lines"]
                ],
                "total": str(summary["total"]),
                "name": name,
                "phone": phone,
                "address": address,
            }

            ORDERS.append(order)

            for line in summary["lines"]:
                PRODUCTS[line["product"]["id"]]["stock"] -= line["quantity"]

            session["cart"] = {}
            session.pop("coupon", None)

            return redirect(
                url_for("order", order_id=order_id)
            )

        except ValueError as exc:
            flash(str(exc), "error")

    return render_template(
        "checkout.html",
        summary=summary,
    )


# ============================================================
# ORDERS
# ============================================================

@app.route("/orders")
@login_required
def orders():
    user = current_user()

    user_orders = [
        order
        for order in ORDERS
        if order["user_id"] == user["id"]
    ]

    return render_template(
        "orders.html",
        orders=user_orders,
    )


@app.route("/orders/<int:order_id>")
@login_required
def order(order_id):
    user = current_user()

    found = next(
        (order for order in ORDERS if order["id"] == order_id),
        None,
    )

    if not found:
        abort(404)

    if found["user_id"] != user["id"] and user["role"] != "admin":
        abort(403)

    return render_template(
        "order.html",
        order=found,
    )


# ============================================================
# ADMIN
# ============================================================

@app.route("/admin")
@admin_required
def admin():
    return render_template(
        "admin.html",
        users=list(USERS.values()),
        products=list(PRODUCTS.values()),
        orders=ORDERS,
    )


# ============================================================
# INTENTIONAL HIGH LAB VULNERABILITY
# ============================================================

@app.route("/api/account/profile", methods=["PATCH"])
@login_required
def profile_api():
    """
    INTENTIONAL HIGH-SEVERITY LAB VULNERABILITY.

    This endpoint incorrectly accepts arbitrary profile fields.

    A secure implementation would allow only:
        name
        phone

    The lab intentionally permits a privileged field such as:
        role

    This demonstrates mass assignment leading to privilege escalation.
    """

    data = request.get_json(silent=True) or {}
    user = current_user()

    # Normal fields.
    if "name" in data:
        try:
            user["name"] = validate_name(data["name"])
        except ValueError:
            return jsonify({
                "ok": False,
                "error": "Invalid name.",
            }), 400

    if "phone" in data:
        try:
            user["phone"] = validate_phone(data["phone"])
        except ValueError:
            return jsonify({
                "ok": False,
                "error": "Invalid phone.",
            }), 400

    # ========================================================
    # INTENTIONAL VULNERABILITY — DO NOT COPY TO PRODUCTION
    # ========================================================
    if "role" in data:
        role = data["role"]

        if role in {"customer", "admin"}:
            user["role"] = role

    return jsonify({
        "ok": True,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "phone": user["phone"],
            "role": user["role"],
        },
    })


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "lab": "QuickCart HIGH",
    })


@app.errorhandler(403)
def forbidden(_):
    return render_template(
        "error.html",
        code=403,
        message="Access denied.",
    ), 403


@app.errorhandler(404)
def not_found(_):
    return render_template(
        "error.html",
        code=404,
        message="Page not found.",
    ), 404


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=9002,
        debug=False,
    )
PY

cat > "$ROOT/templates/base.html" <<'HTML'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{% block title %}QuickCart{% endblock %}</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>

<header class="header">
    <div class="nav">
        <a class="logo" href="{{ url_for('home') }}">QUICKCART</a>

        <nav>
            <a href="{{ url_for('products') }}">Shop</a>
            <a href="{{ url_for('products', category='Clothing') }}">Clothing</a>
            <a href="{{ url_for('products', category='Footwear') }}">Footwear</a>
            <a href="{{ url_for('products', category='Accessories') }}">Accessories</a>
        </nav>

        <div class="actions">
            {% if current_user %}
                <a href="{{ url_for('account') }}">Account</a>
                <a href="{{ url_for('orders') }}">Orders</a>
                {% if current_user.role == "admin" %}
                    <a href="{{ url_for('admin') }}">Admin</a>
                {% endif %}
                <a href="{{ url_for('signout') }}">Sign out</a>
            {% else %}
                <a href="{{ url_for('signin') }}">Sign in</a>
                <a href="{{ url_for('signup') }}">Create account</a>
            {% endif %}
            <a class="cart" href="{{ url_for('cart') }}">Bag {{ cart_count }}</a>
        </div>
    </div>
</header>

{% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
        <div class="messages">
            {% for category, message in messages %}
                <div class="message {{ category }}">{{ message }}</div>
            {% endfor %}
        </div>
    {% endif %}
{% endwith %}

<main>
{% block content %}{% endblock %}
</main>

<footer>
    <div>
        <strong>QUICKCART</strong>
        <p>Everyday products. Simple shopping.</p>
    </div>
    <div>
        <strong>SHOP</strong>
        <a href="{{ url_for('products') }}">All products</a>
        <a href="{{ url_for('cart') }}">Shopping bag</a>
    </div>
    <div>
        <strong>ACCOUNT</strong>
        <a href="{{ url_for('account') }}">Profile</a>
        <a href="{{ url_for('orders') }}">Orders</a>
    </div>
</footer>

<script src="{{ url_for('static', filename='js/app.js') }}"></script>
</body>
</html>
HTML

cat > "$ROOT/templates/index.html" <<'HTML'
{% extends "base.html" %}
{% block title %}QuickCart — Modern Essentials{% endblock %}

{% block content %}
<section class="hero">
    <div>
        <p class="eyebrow">NEW SEASON</p>
        <h1>Everything you need.<br>Nothing you don't.</h1>
        <p>Curated everyday essentials with fast local delivery.</p>
        <a class="button" href="{{ url_for('products') }}">Shop collection</a>
    </div>
</section>

<section class="section">
    <div class="section-head">
        <div>
            <p class="eyebrow">FEATURED</p>
            <h2>Popular right now</h2>
        </div>
        <a href="{{ url_for('products') }}">View all →</a>
    </div>

    <div class="grid">
        {% for product in products[:8] %}
        <article class="card">
            <div class="product-image">
                <span>{{ product.category }}</span>
                <div>{{ product.name[:1] }}</div>
            </div>
            <div class="product-info">
                <p>{{ product.category }}</p>
                <h3>{{ product.name }}</h3>
                <strong>${{ "%.2f"|format(product.price) }}</strong>
                <a href="{{ url_for('product', product_id=product.id) }}">View product</a>
            </div>
        </article>
        {% endfor %}
    </div>
</section>
{% endblock %}
HTML

cat > "$ROOT/templates/products.html" <<'HTML'
{% extends "base.html" %}
{% block title %}Products — QuickCart{% endblock %}

{% block content %}
<section class="section">
    <p class="eyebrow">COLLECTION</p>
    <h1>{{ category or "All products" }}</h1>

    <div class="grid">
        {% for product in products %}
        <article class="card">
            <div class="product-image">
                <span>{{ product.category }}</span>
                <div>{{ product.name[:1] }}</div>
            </div>
            <div class="product-info">
                <p>{{ product.category }}</p>
                <h3>{{ product.name }}</h3>
                <strong>${{ "%.2f"|format(product.price) }}</strong>
                <a href="{{ url_for('product', product_id=product.id) }}">View product</a>
            </div>
        </article>
        {% else %}
        <p>No products found.</p>
        {% endfor %}
    </div>
</section>
{% endblock %}
HTML

cat > "$ROOT/templates/product.html" <<'HTML'
{% extends "base.html" %}
{% block title %}{{ product.name }} — QuickCart{% endblock %}

{% block content %}
<section class="product-detail">
    <div class="detail-image">
        <span>{{ product.category }}</span>
        <div>{{ product.name[:1] }}</div>
    </div>

    <div>
        <p class="eyebrow">{{ product.category }}</p>
        <h1>{{ product.name }}</h1>
        <p class="large-price">${{ "%.2f"|format(product.price) }}</p>
        <p>{{ product.description }}</p>
        <p class="stock">{{ product.stock }} available</p>

        <form id="add-cart-form">
            <input type="hidden" id="product-id" value="{{ product.id }}">
            <label>
                Quantity
                <input id="quantity" type="number" min="1" max="{{ product.stock }}" value="1">
            </label>
            <button class="button" type="submit">Add to bag</button>
        </form>

        <p id="cart-result"></p>
    </div>
</section>
{% endblock %}
HTML

cat > "$ROOT/templates/signin.html" <<'HTML'
{% extends "base.html" %}
{% block title %}Sign in — QuickCart{% endblock %}

{% block content %}
<section class="form-page">
    <p class="eyebrow">WELCOME BACK</p>
    <h1>Sign in</h1>

    <form method="post" class="form">
        <label>Email
            <input type="email" name="email" required maxlength="254"
                   autocomplete="email">
        </label>

        <label>Password
            <input type="password" name="password" required minlength="10"
                   maxlength="128" autocomplete="current-password">
        </label>

        <button class="button" type="submit">Sign in</button>
    </form>

    <p>No account? <a href="{{ url_for('signup') }}">Create one</a></p>
</section>
{% endblock %}
HTML

cat > "$ROOT/templates/signup.html" <<'HTML'
{% extends "base.html" %}
{% block title %}Create account — QuickCart{% endblock %}

{% block content %}
<section class="form-page">
    <p class="eyebrow">JOIN QUICKCART</p>
    <h1>Create account</h1>

    <form method="post" class="form">
        <label>Full name
            <input type="text" name="name" required minlength="2" maxlength="80"
                   pattern="[A-Za-z][A-Za-z '\-]{1,79}">
        </label>

        <label>Email
            <input type="email" name="email" required maxlength="254"
                   autocomplete="email">
        </label>

        <label>Password
            <input type="password" name="password" required minlength="10"
                   maxlength="128" autocomplete="new-password">
        </label>

        <label>Confirm password
            <input type="password" name="confirmation" required minlength="10"
                   maxlength="128" autocomplete="new-password">
        </label>

        <button class="button" type="submit">Create account</button>
    </form>
</section>
{% endblock %}
HTML

cat > "$ROOT/templates/account.html" <<'HTML'
{% extends "base.html" %}
{% block title %}Account — QuickCart{% endblock %}

{% block content %}
<section class="form-page">
    <p class="eyebrow">MY ACCOUNT</p>
    <h1>{{ user.name }}</h1>

    <div class="account-meta">
        <p><strong>Email:</strong> {{ user.email }}</p>
        <p><strong>Role:</strong> {{ user.role }}</p>
    </div>

    <form method="post" class="form">
        <label>Full name
            <input type="text" name="name" value="{{ user.name }}"
                   required minlength="2" maxlength="80">
        </label>

        <label>Phone
            <input type="tel" name="phone" value="{{ user.phone }}"
                   required pattern="[0-9]{10,15}">
        </label>

        <button class="button" type="submit">Save profile</button>
    </form>
</section>
{% endblock %}
HTML

cat > "$ROOT/templates/cart.html" <<'HTML'
{% extends "base.html" %}
{% block title %}Bag — QuickCart{% endblock %}

{% block content %}
<section class="section narrow">
    <p class="eyebrow">SHOPPING BAG</p>
    <h1>Your bag</h1>

    {% for line in summary.lines %}
    <div class="cart-line">
        <div>
            <strong>{{ line.product.name }}</strong>
            <p>${{ "%.2f"|format(line.price) }} × {{ line.quantity }}</p>
        </div>
        <strong>${{ "%.2f"|format(line.total) }}</strong>
    </div>
    {% else %}
    <p>Your bag is empty.</p>
    {% endfor %}

    {% if summary.lines %}
    <div class="totals">
        <p>Subtotal <strong>${{ "%.2f"|format(summary.subtotal) }}</strong></p>
        <p>Discount <strong>-${{ "%.2f"|format(summary.discount) }}</strong></p>
        <p>Shipping <strong>${{ "%.2f"|format(summary.shipping) }}</strong></p>
        <p>Tax <strong>${{ "%.2f"|format(summary.tax) }}</strong></p>
        <h2>Total ${{ "%.2f"|format(summary.total) }}</h2>
    </div>

    {% if current_user %}
        <a class="button" href="{{ url_for('checkout') }}">Checkout</a>
    {% else %}
        <a class="button" href="{{ url_for('signin') }}">Sign in to checkout</a>
    {% endif %}
    {% endif %}
</section>
{% endblock %}
HTML

cat > "$ROOT/templates/checkout.html" <<'HTML'
{% extends "base.html" %}
{% block title %}Checkout — QuickCart{% endblock %}

{% block content %}
<section class="checkout">
    <div>
        <p class="eyebrow">CHECKOUT</p>
        <h1>Delivery details</h1>

        <form method="post" class="form">
            <label>Full name
                <input name="name" required minlength="2" maxlength="80"
                       pattern="[A-Za-z][A-Za-z '\-]{1,79}">
            </label>

            <label>Phone
                <input name="phone" required pattern="[0-9]{10,15}">
            </label>

            <label>Address
                <textarea name="address" required minlength="10"
                          maxlength="200"></textarea>
            </label>

            <button class="button" type="submit">Place order</button>
        </form>
    </div>

    <aside class="summary">
        <h2>Order summary</h2>
        <p>Subtotal ${{ "%.2f"|format(summary.subtotal) }}</p>
        <p>Discount -${{ "%.2f"|format(summary.discount) }}</p>
        <p>Shipping ${{ "%.2f"|format(summary.shipping) }}</p>
        <p>Tax ${{ "%.2f"|format(summary.tax) }}</p>
        <hr>
        <h2>Total ${{ "%.2f"|format(summary.total) }}</h2>
    </aside>
</section>
{% endblock %}
HTML

cat > "$ROOT/templates/orders.html" <<'HTML'
{% extends "base.html" %}
{% block title %}Orders — QuickCart{% endblock %}

{% block content %}
<section class="section narrow">
    <p class="eyebrow">ACCOUNT</p>
    <h1>Your orders</h1>

    {% for order in orders %}
    <div class="order-row">
        <div>
            <strong>Order #{{ order.id }}</strong>
            <p>{{ order.items|length }} item(s)</p>
        </div>
        <strong>${{ order.total }}</strong>
        <a href="{{ url_for('order', order_id=order.id) }}">View</a>
    </div>
    {% else %}
    <p>No orders yet.</p>
    {% endfor %}
</section>
{% endblock %}
HTML

cat > "$ROOT/templates/order.html" <<'HTML'
{% extends "base.html" %}
{% block title %}Order #{{ order.id }} — QuickCart{% endblock %}

{% block content %}
<section class="section narrow">
    <p class="eyebrow">ORDER</p>
    <h1>#{{ order.id }}</h1>

    {% for item in order.items %}
    <div class="order-row">
        <span>Product #{{ item.product_id }}</span>
        <span>{{ item.quantity }} × ${{ item.price }}</span>
    </div>
    {% endfor %}

    <h2>Total ${{ order.total }}</h2>
</section>
{% endblock %}
HTML

cat > "$ROOT/templates/admin.html" <<'HTML'
{% extends "base.html" %}
{% block title %}Admin — QuickCart{% endblock %}

{% block content %}
<section class="section">
    <p class="eyebrow">ADMINISTRATION</p>
    <h1>QuickCart Admin</h1>

    <div class="admin-grid">
        <div class="panel">
            <h2>Users</h2>
            {% for user in users %}
            <p>
                <strong>{{ user.name }}</strong><br>
                {{ user.email }} · {{ user.role }}
            </p>
            {% endfor %}
        </div>

        <div class="panel">
            <h2>Products</h2>
            {% for product in products %}
            <p>{{ product.name }} — ${{ "%.2f"|format(product.price) }}</p>
            {% endfor %}
        </div>

        <div class="panel">
            <h2>Orders</h2>
            {% for order in orders %}
            <p>Order #{{ order.id }} — ${{ order.total }}</p>
            {% else %}
            <p>No orders.</p>
            {% endfor %}
        </div>
    </div>
</section>
{% endblock %}
HTML

cat > "$ROOT/templates/error.html" <<'HTML'
{% extends "base.html" %}
{% block title %}{{ code }} — QuickCart{% endblock %}

{% block content %}
<section class="form-page">
    <p class="eyebrow">ERROR</p>
    <h1>{{ code }}</h1>
    <p>{{ message }}</p>
    <a class="button" href="{{ url_for('home') }}">Return home</a>
</section>
{% endblock %}
HTML

cat > "$ROOT/static/css/style.css" <<'CSS'
* {
    box-sizing: border-box;
}

:root {
    --ink: #171717;
    --muted: #747474;
    --line: #e7e7e7;
    --paper: #f7f6f2;
    --white: #fff;
    --max: 1240px;
}

body {
    margin: 0;
    color: var(--ink);
    background: var(--white);
    font-family: Inter, Arial, sans-serif;
    line-height: 1.55;
}

a {
    color: inherit;
}

.header {
    border-bottom: 1px solid var(--line);
    background: rgba(255,255,255,.96);
}

.nav {
    width: min(calc(100% - 40px), var(--max));
    min-height: 72px;
    margin: auto;
    display: grid;
    grid-template-columns: auto 1fr auto;
    gap: 30px;
    align-items: center;
}

.logo {
    font-size: 18px;
    font-weight: 800;
    letter-spacing: .12em;
    text-decoration: none;
}

.nav nav,
.actions {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 22px;
}

.nav nav a,
.actions a {
    font-size: 13px;
    text-decoration: none;
}

.actions {
    justify-content: flex-end;
    gap: 14px;
}

.cart {
    font-weight: 700;
}

.messages {
    width: min(calc(100% - 40px), var(--max));
    margin: 14px auto 0;
}

.message {
    padding: 12px 16px;
    border: 1px solid var(--line);
    background: var(--paper);
}

.message.error {
    border-color: #d99;
}

.message.success {
    border-color: #9dca9d;
}

.hero {
    min-height: 510px;
    background: #171717;
    color: white;
    display: flex;
    align-items: center;
}

.hero > div {
    width: min(calc(100% - 40px), var(--max));
    margin: auto;
}

.hero h1 {
    max-width: 800px;
    margin: 10px 0 20px;
    font-size: clamp(44px, 6vw, 76px);
    line-height: .98;
    letter-spacing: -.05em;
}

.hero p:not(.eyebrow) {
    color: #ccc;
    max-width: 500px;
}

.eyebrow {
    margin: 0;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .16em;
    color: var(--muted);
}

.hero .eyebrow {
    color: #aaa;
}

.button {
    display: inline-block;
    margin-top: 18px;
    padding: 13px 22px;
    border: 0;
    background: var(--ink);
    color: white;
    text-decoration: none;
    font-weight: 700;
    cursor: pointer;
}

.hero .button {
    background: white;
    color: var(--ink);
}

.section {
    width: min(calc(100% - 40px), var(--max));
    margin: auto;
    padding: 80px 0;
}

.section.narrow,
.form-page {
    max-width: 760px;
}

.section h1,
.form-page h1 {
    font-size: clamp(38px, 5vw, 62px);
    letter-spacing: -.04em;
    line-height: 1;
    margin: 10px 0 35px;
}

.section-head {
    display: flex;
    justify-content: space-between;
    align-items: end;
    margin-bottom: 30px;
}

.section-head h2 {
    margin: 5px 0 0;
    font-size: 34px;
    letter-spacing: -.03em;
}

.section-head a {
    font-size: 13px;
}

.grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 22px;
}

.card {
    min-width: 0;
}

.product-image {
    aspect-ratio: 4 / 5;
    background: var(--paper);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    padding: 15px;
}

.product-image > span {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: .12em;
    color: var(--muted);
}

.product-image > div {
    align-self: center;
    font-size: 100px;
    font-weight: 800;
    color: #d4d2cc;
}

.product-info {
    padding: 14px 2px;
}

.product-info p {
    margin: 0 0 4px;
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .08em;
}

.product-info h3 {
    margin: 0 0 8px;
    font-size: 16px;
}

.product-info strong {
    display: block;
    margin-bottom: 10px;
}

.product-info a {
    font-size: 12px;
    text-decoration: underline;
}

.product-detail,
.checkout {
    width: min(calc(100% - 40px), 1050px);
    margin: auto;
    padding: 80px 0;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 70px;
    align-items: start;
}

.detail-image {
    aspect-ratio: 1 / 1;
    background: var(--paper);
    display: grid;
    place-items: center;
    font-size: 150px;
    font-weight: 800;
    color: #d4d2cc;
    position: relative;
}

.detail-image span {
    position: absolute;
    top: 18px;
    left: 18px;
    font-size: 10px;
    color: var(--muted);
    letter-spacing: .1em;
}

.product-detail h1 {
    font-size: clamp(42px, 5vw, 64px);
    line-height: 1;
    letter-spacing: -.05em;
}

.large-price {
    font-size: 24px;
    font-weight: 700;
}

.stock {
    color: #557955;
    font-size: 13px;
}

.form-page {
    width: min(calc(100% - 40px), 760px);
    margin: auto;
    padding: 80px 0;
}

.form {
    display: grid;
    gap: 18px;
}

.form label {
    display: grid;
    gap: 7px;
    font-size: 13px;
    font-weight: 700;
}

input,
textarea {
    width: 100%;
    padding: 13px 14px;
    border: 1px solid #d8d8d8;
    background: white;
    color: var(--ink);
    font: inherit;
}

textarea {
    min-height: 130px;
    resize: vertical;
}

.cart-line,
.order-row {
    border-bottom: 1px solid var(--line);
    padding: 20px 0;
    display: flex;
    justify-content: space-between;
    gap: 20px;
}

.cart-line p {
    margin: 4px 0 0;
    color: var(--muted);
}

.totals {
    margin: 30px 0;
    max-width: 500px;
    margin-left: auto;
}

.totals p {
    display: flex;
    justify-content: space-between;
}

.totals h2 {
    border-top: 1px solid var(--line);
    padding-top: 18px;
}

.summary {
    background: var(--paper);
    padding: 30px;
}

.summary p {
    display: flex;
    justify-content: space-between;
}

.admin-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 20px;
}

.panel {
    border: 1px solid var(--line);
    padding: 25px;
}

footer {
    border-top: 1px solid var(--line);
    padding: 55px max(20px, calc((100% - var(--max)) / 2));
    display: grid;
    grid-template-columns: 2fr 1fr 1fr;
    gap: 40px;
}

footer a {
    display: block;
    margin-top: 8px;
    font-size: 13px;
}

footer p {
    color: var(--muted);
}

@media (max-width: 900px) {
    .nav {
        grid-template-columns: 1fr;
        padding: 18px 0;
        gap: 15px;
    }

    .nav nav,
    .actions {
        flex-wrap: wrap;
        justify-content: flex-start;
    }

    .grid {
        grid-template-columns: repeat(2, 1fr);
    }

    .product-detail,
    .checkout {
        grid-template-columns: 1fr;
        gap: 35px;
    }

    .admin-grid {
        grid-template-columns: 1fr;
    }
}

@media (max-width: 600px) {
    .hero {
        min-height: 470px;
    }

    .section,
    .form-page,
    .product-detail,
    .checkout {
        padding-top: 55px;
        padding-bottom: 55px;
    }

    .grid {
        gap: 15px;
    }

    footer {
        grid-template-columns: 1fr;
    }
}
CSS

cat > "$ROOT/static/js/app.js" <<'JS'
const form = document.getElementById("add-cart-form");

if (form) {
    form.addEventListener("submit", async (event) => {
        event.preventDefault();

        const productId = Number(
            document.getElementById("product-id").value
        );

        const quantity = Number(
            document.getElementById("quantity").value
        );

        const result = document.getElementById("cart-result");

        if (!Number.isInteger(quantity) || quantity < 1) {
            result.textContent = "Enter a valid quantity.";
            return;
        }

        const response = await fetch("/api/cart/add", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                product_id: productId,
                quantity: quantity
            })
        });

        const data = await response.json();

        result.textContent = data.ok
            ? "Added to bag."
            : data.error || "Unable to add product.";
    });
}
JS

cat > "$ROOT/tests/test_app.py" <<'PY'
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app import app, PRODUCTS, USERS


def test_home():
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b"QUICKCART" in response.data


def test_products():
    client = app.test_client()
    response = client.get("/products")
    assert response.status_code == 200


def test_invalid_email_signup():
    client = app.test_client()

    response = client.post(
        "/account/signup",
        data={
            "name": "Test User",
            "email": "not-an-email",
            "password": "Password@123",
            "confirmation": "Password@123",
        },
        follow_redirects=True,
    )

    assert b"Use a valid email address." in response.data


def test_negative_quantity_rejected():
    client = app.test_client()

    response = client.post(
        "/api/cart/add",
        json={
            "product_id": 1,
            "quantity": -5,
        },
    )

    assert response.status_code == 400


def test_zero_quantity_rejected():
    client = app.test_client()

    response = client.post(
        "/api/cart/add",
        json={
            "product_id": 1,
            "quantity": 0,
        },
    )

    assert response.status_code == 400


def test_invalid_product_rejected():
    client = app.test_client()

    response = client.post(
        "/api/cart/add",
        json={
            "product_id": 999999,
            "quantity": 1,
        },
    )

    assert response.status_code == 400


def test_admin_protected():
    client = app.test_client()
    response = client.get("/admin")
    assert response.status_code == 302


def test_profile_update_requires_authentication():
    client = app.test_client()

    response = client.patch(
        "/api/account/profile",
        json={"role": "admin"},
    )

    assert response.status_code == 302


def test_demo_accounts_exist():
    assert "alice@example.com" in USERS
    assert "admin@example.com" in USERS


def test_products_have_server_side_prices():
    for product in PRODUCTS.values():
        assert product["price"] > 0
        assert product["stock"] >= 0
PY

cat > "$ROOT/README.md" <<'EOF'
# QuickCart — HIGH Security Lab

Local authorized security-testing laboratory for VULNFORGE.

## Start

python app.py

Application:

http://127.0.0.1:9002

## Demo accounts

Customer:

alice@example.com
Alice@12345!

Admin:

admin@example.com
Admin@12345!

## Intended HIGH finding

Mass Assignment → Privilege Escalation.

Endpoint:

PATCH /api/account/profile

The endpoint intentionally accepts the privileged `role` property.

This is deliberately vulnerable and exists only for the local lab.

## Security expectations

The application validates:

- email
- name
- password
- phone
- product ID
- quantity
- inventory
- coupon
- checkout calculations

Prices and checkout totals are calculated server-side.

Do not deploy this application publicly.
EOF

echo
echo "[+] QuickCart created at: $ROOT"
echo "[+] Installing lab dependencies..."

python -m pip install -q -r "$ROOT/requirements.txt"

echo "[+] Running QuickCart tests..."
cd "$ROOT"
pytest -q

echo
echo "=================================================="
echo " QUICKCART HIGH LAB READY"
echo "=================================================="
echo
echo "Start:"
echo "  cd ~/src/VulnForge/$ROOT"
echo "  python app.py"
echo
echo "URL:"
echo "  http://127.0.0.1:9002"
echo
echo "Customer:"
echo "  alice@example.com"
echo "  Alice@12345!"
echo
echo "Admin:"
echo "  admin@example.com"
echo "  Admin@12345!"
echo
echo "Intentional HIGH:"
echo "  Mass Assignment -> Privilege Escalation"
echo
echo "=================================================="
