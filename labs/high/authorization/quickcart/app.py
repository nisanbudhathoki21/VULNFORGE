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
        "image": "/static/images/products/aero-runner.svg",
        "description": "Lightweight everyday running shoes.",
    },
    2: {
        "id": 2,
        "name": "Urban Hoodie",
        "category": "Clothing",
        "price": Decimal("74.00"),
        "stock": 24,
        "image": "/static/images/products/urban-hoodie.svg",
        "description": "Heavyweight cotton everyday hoodie.",
    },
    3: {
        "id": 3,
        "name": "Classic Chrono",
        "category": "Accessories",
        "price": Decimal("189.00"),
        "stock": 8,
        "image": "/static/images/products/classic-chrono.svg",
        "description": "Minimal stainless steel chronograph.",
    },
    4: {
        "id": 4,
        "name": "Trail Pack 28L",
        "category": "Bags",
        "price": Decimal("99.00"),
        "stock": 15,
        "image": "/static/images/products/trail-pack.svg",
        "description": "Weather-resistant commuter backpack.",
    },
    5: {
        "id": 5,
        "name": "Essential Tee",
        "category": "Clothing",
        "price": Decimal("34.00"),
        "stock": 50,
        "image": "/static/images/products/essential-tee.svg",
        "description": "Premium heavyweight cotton T-shirt.",
    },
    6: {
        "id": 6,
        "name": "City Jacket",
        "category": "Outerwear",
        "price": Decimal("159.00"),
        "stock": 11,
        "image": "/static/images/products/city-jacket.svg",
        "description": "Water-resistant urban shell jacket.",
    },
    7: {
        "id": 7,
        "name": "Studio Headphones",
        "category": "Electronics",
        "price": Decimal("219.00"),
        "stock": 12,
        "image": "/static/images/products/studio-headphones.svg",
        "description": "Closed-back wireless headphones.",
    },
    8: {
        "id": 8,
        "name": "Everyday Cap",
        "category": "Accessories",
        "price": Decimal("29.00"),
        "stock": 40,
        "image": "/static/images/products/everyday-cap.svg",
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

        product = PRODUCTS.get(product_id)

        if not product:
            raise ValueError("Invalid product.")

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
