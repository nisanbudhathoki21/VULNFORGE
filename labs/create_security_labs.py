#!/usr/bin/env python3

from pathlib import Path
import textwrap

ROOT = Path(__file__).resolve().parent


def write(path, content):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(textwrap.dedent(content).lstrip())
    print(f"[+] {target}")


# ============================================================
# SHARED CSS
# ============================================================

CSS = r"""
* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: Inter, Arial, sans-serif;
    background: #f4f6f9;
    color: #172033;
}

nav {
    background: #111827;
    color: white;
    min-height: 68px;
    padding: 0 7%;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.brand {
    font-size: 24px;
    font-weight: 800;
    letter-spacing: .3px;
}

nav a {
    color: white;
    text-decoration: none;
    margin-left: 24px;
}

nav a:hover {
    opacity: .75;
}

.container {
    width: 86%;
    max-width: 1200px;
    margin: 35px auto;
}

.hero {
    background: white;
    padding: 45px;
    border-radius: 18px;
    margin-bottom: 28px;
    box-shadow: 0 7px 25px rgba(0,0,0,.06);
}

.hero h1 {
    margin-top: 0;
    font-size: 40px;
}

.grid {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(230px, 1fr));
    gap: 22px;
}

.card {
    background: white;
    padding: 24px;
    border-radius: 16px;
    box-shadow: 0 7px 25px rgba(0,0,0,.06);
}

.card h2 {
    margin-top: 0;
}

.price {
    font-size: 25px;
    font-weight: 800;
    margin: 18px 0;
}

.btn,
button {
    display: inline-block;
    border: 0;
    background: #2563eb;
    color: white;
    padding: 11px 18px;
    border-radius: 9px;
    text-decoration: none;
    cursor: pointer;
    font-weight: 700;
}

input,
select {
    width: 100%;
    padding: 12px;
    border: 1px solid #d1d5db;
    border-radius: 8px;
    margin: 7px 0 15px;
}

table {
    width: 100%;
    background: white;
    border-collapse: collapse;
    overflow: hidden;
    border-radius: 14px;
}

th,
td {
    padding: 15px;
    border-bottom: 1px solid #e5e7eb;
    text-align: left;
}

.badge {
    display: inline-block;
    padding: 5px 10px;
    border-radius: 20px;
    background: #e5e7eb;
}

.notice {
    padding: 16px;
    border-radius: 10px;
    background: #eef6ff;
    margin-bottom: 20px;
}

.warning {
    padding: 16px;
    border-radius: 10px;
    background: #fff7ed;
    margin-bottom: 20px;
}

pre {
    background: #111827;
    color: #e5e7eb;
    padding: 18px;
    border-radius: 10px;
    overflow-x: auto;
}
"""


# ============================================================
# CRITICAL
# BROKEN OBJECT LEVEL AUTHORIZATION
# ============================================================

CRITICAL = "critical/authorization/shopcart"

write(
    f"{CRITICAL}/static/style.css",
    CSS,
)

write(
    f"{CRITICAL}/templates/base.html",
    r"""
    <!doctype html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport"
              content="width=device-width,initial-scale=1">
        <title>{{ title or "ShopCart" }}</title>
        <link rel="stylesheet"
              href="{{ url_for('static',
                                filename='style.css') }}">
    </head>

    <body>

    <nav>
        <div class="brand">ShopCart</div>

        <div>
            <a href="/">Home</a>
            <a href="/products">Products</a>
            <a href="/orders">Orders</a>
            <a href="/profile">Account</a>
        </div>
    </nav>

    <main class="container">
        {% block content %}{% endblock %}
    </main>

    </body>
    </html>
    """,
)

write(
    f"{CRITICAL}/templates/index.html",
    r"""
    {% extends "base.html" %}

    {% block content %}

    <section class="hero">
        <h1>Welcome to ShopCart</h1>

        <p>
            Secure online shopping for everyday products.
        </p>

        <a class="btn" href="/products">
            Browse Products
        </a>
    </section>

    <div class="grid">

        {% for p in products %}
        <div class="card">

            <h2>{{ p.name }}</h2>

            <p>{{ p.description }}</p>

            <div class="price">
                ${{ p.price }}
            </div>

            <a class="btn"
               href="/products/{{ p.id }}">
                View Product
            </a>

        </div>
        {% endfor %}

    </div>

    {% endblock %}
    """,
)

write(
    f"{CRITICAL}/templates/products.html",
    r"""
    {% extends "base.html" %}

    {% block content %}

    <section class="hero">
        <h1>Products</h1>
        <p>Choose a product.</p>
    </section>

    <div class="grid">

        {% for p in products %}
        <div class="card">

            <h2>{{ p.name }}</h2>

            <p>{{ p.description }}</p>

            <div class="price">
                ${{ p.price }}
            </div>

            <a class="btn"
               href="/products/{{ p.id }}">
                View
            </a>

        </div>
        {% endfor %}

    </div>

    {% endblock %}
    """,
)

write(
    f"{CRITICAL}/templates/product.html",
    r"""
    {% extends "base.html" %}

    {% block content %}

    <div class="card">

        <h1>{{ product.name }}</h1>

        <p>{{ product.description }}</p>

        <div class="price">
            ${{ product.price }}
        </div>

        <button onclick="alert('Product added to cart')">
            Add to Cart
        </button>

    </div>

    {% endblock %}
    """,
)

write(
    f"{CRITICAL}/templates/orders.html",
    r"""
    {% extends "base.html" %}

    {% block content %}

    <section class="hero">
        <h1>My Orders</h1>

        <p>
            Current user:
            <strong>{{ user }}</strong>
        </p>
    </section>

    <table>

        <tr>
            <th>Order</th>
            <th>Product</th>
            <th>Price</th>
            <th>Status</th>
            <th>Action</th>
        </tr>

        {% for order_id, order in orders %}

        <tr>

            <td>#{{ order_id }}</td>

            <td>{{ order.product }}</td>

            <td>${{ order.price }}</td>

            <td>
                <span class="badge">
                    {{ order.status }}
                </span>
            </td>

            <td>
                <a class="btn"
                   href="/orders/{{ order_id }}">
                    View
                </a>
            </td>

        </tr>

        {% endfor %}

    </table>

    {% endblock %}
    """,
)

write(
    f"{CRITICAL}/templates/order.html",
    r"""
    {% extends "base.html" %}

    {% block content %}

    <div class="card">

        <h1>Order #{{ order_id }}</h1>

        <p>
            Product:
            <strong>{{ order.product }}</strong>
        </p>

        <p>
            Price:
            <strong>${{ order.price }}</strong>
        </p>

        <p>
            Customer:
            <strong>{{ order.user_id }}</strong>
        </p>

        <p>
            Status:
            <span class="badge">
                {{ order.status }}
            </span>
        </p>

    </div>

    {% endblock %}
    """,
)

write(
    f"{CRITICAL}/templates/profile.html",
    r"""
    {% extends "base.html" %}

    {% block content %}

    <div class="card">

        <h1>Account</h1>

        <p>
            User:
            <strong>{{ user }}</strong>
        </p>

        <p>Role: Customer</p>

    </div>

    {% endblock %}
    """,
)

write(
    f"{CRITICAL}/app.py",
    r'''
    from flask import (
        Flask,
        jsonify,
        render_template,
        request,
    )

    app = Flask(__name__)

    USERS = {
        "alice-token": "alice",
        "bob-token": "bob",
    }

    ORDERS = {
        "1001": {
            "user_id": "alice",
            "product": "Gaming Laptop",
            "price": 1200,
            "status": "shipped",
        },
        "1002": {
            "user_id": "bob",
            "product": "Smartphone",
            "price": 800,
            "status": "processing",
        },
    }

    PRODUCTS = [
        {
            "id": 1,
            "name": "Gaming Laptop",
            "description": "High performance laptop.",
            "price": 1200,
        },
        {
            "id": 2,
            "name": "Smartphone",
            "description": "Modern smartphone.",
            "price": 800,
        },
        {
            "id": 3,
            "name": "Mechanical Keyboard",
            "description": "RGB mechanical keyboard.",
            "price": 100,
        },
    ]


    def current_user():
        token = request.headers.get("Authorization", "")

        if token.startswith("Bearer "):
            token = token[7:]

        return USERS.get(token)


    @app.get("/")
    def home():
        return render_template(
            "index.html",
            products=PRODUCTS,
            title="ShopCart",
        )


    @app.get("/products")
    def products():
        return render_template(
            "products.html",
            products=PRODUCTS,
            title="Products",
        )


    @app.get("/products/<int:product_id>")
    def product(product_id):
        product = next(
            (
                p for p in PRODUCTS
                if p["id"] == product_id
            ),
            None,
        )

        if not product:
            return "Product not found", 404

        return render_template(
            "product.html",
            product=product,
            title=product["name"],
        )


    @app.get("/profile")
    def profile():
        user = current_user() or "guest"

        return render_template(
            "profile.html",
            user=user,
            title="Account",
        )


    @app.get("/orders")
    def orders():
        user = current_user() or "alice"

        visible = [
            (order_id, order)
            for order_id, order in ORDERS.items()
            if order["user_id"] == user
        ]

        return render_template(
            "orders.html",
            user=user,
            orders=visible,
            title="Orders",
        )


    @app.get("/orders/<order_id>")
    def order_page(order_id):
        order = ORDERS.get(order_id)

        if not order:
            return "Order not found", 404

        return render_template(
            "order.html",
            order_id=order_id,
            order=order,
            title=f"Order #{order_id}",
        )


    @app.get("/api/profile")
    def api_profile():
        user = current_user()

        if not user:
            return jsonify({
                "error": "authentication required"
            }), 401

        return jsonify({
            "user": user,
            "role": "customer",
        })


    @app.get("/api/orders/<order_id>")
    def api_order(order_id):
        user = current_user()

        if not user:
            return jsonify({
                "error": "authentication required"
            }), 401

        order = ORDERS.get(order_id)

        if not order:
            return jsonify({
                "error": "order not found"
            }), 404

        # ====================================================
        # INTENTIONAL CRITICAL LAB
        #
        # Authentication is performed, but object ownership
        # is NOT enforced.
        #
        # Alice can therefore request Bob's order.
        # ====================================================

        return jsonify({
            "order_id": order_id,
            **order,
        })


    @app.get("/health")
    def health():
        return jsonify({
            "status": "ok",
            "severity": "critical",
            "lab": "authorization",
        })


    if __name__ == "__main__":
        app.run(
            host="127.0.0.1",
            port=9001,
            debug=False,
        )
    ''',
)

write(
    f"{CRITICAL}/README.md",
    """
    # Critical - ShopCart Authorization Lab

    Intended vulnerability:

    Broken Object-Level Authorization (BOLA/IDOR).

    Users:

    Alice:
      Bearer alice-token

    Bob:
      Bearer bob-token

    Orders:

      1001 -> Alice
      1002 -> Bob

    Expected security test:

      Alice requests /api/orders/1002

    The application intentionally returns Bob's order.
    """,
)


# ============================================================
# HIGH
# SQL-INJECTION-LIKE DIFFERENTIAL + REFLECTION
# ============================================================

HIGH = "high/injection/quickcart"

write(
    f"{HIGH}/static/style.css",
    CSS,
)

write(
    f"{HIGH}/templates/base.html",
    r"""
    <!doctype html>
    <html>

    <head>
        <meta charset="utf-8">
        <meta name="viewport"
              content="width=device-width,initial-scale=1">

        <title>{{ title or "QuickCart" }}</title>

        <link rel="stylesheet"
              href="{{ url_for('static',
                                filename='style.css') }}">
    </head>

    <body>

    <nav>

        <div class="brand">
            QuickCart
        </div>

        <div>
            <a href="/">Home</a>
            <a href="/products">Products</a>
            <a href="/search">Search</a>
        </div>

    </nav>

    <main class="container">
        {% block content %}{% endblock %}
    </main>

    </body>
    </html>
    """,
)

write(
    f"{HIGH}/templates/index.html",
    r"""
    {% extends "base.html" %}

    {% block content %}

    <section class="hero">

        <h1>QuickCart</h1>

        <p>
            Fast online shopping.
        </p>

        <form action="/search">

            <input
                name="q"
                placeholder="Search products..."
            >

            <button>
                Search
            </button>

        </form>

    </section>

    <div class="grid">

        {% for p in products %}

        <div class="card">

            <h2>{{ p.name }}</h2>

            <p>{{ p.category }}</p>

            <div class="price">
                ${{ p.price }}
            </div>

        </div>

        {% endfor %}

    </div>

    {% endblock %}
    """,
)

write(
    f"{HIGH}/templates/search.html",
    r"""
    {% extends "base.html" %}

    {% block content %}

    <section class="hero">

        <h1>Product Search</h1>

        <form action="/search">

            <input
                name="q"
                value="{{ query }}"
                placeholder="Search..."
            >

            <button>
                Search
            </button>

        </form>

    </section>

    <div class="notice">
        Search results for:
        <strong>{{ query }}</strong>
    </div>

    <div class="grid">

        {% for p in products %}

        <div class="card">

            <h2>{{ p.name }}</h2>

            <p>{{ p.category }}</p>

            <div class="price">
                ${{ p.price }}
            </div>

        </div>

        {% endfor %}

    </div>

    {% endblock %}
    """,
)

write(
    f"{HIGH}/app.py",
    r'''
    from flask import (
        Flask,
        jsonify,
        render_template,
        request,
    )

    app = Flask(__name__)

    PRODUCTS = [
        {
            "id": 1,
            "name": "Gaming Laptop",
            "category": "electronics",
            "price": 1200,
        },
        {
            "id": 2,
            "name": "Mechanical Keyboard",
            "category": "electronics",
            "price": 100,
        },
        {
            "id": 3,
            "name": "Running Shoes",
            "category": "fashion",
            "price": 80,
        },
    ]


    @app.get("/")
    def home():
        return render_template(
            "index.html",
            products=PRODUCTS,
            title="QuickCart",
        )


    @app.get("/products")
    def products():
        return jsonify({
            "products": PRODUCTS,
            "count": len(PRODUCTS),
        })


    @app.get("/search")
    def search():
        query = request.args.get("q", "")

        matches = [
            p for p in PRODUCTS
            if query.lower() in p["name"].lower()
        ]

        return render_template(
            "search.html",
            query=query,
            products=matches,
            title="Search",
        )


    @app.get("/api/products")
    def api_products():

        query = request.args.get("q", "")

        # Deterministic SQL-injection differential.
        #
        # This is intentionally a local training target.
        injection_probes = {
            "' OR '1'='1",
            "' OR 1=1 --",
            "' OR 1=1--",
            '" OR "1"="1',
        }

        normalized = query.strip()

        if normalized in injection_probes:
            return jsonify({
                "products": PRODUCTS,
                "count": len(PRODUCTS),
                "database": "sqlite",
                "differential": "expanded-result-set",
            })

        if "'" in query or '"' in query:
            return jsonify({
                "error": "database query syntax error",
                "query": query,
            }), 500

        matches = [
            p for p in PRODUCTS
            if query.lower() in p["name"].lower()
        ]

        return jsonify({
            "products": matches,
            "count": len(matches),
        })


    @app.get("/health")
    def health():
        return jsonify({
            "status": "ok",
            "severity": "high",
            "lab": "injection",
        })


    if __name__ == "__main__":
        app.run(
            host="127.0.0.1",
            port=9002,
            debug=False,
        )
    ''',
)

write(
    f"{HIGH}/README.md",
    """
    # High - QuickCart Injection Lab

    Intended coverage:

    - SQL-injection-like differential
    - Reflected search input

    API:

      /api/products?q=

    UI:

      /search?q=

    This is an intentionally isolated local training target.
    """,
)


# ============================================================
# MEDIUM
# BUSINESS LOGIC
# ============================================================

MEDIUM = "medium/business_logic/megamart"

write(
    f"{MEDIUM}/static/style.css",
    CSS,
)

write(
    f"{MEDIUM}/templates/base.html",
    r"""
    <!doctype html>
    <html>

    <head>

        <meta charset="utf-8">

        <meta name="viewport"
              content="width=device-width,initial-scale=1">

        <title>{{ title or "MegaMart" }}</title>

        <link rel="stylesheet"
              href="{{ url_for('static',
                                filename='style.css') }}">

    </head>

    <body>

    <nav>

        <div class="brand">
            MegaMart
        </div>

        <div>
            <a href="/">Home</a>
            <a href="/cart">Cart</a>
            <a href="/checkout">Checkout</a>
        </div>

    </nav>

    <main class="container">
        {% block content %}{% endblock %}
    </main>

    </body>
    </html>
    """,
)

write(
    f"{MEDIUM}/templates/index.html",
    r"""
    {% extends "base.html" %}

    {% block content %}

    <section class="hero">

        <h1>MegaMart</h1>

        <p>
            Everything you need in one place.
        </p>

        <a class="btn" href="/cart">
            View Cart
        </a>

    </section>

    <div class="grid">

        {% for product, price in products.items() %}

        <div class="card">

            <h2>{{ product|title }}</h2>

            <div class="price">
                ${{ price }}
            </div>

            <a class="btn" href="/cart">
                Add to Cart
            </a>

        </div>

        {% endfor %}

    </div>

    {% endblock %}
    """,
)

write(
    f"{MEDIUM}/templates/cart.html",
    r"""
    {% extends "base.html" %}

    {% block content %}

    <section class="hero">

        <h1>Your Cart</h1>

        <p>
            Review your order before checkout.
        </p>

    </section>

    <div class="card">

        <h2>Gaming Laptop</h2>

        <p>Quantity: 1</p>

        <div class="price">
            $1000
        </div>

        <a class="btn" href="/checkout">
            Proceed to Checkout
        </a>

    </div>

    {% endblock %}
    """,
)

write(
    f"{MEDIUM}/templates/checkout.html",
    r"""
    {% extends "base.html" %}

    {% block content %}

    <section class="hero">

        <h1>Checkout</h1>

        <p>
            Complete your order.
        </p>

    </section>

    <div class="card">

        <h2>Order Summary</h2>

        <p>Gaming Laptop × 1</p>

        <p>
            Subtotal:
            <strong>$1000</strong>
        </p>

        <hr>

        <h2>Coupon</h2>

        <form id="coupon-form">

            <label>User</label>

            <input
                id="user"
                value="alice"
            >

            <label>Coupon</label>

            <input
                id="coupon"
                value="WELCOME50"
            >

            <button type="submit">
                Apply Coupon
            </button>

        </form>

        <br>

        <pre id="result">
Awaiting coupon...
        </pre>

    </div>

    <script>

    document
        .getElementById("coupon-form")
        .addEventListener(
            "submit",
            async function(event) {

                event.preventDefault();

                const response = await fetch(
                    "/api/coupon/apply",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({
                            user:
                                document
                                .getElementById(
                                    "user"
                                ).value,

                            coupon:
                                document
                                .getElementById(
                                    "coupon"
                                ).value
                        })
                    }
                );

                const data =
                    await response.json();

                document
                    .getElementById("result")
                    .textContent =
                        JSON.stringify(
                            data,
                            null,
                            2
                        );
            }
        );

    </script>

    {% endblock %}
    """,
)

write(
    f"{MEDIUM}/app.py",
    r'''
    from flask import (
        Flask,
        jsonify,
        render_template,
        request,
    )

    app = Flask(__name__)

    PRODUCTS = {
        "laptop": 1000,
        "mouse": 50,
        "keyboard": 100,
    }

    COUPONS = {
        "WELCOME50": {
            "discount": 50,
            "max_uses": 1,
        }
    }

    USES = {}


    @app.get("/")
    def home():
        return render_template(
            "index.html",
            products=PRODUCTS,
            title="MegaMart",
        )


    @app.get("/cart")
    def cart():
        return render_template(
            "cart.html",
            title="Cart",
        )


    @app.get("/checkout")
    def checkout():
        return render_template(
            "checkout.html",
            title="Checkout",
        )


    @app.post("/api/cart/price")
    def cart_price():

        data = request.get_json(silent=True) or {}

        product = data.get("product")
        quantity = data.get("quantity", 1)

        if product not in PRODUCTS:
            return jsonify({
                "error": "unknown product"
            }), 400

        try:
            quantity = int(quantity)
        except (TypeError, ValueError):
            return jsonify({
                "error": "invalid quantity"
            }), 400

        if quantity <= 0:
            return jsonify({
                "error": "quantity must be positive"
            }), 400

        total = PRODUCTS[product] * quantity

        return jsonify({
            "product": product,
            "quantity": quantity,
            "unit_price": PRODUCTS[product],
            "total": total,
        })


    @app.post("/api/coupon/apply")
    def apply_coupon():

        data = request.get_json(silent=True) or {}

        coupon = data.get("coupon")
        user = data.get("user", "anonymous")

        if coupon not in COUPONS:
            return jsonify({
                "error": "invalid coupon"
            }), 400

        record = COUPONS[coupon]

        key = f"{user}:{coupon}"

        previous = USES.get(key, 0)

        # ====================================================
        # INTENTIONAL MEDIUM LAB
        #
        # Coupon is configured for one use.
        #
        # The application intentionally accepts it repeatedly.
        # ====================================================

        USES[key] = previous + 1

        return jsonify({
            "accepted": True,
            "coupon": coupon,
            "discount": record["discount"],
            "max_uses": record["max_uses"],
            "previous_uses": previous,
            "current_uses": USES[key],
            "user": user,
        })


    @app.get("/health")
    def health():
        return jsonify({
            "status": "ok",
            "severity": "medium",
            "lab": "business_logic",
        })


    if __name__ == "__main__":
        app.run(
            host="127.0.0.1",
            port=9003,
            debug=False,
        )
    ''',
)

write(
    f"{MEDIUM}/README.md",
    """
    # Medium - MegaMart Business Logic Lab

    Intended vulnerability:

    Coupon reuse / business-rule violation.

    Coupon:

      WELCOME50

    Maximum allowed uses:

      1

    The lab intentionally accepts the coupon repeatedly.

    UI:

      /checkout

    API:

      POST /api/coupon/apply
    """,
)


# ============================================================
# RUNNER
# ============================================================

write(
    "run_labs.sh",
    r'''
    #!/usr/bin/env bash

    set -u

    ROOT="$(cd "$(dirname "$0")" && pwd)"

    echo
    echo "======================================================"
    echo "                 VULNFORGE LABS"
    echo "======================================================"
    echo
    echo "  CRITICAL"
    echo "    ShopCart  http://127.0.0.1:9001"
    echo
    echo "  HIGH"
    echo "    QuickCart http://127.0.0.1:9002"
    echo
    echo "  MEDIUM"
    echo "    MegaMart  http://127.0.0.1:9003"
    echo
    echo "======================================================"
    echo

    if ! python -c "import flask" >/dev/null 2>&1; then
        echo "[ERROR] Flask is not installed."
        echo
        echo "Run:"
        echo "  python -m pip install 'Flask>=3,<4'"
        exit 1
    fi

    pids=()

    python "$ROOT/critical/authorization/shopcart/app.py" &
    pids+=("$!")

    python "$ROOT/high/injection/quickcart/app.py" &
    pids+=("$!")

    python "$ROOT/medium/business_logic/megamart/app.py" &
    pids+=("$!")

    sleep 1

    echo
    echo "[+] Services started."
    echo
    echo "Browser:"
    echo "  CRITICAL -> http://127.0.0.1:9001"
    echo "  HIGH     -> http://127.0.0.1:9002"
    echo "  MEDIUM   -> http://127.0.0.1:9003"
    echo

    cleanup() {
        echo
        echo "[*] Stopping labs..."

        for pid in "${pids[@]}"; do
            kill "$pid" 2>/dev/null || true
        done
    }

    trap cleanup EXIT INT TERM

    wait
    ''',
)

(ROOT / "run_labs.sh").chmod(0o755)

print()
print("=" * 60)
print("VULNFORGE SECURITY LABS CREATED")
print("=" * 60)
print()
print("CRITICAL : http://127.0.0.1:9001")
print("HIGH     : http://127.0.0.1:9002")
print("MEDIUM   : http://127.0.0.1:9003")
print()
