from decimal import Decimal
from functools import wraps

from flask import Flask, abort, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config["SECRET_KEY"] = "megamart-local-training-secret"


PRODUCTS = {
    1: {
        "id": 1,
        "name": "Aero Performance Runner",
        "category": "Footwear",
        "price": Decimal("129.00"),
        "stock": 18,
        "image": "/static/images/products/aero-runner.jpg",
        "description": "Performance running shoes for everyday training.",
    },
    2: {
        "id": 2,
        "name": "Studio Wireless Headphones",
        "category": "Electronics",
        "price": Decimal("189.00"),
        "stock": 12,
        "image": "/static/images/products/headphones.jpg",
        "description": "Premium over-ear wireless headphones.",
    },
    3: {
        "id": 3,
        "name": "Minimal Chronograph",
        "category": "Accessories",
        "price": Decimal("219.00"),
        "stock": 9,
        "image": "/static/images/products/watch.jpg",
        "description": "Minimal stainless-steel chronograph.",
    },
    4: {
        "id": 4,
        "name": "Urban Leather Backpack",
        "category": "Bags",
        "price": Decimal("149.00"),
        "stock": 15,
        "image": "/static/images/products/backpack.jpg",
        "description": "Structured everyday backpack.",
    },
    5: {
        "id": 5,
        "name": "Modern Denim Jacket",
        "category": "Clothing",
        "price": Decimal("119.00"),
        "stock": 20,
        "image": "/static/images/products/jacket.jpg",
        "description": "Contemporary denim jacket.",
    },
    6: {
        "id": 6,
        "name": "Precision Coffee Machine",
        "category": "Home",
        "price": Decimal("299.00"),
        "stock": 7,
        "image": "/static/images/products/coffee.jpg",
        "description": "Compact home espresso machine.",
    },
    7: {
        "id": 7,
        "name": "Mechanical Keyboard",
        "category": "Electronics",
        "price": Decimal("139.00"),
        "stock": 16,
        "image": "/static/images/products/keyboard.jpg",
        "description": "Compact mechanical keyboard.",
    },
    8: {
        "id": 8,
        "name": "Architect Desk Lamp",
        "category": "Home",
        "price": Decimal("79.00"),
        "stock": 25,
        "image": "/static/images/products/lamp.jpg",
        "description": "Minimal adjustable desk lamp.",
    },
    9: {
        "id": 9,
        "name": "Classic Polarized Sunglasses",
        "category": "Accessories",
        "price": Decimal("89.00"),
        "stock": 22,
        "image": "/static/images/products/sunglasses.jpg",
        "description": "Lightweight polarized sunglasses.",
    },
    10: {
        "id": 10,
        "name": "Insulated Steel Bottle",
        "category": "Lifestyle",
        "price": Decimal("39.00"),
        "stock": 35,
        "image": "/static/images/products/bottle.jpg",
        "description": "Double-wall stainless-steel bottle.",
    },
}


USERS = {
    "alice@example.com": {
        "email": "alice@example.com",
        "name": "Alice Morgan",
        "password": generate_password_hash("Alice@12345!"),
        "role": "customer",
        "shipping_preference": "standard",
    },
    "admin@example.com": {
        "email": "admin@example.com",
        "name": "Admin User",
        "password": generate_password_hash("Admin@12345!"),
        "role": "admin",
        "shipping_preference": "standard",
    },
}


ORDERS = []


def current_user():
    email = session.get("user")
    return USERS.get(email) if email else None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("signin", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def valid_quantity(value):
    try:
        quantity = int(value)
    except (TypeError, ValueError):
        raise ValueError("Invalid quantity.")

    if quantity < 1 or quantity > 99:
        raise ValueError("Invalid quantity.")

    return quantity


def calculate_total(cart):
    subtotal = Decimal("0.00")

    for item in cart:
        product = PRODUCTS.get(item["product_id"])

        if product:
            subtotal += product["price"] * item["quantity"]

    shipping = (
        Decimal("0.00")
        if subtotal >= Decimal("100.00")
        else Decimal("8.00")
    )

    tax = (subtotal * Decimal("0.13")).quantize(
        Decimal("0.01")
    )

    total = subtotal + shipping + tax

    return subtotal, shipping, tax, total


@app.context_processor
def globals_for_templates():
    cart = session.get("cart", [])

    return {
        "current_user": current_user(),
        "cart_count": sum(
            item["quantity"]
            for item in cart
        ),
    }


@app.get("/")
def home():
    return render_template(
        "index.html",
        products=list(PRODUCTS.values())[:6],
    )


@app.get("/products")
def products():
    category = request.args.get(
        "category",
        "",
    ).strip()

    if category:
        items = [
            product
            for product in PRODUCTS.values()
            if product["category"].lower()
            == category.lower()
        ]
    else:
        items = list(PRODUCTS.values())

    categories = sorted({
        product["category"]
        for product in PRODUCTS.values()
    })

    return render_template(
        "products.html",
        products=items,
        categories=categories,
        selected_category=category,
    )


@app.get("/product/<int:product_id>")
def product(product_id):
    item = PRODUCTS.get(product_id)

    if not item:
        abort(404)

    return render_template(
        "product.html",
        product=item,
    )


@app.get("/search")
def search():
    query = request.args.get(
        "q",
        "",
    )

    results = []

    if query:
        lowered = query.lower()

        results = [
            product
            for product in PRODUCTS.values()
            if lowered in product["name"].lower()
            or lowered in product["category"].lower()
        ]

    return render_template(
        "search.html",
        query=query,
        results=results,
    )


@app.route(
    "/account/signin",
    methods=["GET", "POST"],
)
def signin():
    if request.method == "POST":
        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        password = request.form.get(
            "password",
            "",
        )

        user = USERS.get(email)

        if not user or not check_password_hash(
            user["password"],
            password,
        ):
            return render_template(
                "signin.html",
                error="Invalid email or password.",
            ), 401

        session.clear()
        session["user"] = email

        return redirect(
            url_for("account")
        )

    return render_template(
        "signin.html"
    )


@app.get("/account/signout")
def signout():
    session.clear()

    return redirect(
        url_for("home")
    )


@app.get("/account")
@login_required
def account():
    return render_template(
        "account.html",
        user=current_user(),
    )


@app.post("/account/shipping")
@login_required
def shipping():
    preference = request.form.get(
        "shipping_preference",
        "",
    ).strip().lower()

    if preference not in {
        "standard",
        "express",
    }:
        abort(400)

    # INTENTIONAL MEDIUM FINDING:
    # Authenticated state-changing request
    # intentionally has no CSRF token.
    current_user()[
        "shipping_preference"
    ] = preference

    return redirect(
        url_for("account")
    )


@app.post("/cart/add")
def cart_add():
    try:
        product_id = int(
            request.form.get(
                "product_id",
                "0",
            )
        )

        quantity = valid_quantity(
            request.form.get(
                "quantity",
                "1",
            )
        )

    except ValueError as exc:
        return str(exc), 400

    product = PRODUCTS.get(
        product_id
    )

    if not product:
        return "Invalid product.", 400

    if quantity > product["stock"]:
        return (
            "Requested quantity exceeds stock.",
            400,
        )

    cart = session.get(
        "cart",
        [],
    )

    for item in cart:
        if item["product_id"] == product_id:

            new_quantity = (
                item["quantity"]
                + quantity
            )

            if new_quantity > product["stock"]:
                return (
                    "Requested quantity exceeds stock.",
                    400,
                )

            item["quantity"] = new_quantity
            break

    else:
        cart.append({
            "product_id": product_id,
            "quantity": quantity,
        })

    session["cart"] = cart

    return redirect(
        url_for("cart")
    )


@app.get("/cart")
def cart():
    items = []

    for item in session.get(
        "cart",
        [],
    ):

        product = PRODUCTS.get(
            item["product_id"]
        )

        if product:
            items.append({
                "product": product,
                "quantity": item["quantity"],
                "line_total": (
                    product["price"]
                    * item["quantity"]
                ),
            })

    subtotal, shipping, tax, total = (
        calculate_total(
            [
                {
                    "product_id": item[
                        "product"
                    ]["id"],
                    "quantity": item[
                        "quantity"
                    ],
                }
                for item in items
            ]
        )
    )

    return render_template(
        "cart.html",
        items=items,
        subtotal=subtotal,
        shipping=shipping,
        tax=tax,
        total=total,
    )


@app.post(
    "/cart/remove/<int:product_id>"
)
def cart_remove(product_id):
    session["cart"] = [
        item
        for item in session.get(
            "cart",
            [],
        )
        if item["product_id"]
        != product_id
    ]

    return redirect(
        url_for("cart")
    )


@app.route(
    "/checkout",
    methods=["GET", "POST"],
)
@login_required
def checkout():

    cart = session.get(
        "cart",
        [],
    )

    if not cart:
        return redirect(
            url_for("cart")
        )

    if request.method == "POST":

        items = []

        for item in cart:

            product = PRODUCTS.get(
                item["product_id"]
            )

            if not product:
                continue

            if item["quantity"] > product["stock"]:
                return (
                    "Stock changed.",
                    409,
                )

            items.append({
                "product_id": product["id"],
                "name": product["name"],
                "quantity": item["quantity"],
                "unit_price": product["price"],
            })

        subtotal, shipping, tax, total = (
            calculate_total(
                [
                    {
                        "product_id":
                            item["product_id"],
                        "quantity":
                            item["quantity"],
                    }
                    for item in items
                ]
            )
        )

        ORDERS.append({
            "id": 7000 + len(ORDERS) + 1,
            "owner":
                current_user()["email"],
            "items": items,
            "subtotal": subtotal,
            "shipping": shipping,
            "tax": tax,
            "total": total,
        })

        session["cart"] = []

        return redirect(
            url_for("orders")
        )

    return render_template(
        "checkout.html"
    )


@app.get("/orders")
@login_required
def orders():

    mine = [
        order
        for order in ORDERS
        if order["owner"]
        == current_user()["email"]
    ]

    return render_template(
        "orders.html",
        orders=mine,
    )


@app.get("/health")
def health():
    return {
        "status": "ok",
        "lab": "megamart-medium",
        "severity": "medium",
    }


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=9003,
        debug=False,
    )
