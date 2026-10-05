from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    redirect,
    url_for,
    session,
)

import sys
from pathlib import Path


# ============================================================
# SHARED LAB AUTHENTICATION
# ============================================================


sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[3]),
)

from common.auth import (
    USERS as ACCOUNT_USERS,
    authenticate,
    create_user,
    seed_demo_users,
    validate_email,
    validate_password,
)


# ============================================================
# APPLICATION
# ============================================================

app = Flask(__name__)

app.secret_key = "vulnforge-local-shopcart-secret"

seed_demo_users()


# ============================================================
# API TOKENS
#
# These are deliberately kept separate from browser accounts.
# VULNFORGE can use these deterministic identities to test
# authorization behavior.
# ============================================================

API_USERS = {
    "alice-token": "alice",
    "bob-token": "bob",
}


# ============================================================
# ORDERS
# ============================================================

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


# ============================================================
# PRODUCTS
# ============================================================

PRODUCTS = [
    {
        "id": 1,
        "name": "Aster Relaxed Overshirt",
        "category": "Men",
        "subcategory": "Shirts",
        "description": "A relaxed everyday overshirt crafted for effortless layering.",
        "price": 89,
        "compare_at": 109,
        "rating": 4.8,
        "reviews": 124,
        "sizes": ["S", "M", "L", "XL"],
        "colors": ["Stone", "Black", "Olive"],
        "stock": 18,
        "badge": "BESTSELLER",
        "image": "https://images.unsplash.com/photo-1596755389378-c31d21fd1273?auto=format&fit=crop&w=900&q=85",
    },
    {
        "id": 2,
        "name": "Nova Essential Hoodie",
        "category": "Unisex",
        "subcategory": "Hoodies",
        "description": "A heavyweight essential hoodie with a clean contemporary silhouette.",
        "price": 64,
        "compare_at": 79,
        "rating": 4.6,
        "reviews": 89,
        "sizes": ["S", "M", "L", "XL", "XXL"],
        "colors": ["Charcoal", "Cream", "Black"],
        "stock": 24,
        "badge": "TRENDING",
        "image": "https://images.unsplash.com/photo-1556821840-3a63f95609a7?auto=format&fit=crop&w=900&q=85",
    },
    {
        "id": 3,
        "name": "Luna Essential Tee",
        "category": "Women",
        "subcategory": "T-Shirts",
        "description": "A soft premium cotton tee designed for everyday comfort.",
        "price": 39,
        "compare_at": 49,
        "rating": 4.9,
        "reviews": 217,
        "sizes": ["XS", "S", "M", "L", "XL"],
        "colors": ["White", "Black", "Sand"],
        "stock": 31,
        "badge": "NEW",
        "image": "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?auto=format&fit=crop&w=900&q=85",
    },
    {
        "id": 4,
        "name": "Atlas Bomber Jacket",
        "category": "Men",
        "subcategory": "Outerwear",
        "description": "A structured bomber jacket with a modern streetwear finish.",
        "price": 129,
        "compare_at": 159,
        "rating": 4.7,
        "reviews": 156,
        "sizes": ["S", "M", "L", "XL"],
        "colors": ["Black", "Navy", "Olive"],
        "stock": 12,
        "badge": "LIMITED",
        "image": "https://images.unsplash.com/photo-1551028719-00167b16eac5?auto=format&fit=crop&w=900&q=85",
    },
    {
        "id": 5,
        "name": "Ridge Straight Denim",
        "category": "Unisex",
        "subcategory": "Denim",
        "description": "Classic straight-leg denim with a comfortable everyday fit.",
        "price": 79,
        "compare_at": 99,
        "rating": 4.8,
        "reviews": 103,
        "sizes": ["28", "30", "32", "34", "36"],
        "colors": ["Indigo", "Washed Black"],
        "stock": 20,
        "badge": "POPULAR",
        "image": "https://images.unsplash.com/photo-1542272604-787c3835535d?auto=format&fit=crop&w=900&q=85",
    },
    {
        "id": 6,
        "name": "Sienna Knit Dress",
        "category": "Women",
        "subcategory": "Dresses",
        "description": "A refined knit dress with a flattering silhouette for day or evening.",
        "price": 95,
        "compare_at": 119,
        "rating": 4.6,
        "reviews": 71,
        "sizes": ["XS", "S", "M", "L"],
        "colors": ["Espresso", "Cream", "Black"],
        "stock": 9,
        "badge": "NEW",
        "image": "https://images.unsplash.com/photo-1539008835657-9e8e9680c956?auto=format&fit=crop&w=900&q=85",
    },
    {
        "id": 7,
        "name": "Marlow Cargo Pants",
        "category": "Men",
        "subcategory": "Trousers",
        "description": "Relaxed cargo trousers with utility-inspired detailing.",
        "price": 74,
        "compare_at": 89,
        "rating": 4.5,
        "reviews": 64,
        "sizes": ["S", "M", "L", "XL"],
        "colors": ["Black", "Khaki", "Stone"],
        "stock": 16,
        "badge": "POPULAR",
        "image": "https://images.unsplash.com/photo-1624378439575-d8705ad7ae80?auto=format&fit=crop&w=900&q=85",
    },
    {
        "id": 8,
        "name": "Aria Soft Knit",
        "category": "Women",
        "subcategory": "Knitwear",
        "description": "A lightweight knit layer designed for understated everyday styling.",
        "price": 69,
        "compare_at": 84,
        "rating": 4.7,
        "reviews": 92,
        "sizes": ["XS", "S", "M", "L"],
        "colors": ["Oat", "Grey", "Black"],
        "stock": 14,
        "badge": "NEW",
        "image": "https://images.unsplash.com/photo-1434389677669-e08b4cac3105?auto=format&fit=crop&w=900&q=85",
    },
]



# ============================================================
# IDENTITY RESOLUTION
# ============================================================

def current_user():
    """
    Resolve the authenticated identity.

    API:
        Authorization: Bearer alice-token

    Browser:
        Flask session
    """

    authorization = request.headers.get(
        "Authorization",
        "",
    )

    if authorization.startswith("Bearer "):

        token = authorization[
            len("Bearer "):
        ].strip()

        user = API_USERS.get(token)

        if user:
            return user

    # Browser account session

    session_user = session.get("user")

    if session_user:
        return session_user

    return None


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return render_template(
        "index.html",
        products=PRODUCTS,
        title="ShopCart",
    )


# ============================================================
# PRODUCTS
# ============================================================

@app.get("/products")
def products():

    return render_template(
        "products.html",
        products=PRODUCTS,
        title="Products",
    )


@app.get("/products/<int:product_id>")
def product(product_id):

    selected_product = next(
        (
            product
            for product in PRODUCTS
            if product["id"] == product_id
        ),
        None,
    )

    if not selected_product:
        return "Product not found", 404

    return render_template(
        "product.html",
        product=selected_product,
        title=selected_product["name"],
    )


# ============================================================
# ACCOUNT — SIGN IN
# ============================================================

@app.route(
    "/account/signin",
    methods=["GET", "POST"],
)
def account_signin():

    if session.get("user"):

        return redirect(
            url_for("account")
        )

    if request.method == "POST":

        email = request.form.get(
            "email",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

        errors = []

        # Email validation

        valid_email, email_error = validate_email(
            email
        )

        if not valid_email:
            errors.append(email_error)

        # Password validation

        if not password:
            errors.append(
                "Password is required."
            )

        # Authentication

        if not errors:

            user = authenticate(
                email,
                password,
            )

            if user is None:

                errors.append(
                    "Invalid email or password."
                )

            else:

                # Start a clean authenticated session.

                session.clear()

                session["user"] = user.email
                session["first_name"] = user.first_name
                session["last_name"] = user.last_name

                return redirect(
                    url_for("account")
                )

        return render_template(
            "account/signin.html",
            errors=errors,
            title="Sign In",
        )

    return render_template(
        "account/signin.html",
        errors=[],
        title="Sign In",
    )


# ============================================================
# ACCOUNT — SIGN UP
# ============================================================

@app.route(
    "/account/signup",
    methods=["GET", "POST"],
)
def account_signup():

    if session.get("user"):
        return redirect(
            url_for("account")
        )

    if request.method == "POST":

        first_name = request.form.get(
            "first_name",
            "",
        ).strip()

        last_name = request.form.get(
            "last_name",
            "",
        ).strip()

        email = request.form.get(
            "email",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

        confirm_password = request.form.get(
            "confirm_password",
            "",
        )

        terms = request.form.get("terms")

        errors = []

        # ----------------------------------------------------
        # NAME VALIDATION
        # ----------------------------------------------------

        if not first_name:
            errors.append(
                "First name is required."
            )

        if not last_name:
            errors.append(
                "Last name is required."
            )

        # ----------------------------------------------------
        # EMAIL VALIDATION
        # ----------------------------------------------------

        valid_email, email_error = validate_email(
            email
        )

        if not valid_email:

            errors.append(email_error)

        elif email.lower() in ACCOUNT_USERS:

            errors.append(
                "An account with this email already exists."
            )

        # ----------------------------------------------------
        # PASSWORD VALIDATION
        # ----------------------------------------------------

        errors.extend(
            validate_password(password)
        )

        # ----------------------------------------------------
        # PASSWORD CONFIRMATION
        # ----------------------------------------------------

        if password != confirm_password:

            errors.append(
                "Passwords do not match."
            )

        # ----------------------------------------------------
        # TERMS
        # ----------------------------------------------------

        if not terms:

            errors.append(
                "You must accept the terms to create an account."
            )

        # ----------------------------------------------------
        # CREATE UNVERIFIED USER
        # ----------------------------------------------------

        if not errors:

            user = create_user(
                email=email,
                first_name=first_name,
                last_name=last_name,
                password=password,
                verified=False,
            )

            # Local-lab verification flow.
            #
            # In a production application this token would be
            # delivered through an email provider. For this
            # security lab we print the verification URL to
            # the Flask console instead.
            verification_url = url_for(
                "account_verify",
                token=user.verification_token,
                _external=True,
            )

            print()
            print("=" * 72)
            print("SHOPCART EMAIL VERIFICATION")
            print("=" * 72)
            print(f"Account: {user.email}")
            print(f"Verification URL: {verification_url}")
            print("=" * 72)
            print()

            return render_template(
                "account/verification_required.html",
                email=user.email,
                verification_url=verification_url,
                title="Verify Your Email",
            )

        return render_template(
            "account/signup.html",
            errors=errors,
            title="Create Account",
        )

    return render_template(
        "account/signup.html",
        errors=[],
        title="Create Account",
    )


# ============================================================
# ACCOUNT EMAIL VERIFICATION
# ============================================================

@app.get("/account/verify")
def account_verify():

    token = request.args.get(
        "token",
        "",
    )

    user = verify_user(token)

    if user is None:

        return render_template(
            "account/verification_result.html",
            success=False,
            message=(
                "This verification link is invalid "
                "or has already been used."
            ),
            title="Verification Failed",
        ), 400

    session.clear()

    session["user"] = user.email
    session["first_name"] = user.first_name
    session["last_name"] = user.last_name

    return render_template(
        "account/verification_result.html",
        success=True,
        message=(
            "Your email address has been verified. "
            "Your ShopCart account is now active."
        ),
        title="Email Verified",
    )


# ============================================================
# ACCOUNT DASHBOARD
# ============================================================


# ============================================================

@app.get("/account")
def account():

    email = session.get("user")

    if not email:

        return redirect(
            url_for("account_signin")
        )

    user = ACCOUNT_USERS.get(email)

    if user is None:

        session.clear()

        return redirect(
            url_for("account_signin")
        )

    return render_template(
        "account/dashboard.html",
        user=user,
        title="My Account",
    )


# ============================================================
# ACCOUNT SIGN OUT
# ============================================================

@app.get("/account/signout")
def account_signout():

    session.clear()

    return redirect(
        url_for("account_signin")
    )


# ============================================================
# PROFILE
# ============================================================

@app.get("/profile")
def profile():

    user = current_user()

    if not user:

        return redirect(
            url_for("account_signin")
        )

    return render_template(
        "profile.html",
        user=user,
        title="Account",
    )


# ============================================================
# ORDERS PAGE
# ============================================================

@app.get("/orders")
def orders():

    user = current_user()

    if not user:

        return redirect(
            url_for("account_signin")
        )

    visible_orders = [
        (order_id, order)
        for order_id, order in ORDERS.items()
        if order["user_id"] == user
    ]

    return render_template(
        "orders.html",
        user=user,
        orders=visible_orders,
        title="Orders",
    )


# ============================================================
# ORDER PAGE
# ============================================================

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


# ============================================================
# API PROFILE
# ============================================================

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


# ============================================================
# CRITICAL AUTHORIZATION LAB
#
# INTENTIONAL BOLA / IDOR
# ============================================================

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

    # --------------------------------------------------------
    # INTENTIONAL VULNERABILITY
    #
    # Authentication is checked.
    #
    # Ownership is NOT checked.
    #
    # Alice can access Bob's order:
    #
    # Bearer alice-token
    #       +
    # /api/orders/1002
    #
    # This MUST remain vulnerable because this endpoint is
    # the security-testing target for the critical lab.
    # --------------------------------------------------------

    response = jsonify({
        "order_id": order_id,
        **order,
    })

    # Lab-only identity assertion used by VULNFORGE's
    # authorization verification contract.
    # This exposes the authenticated requester, not the
    # object's owner, so the BOLA boundary remains testable.
    response.headers["X-Lab-Principal"] = str(user)

    return response


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return jsonify({
        "status": "ok",
        "severity": "critical",
        "lab": "authorization",
    })


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=9001,
        debug=False,
    )
