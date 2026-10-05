import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_DIR))

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
