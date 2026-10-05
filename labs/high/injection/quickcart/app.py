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
