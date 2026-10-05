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
