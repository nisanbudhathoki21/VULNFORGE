document.addEventListener("DOMContentLoaded", () => {
    const forms = document.querySelectorAll("form");

    forms.forEach((form) => {
        form.addEventListener("submit", () => {
            const submit = form.querySelector("button[type=\"submit\"]");

            if (submit && !submit.disabled) {
                submit.dataset.originalText = submit.textContent;
                submit.disabled = true;
                submit.textContent = "Processing...";
            }
        });
    });
});
