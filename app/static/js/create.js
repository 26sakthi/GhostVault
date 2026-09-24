(() => {
  const form = document.getElementById("create-form");
  const secret = document.getElementById("secret");
  const ttl = document.getElementById("ttl");
  const views = document.getElementById("views");
  const error = document.getElementById("error");
  const result = document.getElementById("result");
  const link = document.getElementById("link");
  const copy = document.getElementById("copy");
  const submit = form.querySelector("button[type=submit]");

  const showError = (msg) => { error.textContent = msg; error.hidden = false; };

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    error.hidden = true;
    const value = secret.value;
    const n = Number(views.value);
    if (!value.trim()) return showError("Enter a secret.");
    if (!Number.isInteger(n) || n < 1 || n > 10) return showError("Views must be between 1 and 10.");

    submit.disabled = true;
    try {
      const r = await fetch("/api/secret", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ secret: value, ttl_seconds: Number(ttl.value), max_views: n }),
        cache: "no-store",
        credentials: "omit",
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) return showError(data.error || "Could not create the secret.");
      secret.value = "";
      link.value = data.view_url;
      document.getElementById("expires").textContent = new Date(data.expires_at).toLocaleString();
      document.getElementById("remaining").textContent = data.views_remaining;
      form.hidden = true;
      result.hidden = false;
      link.focus();
      link.select();
    } catch {
      showError("Network error. Please try again.");
    } finally {
      submit.disabled = false;
    }
  });

  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(link.value);
      copy.textContent = "Copied";
    } catch {
      link.select();
    }
  });

  document.getElementById("another").addEventListener("click", () => {
    result.hidden = true;
    form.hidden = false;
    copy.textContent = "Copy";
    secret.focus();
  });
})();
