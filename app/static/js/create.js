(() => {
  const form = document.getElementById("create-form");
  const secret = document.getElementById("secret");
  const ttl = document.getElementById("ttl");
  const views = document.getElementById("views");
  const password = document.getElementById("password");
  const e2e = document.getElementById("e2e");
  const error = document.getElementById("error");
  const result = document.getElementById("result");
  const link = document.getElementById("link");
  const copy = document.getElementById("copy");
  const submit = form.querySelector("button[type=submit]");

  const showError = (msg) => { error.textContent = msg; error.hidden = false; };

  // Stretch S3: WebCrypto needs a secure context (https or localhost).
  if (!VaultE2E.available()) {
    e2e.disabled = true;
    document.getElementById("e2e-hint").textContent = "Unavailable here: browser encryption needs HTTPS or localhost.";
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    error.hidden = true;
    const value = secret.value;
    const n = Number(views.value);
    if (!value.trim()) return showError("Enter a secret.");
    if (!Number.isInteger(n) || n < 1 || n > 10) return showError("Views must be between 1 and 10.");

    const payload = { secret: value, ttl_seconds: Number(ttl.value), max_views: n };
    if (password.value) payload.password = password.value;  // stretch S2, optional

    submit.disabled = true;
    try {
      let fragment = "";
      if (e2e.checked) {  // encrypt locally; only ciphertext is sent
        const sealed = await VaultE2E.encrypt(value);
        payload.secret = sealed.payload;
        payload.e2e = true;
        fragment = sealed.fragment;
      }
      const r = await fetch("/api/secret", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        cache: "no-store",
        credentials: "omit",
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) return showError(data.error || "Could not create the secret.");
      secret.value = "";
      password.value = "";
      link.value = fragment ? `${data.view_url}#${fragment}` : data.view_url;
      document.getElementById("expires").textContent = new Date(data.expires_at).toLocaleString();
      document.getElementById("remaining").textContent = data.views_remaining;
      // S1 fingerprint (present only when the server enables it). For e2e the server hashed
      // ciphertext, so show the plaintext hash computed here: that's what the recipient will see.
      const fpValue = data.fingerprint && (fragment ? `sha256:${await VaultE2E.sha256Hex(value)}` : data.fingerprint);
      const fp = document.getElementById("fp");
      fp.textContent = fpValue || "";
      fp.hidden = document.getElementById("fp-label").hidden = !fpValue;
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
