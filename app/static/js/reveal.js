(() => {
  const main = document.querySelector("[data-secret-id]");
  const id = main.dataset.secretId;
  const btn = document.getElementById("reveal");
  const out = document.getElementById("secret");
  const result = document.getElementById("result");
  const status = document.getElementById("status");
  const copy = document.getElementById("copy");
  const exp = document.getElementById("expires");
  const expDate = new Date(exp.dateTime);
  if (!isNaN(expDate)) exp.textContent = expDate.toLocaleString();

  btn.addEventListener("click", async () => {
    if (!confirm("This will reveal the secret and permanently destroy it. Continue?")) return;
    btn.disabled = true;
    btn.textContent = "Revealing…";
    try {
      const r = await fetch(`/api/secret/${encodeURIComponent(id)}/burn`,
        { method: "POST", cache: "no-store", credentials: "omit" });
      const data = await r.json().catch(() => ({}));
      if (r.ok) {
        out.textContent = data.secret; // never innerHTML
        out.hidden = false;
        copy.hidden = false;
        status.textContent = data.burned
          ? "This secret has been destroyed. It cannot be viewed again."
          : `${data.views_remaining} view(s) remaining.`;
        document.getElementById("views").textContent = data.views_remaining;
      } else {
        out.hidden = true;
        copy.hidden = true;
        status.textContent = data.error || "Secret not found, expired, or already destroyed.";
      }
      result.hidden = false;
      btn.hidden = true;
    } catch {
      // The POST may have reached the server even though the response was lost.
      btn.disabled = false;
      btn.textContent = "Reveal and Destroy Secret";
      out.hidden = true;
      copy.hidden = true;
      status.textContent = "Network error. The request may have succeeded, and the secret may already " +
        "have been consumed. Check again before retrying.";
      result.hidden = false;
    }
  });

  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(out.textContent);
      copy.textContent = "Copied";
    } catch {
      const range = document.createRange();
      range.selectNodeContents(out);
      const sel = getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    }
  });

  addEventListener("pagehide", () => { out.textContent = ""; });
})();
