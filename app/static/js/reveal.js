(() => {
  const main = document.querySelector("[data-secret-id]");
  const id = main.dataset.secretId;
  const btn = document.getElementById("reveal");
  const out = document.getElementById("secret");
  const result = document.getElementById("result");
  const status = document.getElementById("status");
  const copy = document.getElementById("copy");
  const fpOut = document.getElementById("fingerprint");
  const exp = document.getElementById("expires");
  const expDate = new Date(exp.dateTime);
  if (!isNaN(expDate)) exp.textContent = expDate.toLocaleString();

  // Stretch S1: same SHA-256 the sender got at creation, so both sides can compare.
  async function showFingerprint(secret) {
    if (!main.dataset.fingerprint || !window.crypto?.subtle) return;  // subtle needs a secure context
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
    const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
    fpOut.textContent = `Fingerprint: sha256:${hex}`;
    fpOut.hidden = false;
  }

  // Stretch S2: password field is rendered only for protected secrets.
  const pw = document.getElementById("password");
  const pwError = document.getElementById("pw-error");
  const showPwError = (msg) => { pwError.textContent = msg; pwError.hidden = false; };

  // Stretch S3: for end-to-end encrypted secrets, load the key from the #fragment BEFORE allowing a
  // reveal. Without a usable key a burn would destroy a secret that can never be decrypted.
  let e2eKey = null;
  if (main.dataset.e2e) {
    btn.disabled = true;
    const e2eError = document.getElementById("e2e-error");
    const blockReveal = (msg) => { e2eError.textContent = msg; e2eError.hidden = false; };
    const loadKey = () => {
      e2eKey = null;
      btn.disabled = true;
      VaultE2E.keyFromHash(location.hash).then((key) => {
        if (!key) {
          blockReveal("This link is missing its decryption key (the part after #). Ask the sender for the full link. Nothing was revealed.");
          return;
        }
        e2eKey = key;
        e2eError.hidden = true;
        btn.disabled = false;
      }).catch(() => blockReveal("The decryption key in this link is invalid. Nothing was revealed."));
    };
    if (!VaultE2E.available()) {
      blockReveal("This browser can't decrypt here: end-to-end encryption needs HTTPS or localhost. Nothing was revealed.");
    } else {
      loadKey();
      // Pasting the full link into a tab already showing this page only changes the #fragment (no reload).
      addEventListener("hashchange", () => { if (!btn.hidden) loadKey(); });
    }
  }

  btn.addEventListener("click", async () => {
    if (main.dataset.e2e && !e2eKey) return;
    if (pw) {
      pwError.hidden = true;
      if (!pw.value) { showPwError("Enter the password."); pw.focus(); return; }
    }
    if (!confirm("This will reveal the secret and permanently destroy it. Continue?")) return;
    btn.disabled = true;
    btn.textContent = "Revealing…";
    try {
      const opts = { method: "POST", cache: "no-store", credentials: "omit" };
      if (pw) {
        opts.headers = { "Content-Type": "application/json" };
        opts.body = JSON.stringify({ password: pw.value });
      }
      const r = await fetch(`/api/secret/${encodeURIComponent(id)}/burn`, opts);
      const data = await r.json().catch(() => ({}));
      if (r.status === 401) {  // wrong/missing password: nothing was consumed, let them retry
        btn.disabled = false;
        btn.textContent = "Reveal and Destroy Secret";
        showPwError(data.error || "Incorrect password.");
        pw?.select();
        return;
      }
      if (pw) { pw.value = ""; pw.hidden = true; pw.labels.forEach((l) => { l.hidden = true; }); }
      if (r.ok) {
        let text = data.secret;
        let decryptFailed = false;
        if (data.e2e) {
          try {
            text = await VaultE2E.decrypt(e2eKey, data.secret);
          } catch {
            decryptFailed = true;
          }
          history.replaceState(null, "", location.pathname + location.search);  // drop the key from the URL bar
        }
        document.getElementById("views").textContent = data.views_remaining;
        if (decryptFailed) {
          out.hidden = true;
          copy.hidden = true;
          status.textContent = "Could not decrypt: the key in this link doesn't match. " +
            (data.burned ? "The secret has been destroyed." : `${data.views_remaining} view(s) remaining.`);
        } else {
          out.textContent = text; // never innerHTML
          out.hidden = false;
          copy.hidden = false;
          status.textContent = data.burned
            ? "This secret has been destroyed. It cannot be viewed again."
            : `${data.views_remaining} view(s) remaining.`;
          showFingerprint(text).catch(() => {});
        }
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

  addEventListener("pagehide", () => {
    out.textContent = "";
    fpOut.textContent = "";
    if (pw) pw.value = "";
  });
})();
