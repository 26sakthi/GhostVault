import pytest

from app.security import is_bot

BOT_UAS = [
    "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
    "Slackbot 1.0 (+https://api.slack.com/robots)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Twitterbot/1.0",
    "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
    "WhatsApp/2.23.20.0",
    "TelegramBot (like TwitterBot)",
    "LinkedInBot/1.0 (compatible; Mozilla/5.0)",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; SomeCrawler/1.0)",
    "my-spider/0.1",
]
HUMAN_UAS = [
    "curl/8.5.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "python-httpx/0.28.1",
    "vault-cli/1.0",
]


@pytest.mark.parametrize("ua", BOT_UAS)
def test_bot_patterns_match(ua):
    assert is_bot(ua)


@pytest.mark.parametrize("ua", HUMAN_UAS + ["", None])
def test_human_patterns_do_not_match(ua):
    assert not is_bot(ua)


def _views(db, sid):
    return db.execute("SELECT views_remaining FROM secrets WHERE id = ?", (sid,)).fetchone()[0]


@pytest.mark.parametrize("ua", BOT_UAS)
def test_bot_cannot_consume(client, make_secret, db, ua):
    """Scenario B: the bot receives an HTML shell; the secret stays unburned."""
    sid = make_secret("bot-target")
    r = client.get(f"/view/{sid}", headers={"User-Agent": ua})
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert sid not in r.text and "Reveal" not in r.text  # generic shell, no metadata

    r = client.post(f"/api/secret/{sid}/burn", headers={"User-Agent": ua})
    assert r.status_code == 403 and r.json() == {"error": "Automated clients are not permitted."}
    assert _views(db, sid) == 1

    r = client.post(f"/api/secret/{sid}/burn")  # a human still gets it
    assert r.status_code == 200 and r.json()["secret"] == "bot-target"


def test_bot_cannot_create(client, db):
    before = db.execute("SELECT COUNT(*) FROM secrets").fetchone()[0]
    r = client.post("/api/secret", json={"secret": "x"}, headers={"User-Agent": BOT_UAS[0]})
    assert r.status_code == 403
    assert db.execute("SELECT COUNT(*) FROM secrets").fetchone()[0] == before


@pytest.mark.parametrize("path", ["/", "/health", "/static/css/app.css", "/nope"])
def test_bot_other_routes_blank_403(client, path):
    r = client.get(path, headers={"User-Agent": BOT_UAS[0]})
    assert r.status_code == 403 and r.content == b""


def test_view_page_is_read_only(client, make_secret, db):
    sid = make_secret("human-view", views=1)
    for _ in range(10):
        r = client.get(f"/view/{sid}")
        assert r.status_code == 200
        assert "You have been sent a secure, self-destructing secret." in r.text
        assert "Reveal and Destroy Secret" in r.text
        assert "human-view" not in r.text  # never decrypted on GET
    assert _views(db, sid) == 1
    assert client.post(f"/api/secret/{sid}/burn").json()["secret"] == "human-view"


def test_head_on_view_does_not_consume(client, make_secret, db):
    sid = make_secret()
    client.head(f"/view/{sid}")
    assert _views(db, sid) == 1


@pytest.mark.parametrize("ua", HUMAN_UAS)
def test_humans_not_blocked(client, make_secret, ua):
    sid = make_secret()
    assert client.get(f"/view/{sid}", headers={"User-Agent": ua}).status_code == 200


def test_security_headers_everywhere(client, make_secret):
    sid = make_secret()
    for r in [client.get("/"), client.get(f"/view/{sid}"), client.get("/view/0000000000000000"),
              client.post("/api/secret/0000000000000000/burn"),
              client.get(f"/view/{sid}", headers={"User-Agent": BOT_UAS[0]})]:
        assert "script-src 'self'" in r.headers["content-security-policy"]
        assert r.headers["cache-control"] == "no-store"
        assert r.headers["referrer-policy"] == "no-referrer"
        assert r.headers["x-frame-options"] == "DENY"
