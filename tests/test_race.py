"""Scenario C: 20 simultaneous burns of a 1-view secret against a REAL server.

TestClient would serialize requests and pass even with broken code, so this uses the live_server fixture.
Proves: (1) exactly one 200 with the plaintext, (2) exactly nineteen 404s, (3) the row is physically gone.
"""
import threading
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from tests.conftest import row_count

N = 20


def _create(base, secret, views):
    r = httpx.post(base + "/api/secret", json={"secret": secret, "ttl_seconds": 60, "max_views": views})
    assert r.status_code == 201
    return r.json()["id"]


def _storm(base, sid, n=N):
    barrier = threading.Barrier(n)

    def hit(_):
        with httpx.Client(timeout=30) as c:
            barrier.wait()  # release all requests at once
            return c.post(f"{base}/api/secret/{sid}/burn")

    with ThreadPoolExecutor(n) as ex:
        return list(ex.map(hit, range(n)))


@pytest.mark.parametrize("round_", range(10))  # races are probabilistic: repeat
def test_exactly_one_reader(live_server, round_):
    base, db = live_server["base"], live_server["db"]
    sid = _create(base, "race-me", 1)
    rs = _storm(base, sid)
    codes = [r.status_code for r in rs]
    assert codes.count(200) == 1, codes                                    # (1)
    assert codes.count(404) == N - 1, codes                                # (2)
    assert [r.json()["secret"] for r in rs if r.status_code == 200] == ["race-me"]
    assert row_count(db, sid) == 0                                         # (3) physically deleted


@pytest.mark.parametrize("views", [2, 3, 5])
def test_multi_view_never_over_delivers(live_server, views):
    base, db = live_server["base"], live_server["db"]
    sid = _create(base, "multi", views)
    rs = _storm(base, sid)
    codes = [r.status_code for r in rs]
    assert codes.count(200) == views and codes.count(404) == N - views, codes
    remaining = sorted(r.json()["views_remaining"] for r in rs if r.status_code == 200)
    assert remaining == list(range(views))  # each view handed out exactly once
    assert sum(r.json()["burned"] for r in rs if r.status_code == 200) == 1
    assert row_count(db, sid) == 0
