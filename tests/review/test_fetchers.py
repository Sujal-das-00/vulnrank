import io
import zipfile

import httpx
import pytest
import respx

from app.review import github
from app.review.netguard import Blocked, SafeFetcher, ip_is_public, validate_url


@pytest.mark.parametrize("ip,ok", [("93.184.216.34", True), ("8.8.8.8", True), ("127.0.0.1", False), ("10.0.0.5", False),
                                   ("192.168.1.1", False), ("169.254.169.254", False), ("::1", False), ("fd00::1", False),
                                   ("::ffff:127.0.0.1", False), ("100.64.0.1", False), ("0.0.0.0", False), ("224.0.0.1", False)])
def test_ip_is_public(ip, ok):
    assert ip_is_public(ip) is ok


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com", "http://127.0.0.1/", "http://169.254.169.254/latest",
                                 "http://localhost/", "https://user:pw@example.com/", "https://example.com:8443/", "http://[::1]/", "javascript:alert(1)"])
def test_validate_url_blocks(url):
    with pytest.raises(Blocked):
        validate_url(url)


def fake_resolver(mapping):
    async def r(host):
        if host not in mapping:
            raise OSError("nxdomain")
        return mapping[host]
    return r


@pytest.mark.asyncio
@respx.mock
async def test_fetch_ok_pins_ip_and_sets_host():
    route = respx.get("https://93.184.216.34/privacy").respond(200, text="<h1>Privacy</h1>", headers={"content-type": "text/html"})
    sf = SafeFetcher(httpx.AsyncClient(), resolver=fake_resolver({"example.com": ["93.184.216.34"]}))
    page = await sf.get("https://example.com/privacy")
    assert page.status == 200 and "Privacy" in page.text
    assert route.calls.last.request.headers["host"] == "example.com"


@pytest.mark.asyncio
async def test_host_resolving_to_private_blocked():
    sf = SafeFetcher(httpx.AsyncClient(), resolver=fake_resolver({"evil.example": ["10.0.0.7"], "mixed.example": ["93.184.216.34", "127.0.0.1"]}))
    for h in ("evil.example", "mixed.example"):
        with pytest.raises(Blocked, match="non-public"):
            await sf.get(f"https://{h}/")


@pytest.mark.asyncio
@respx.mock
async def test_redirect_into_private_space_blocked():
    respx.get("https://93.184.216.34/").respond(302, headers={"location": "http://internal.example/admin"})
    sf = SafeFetcher(httpx.AsyncClient(), resolver=fake_resolver({"example.com": ["93.184.216.34"], "internal.example": ["192.168.0.10"]}))
    with pytest.raises(Blocked, match="non-public"):
        await sf.get("https://example.com/")


@pytest.mark.asyncio
@respx.mock
async def test_redirect_loop_capped():
    respx.get("https://93.184.216.34/a").respond(302, headers={"location": "https://example.com/a"})
    sf = SafeFetcher(httpx.AsyncClient(), resolver=fake_resolver({"example.com": ["93.184.216.34"]}))
    with pytest.raises(Blocked, match="too many redirects"):
        await sf.get("https://example.com/a")


@pytest.mark.asyncio
@respx.mock
async def test_body_is_size_capped_and_binary_skipped():
    respx.get("https://93.184.216.34/big").respond(200, content=b"x" * 5000, headers={"content-type": "text/html"})
    respx.get("https://93.184.216.34/img").respond(200, content=b"\x89PNG", headers={"content-type": "image/png"})
    sf = SafeFetcher(httpx.AsyncClient(), resolver=fake_resolver({"example.com": ["93.184.216.34"]}), max_bytes=1000)
    big = await sf.get("https://example.com/big")
    assert big.truncated and len(big.text) == 1000
    assert (await sf.get("https://example.com/img")).text == ""


def make_zip(files: dict[str, bytes]) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in files.items():
            z.writestr(k, v)
    return b.getvalue()


def test_extract_zip_filters():
    data = make_zip({"r-abc/app.py": b"print(1)", "r-abc/node_modules/x/index.js": b"x", "r-abc/logo.png": b"\x89PNG\x00",
                     "r-abc/big.js": b"a" * (github.MAX_FILE_BYTES + 10), "r-abc/requirements.txt": b"flask==2.0.0\n", "r-abc/bin.dat": b"\x00\x01"})
    files, stats = github.extract_zip(data)
    assert set(files) == {"app.py", "requirements.txt"}
    assert stats["skipped_dirs"] == 1 and stats["skipped_large"] == 1 and stats["skipped_binary"] >= 1


def test_extract_zip_uncompressed_cap(monkeypatch):
    monkeypatch.setattr(github, "MAX_UNCOMPRESSED", 1000)
    data = make_zip({f"r/f{i}.py": b"a" * 400 for i in range(10)})
    files, stats = github.extract_zip(data)
    assert stats["truncated"] and len(files) <= 2


@pytest.mark.asyncio
@respx.mock
async def test_fetch_repo_404_and_ok():
    respx.get("https://codeload.github.com/o/missing/zip/HEAD").respond(404)
    respx.get("https://codeload.github.com/o/r/zip/HEAD").respond(200, content=make_zip({"r-1/a.py": b"x=1"}))
    async with httpx.AsyncClient() as c:
        with pytest.raises(github.RepoError, match="not found"):
            await github.fetch_repo(c, "o", "missing")
        snap = await github.fetch_repo(c, "o", "r")
    assert snap.files == {"a.py": "x=1"}
