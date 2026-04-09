from fastapi import FastAPI, Header, HTTPException, Query
from typing import Optional
import time
import hashlib

app = FastAPI()

TOKEN = "test-token"

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/api/authenticate")
def authenticate():
    return {
        "access_token": TOKEN,
        "token_type": "Bearer",
        "expires_in": 300
    }

def check_auth(authorization: Optional[str]):
    if authorization != f"Bearer {TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")

def make_device(i: int, tenant: str):
    return {
        "id": f"{tenant}-device-{i}",
        "name": f"device-{i}",
        "ip": f"10.{(i // 65025) % 255}.{(i // 255) % 255}.{i % 255}",
        "mac": f"AA:BB:CC:{(i>>16)&255:02X}:{(i>>8)&255:02X}:{i&255:02X}",
        "site": "Mock Site",
        "type": "OT_DEVICE",
        "vendor": "MockVendor",
        "model": f"Model-{i % 20}",
        "last_seen": int(time.time()) - (i % 3600)
    }

@app.get("/api/devices")
def get_devices(
    page: int = Query(1, ge=1),
    page_size: int = Query(1000, ge=1, le=5000),
    total: int = Query(1000000, ge=1, le=5000000),
    tenant: str = Query("tenant-a"),
    delay_ms: int = Query(0, ge=0, le=10000),
    authorization: Optional[str] = Header(None)
):
    check_auth(authorization)

    if delay_ms:
        time.sleep(delay_ms / 1000)

    start = (page - 1) * page_size
    end = min(start + page_size, total)

    if start >= total:
        return {
            "items": [],
            "page": page,
            "page_size": page_size,
            "total": total,
            "has_more": False
        }

    items = [make_device(i, tenant) for i in range(start, end)]

    return {
        "items": items,
        "page": page,
        "page_size": page_size,
        "total": total,
        "has_more": end < total
    }

@app.get("/api/findings")
def get_findings(
    page: int = Query(1, ge=1),
    page_size: int = Query(1000, ge=1, le=5000),
    total: int = Query(500000, ge=1, le=5000000),
    tenant: str = Query("tenant-a"),
    delay_ms: int = Query(0, ge=0, le=10000),
    authorization: Optional[str] = Header(None)
):
    check_auth(authorization)

    if delay_ms:
        time.sleep(delay_ms / 1000)

    start = (page - 1) * page_size
    end = min(start + page_size, total)

    items = []
    for i in range(start, end):
        items.append({
            "id": f"{tenant}-finding-{i}",
            "device_id": f"{tenant}-device-{i % 100000}",
            "severity": ["LOW", "MEDIUM", "HIGH", "CRITICAL"][i % 4],
            "title": f"Mock finding {i}",
            "status": "open" if i % 3 else "resolved",
            "updated_at": int(time.time()) - (i % 7200)
        })

    return {
        "items": items,
        "page": page,
        "page_size": page_size,
        "total": total,
        "has_more": end < total
    }