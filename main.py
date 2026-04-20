from fastapi import FastAPI, Header, HTTPException, Body
from typing import Optional, Any
import time
import random

app = FastAPI()

TOKEN = "test-token"

DEFAULT_PAGE_SIZE = 500
ALLOWED_SUBCATEGORIES = ["Communication", "Process"]


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


def pick_subcategory(requested_subcategories: list[str], i: int) -> str:
    valid = [x for x in requested_subcategories if x in ALLOWED_SUBCATEGORIES]
    if not valid:
        valid = ALLOWED_SUBCATEGORIES
    return valid[i % len(valid)]


def make_ipv4(i: int) -> str:
    return f"10.{(i // 65025) % 255}.{(i // 255) % 255}.{i % 255}"


def make_ipv6(i: int) -> str:
    return f"2001:db8::{i:x}"


def make_mac(i: int) -> str:
    return f"AA:BB:CC:{(i >> 16) & 255:02X}:{(i >> 8) & 255:02X}:{i & 255:02X}"


def make_timestamp(epoch_now: int, offset_seconds: int) -> int:
    return epoch_now - offset_seconds


def make_device(i: int, tenant: str, requested_subcategories: list[str]) -> dict[str, Any]:
    now = int(time.time())
    subcategory = pick_subcategory(requested_subcategories, i)
    category = "OT" if i % 2 == 0 else "IT"
    risk_score = (i % 100) + 1
    visibility_score = (i % 100) + 1
    first_seen = make_timestamp(now, 86400 + (i % 50000))
    last_seen = make_timestamp(now, i % 3600)

    return {
        "uid": f"{tenant}-uid-{i}",
        "asset_id": f"{tenant}-asset-{i}",
        "device_name": f"device-{i}",
        "local_name": f"local-device-{i}",
        "device_category": category,
        "device_subcategory": subcategory,
        "device_type": "Controller" if i % 2 == 0 else "Sensor",
        "device_type_family": "Industrial",
        "manufacturer": ["Siemens", "Schneider", "ABB", "Honeywell"][i % 4],
        "model": f"Model-{i % 20}",
        "site_name": f"Site-{(i % 10) + 1}",
        "network_scope_list": [f"scope-{i % 5}", f"scope-{(i + 1) % 5}"],
        "organization_zone_name": f"Org-Zone-{i % 6}",
        "recommended_zone_name": f"Rec-Zone-{i % 6}",
        "edge_locations": [f"Edge-{i % 3}"],
        "mac_list": [make_mac(i), make_mac(i + 1)],
        "ip_list": [make_ipv4(i), make_ipv6(i)],
        "switch_name_list": [f"switch-{i % 15}"],
        "switch_port_list": [f"Gi1/0/{(i % 48) + 1}"],
        "labels": [f"label-{i % 4}", f"env-{'prod' if i % 2 == 0 else 'dev'}"],
        "purdue_level": float((i % 5) + 1),
        "risk_score": risk_score,
        "os_name": ["Windows", "Linux", "VxWorks", "RTOS"][i % 4],
        "combined_os": f"{['Windows', 'Linux', 'VxWorks', 'RTOS'][i % 4]} {(i % 11) + 1}",
        "os_version": f"{(i % 11) + 1}.{i % 10}",
        "detector_name": f"detector-{i % 8}",
        "endpoint_security_names": [f"security-{i % 3}"],
        "edr_endpoint_status": ["enabled", "disabled", "partial"][i % 3],
        "edr_is_up_to_date_text": ["up_to_date", "outdated"][i % 2],
        "infected": i % 17 == 0,
        "suspicious": i % 11 == 0,
        "first_seen_list": [first_seen],
        "last_seen_list": [last_seen],
        "last_seen_reported": last_seen,
        "visibility_score": visibility_score,
        "visibility_score_level": ["LOW", "MEDIUM", "HIGH"][i % 3],
        "data_sources_seen_reported_from": [f"source-{i % 4}"],
        "integration_types_reported_from": [f"integration-type-{i % 3}"],
        "integrations_reported_from": [f"integration-{i % 5}"],
        "ot_criticality": ["Low", "Medium", "High", "Critical"][i % 4],
        "criticality": ["Low", "Medium", "High", "Critical"][i % 4],
        "equipment_class": ["PLC", "HMI", "RTU", "SCADA"][i % 4]
    }


def extract_requested_subcategories(payload: dict[str, Any]) -> list[str]:
    try:
        operands = payload.get("filter_by", {}).get("operands", [])
        for operand in operands:
            if operand.get("field") == "device_subcategory" and operand.get("operation") == "in":
                value = operand.get("value", [])
                if isinstance(value, list):
                    return [str(v) for v in value]
    except Exception:
        pass
    return ALLOWED_SUBCATEGORIES


@app.post("/api/devices")
def get_devices(
    payload: dict[str, Any] = Body(...),
    authorization: Optional[str] = Header(None)
):
    check_auth(authorization)

    offset = int(payload.get("offset", 0))
    limit = int(payload.get("limit", DEFAULT_PAGE_SIZE))
    include_count = bool(payload.get("include_count", False))

    # Optional test knobs you can pass in body for load testing
    total = int(payload.get("total", 1000000))
    tenant = str(payload.get("tenant", "tenant-a"))
    delay_ms = int(payload.get("delay_ms", 0))

    if delay_ms > 0:
        time.sleep(delay_ms / 1000)

    requested_subcategories = extract_requested_subcategories(payload)

    start = max(offset, 0)
    end = min(start + limit, total)

    if start >= total:
        response = {"devices": []}
        if include_count:
            response["count"] = total
        return response

    devices = [make_device(i, tenant, requested_subcategories) for i in range(start, end)]

    response = {
        "devices": devices
    }

    if include_count:
        response["count"] = total

    return response


@app.get("/api/findings")
def get_findings(
    page: int = 1,
    page_size: int = 1000,
    total: int = 500000,
    tenant: str = "tenant-a",
    delay_ms: int = 0,
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
            "device_id": f"{tenant}-uid-{i % 100000}",
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
