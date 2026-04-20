from fastapi import FastAPI, Header, HTTPException, Body
from typing import Optional, Any
import time
import random

app = FastAPI()

TOKEN = "test-token"

DEFAULT_PAGE_SIZE = 500
DEFAULT_TOTAL = 1_000_000
ALLOWED_SUBCATEGORIES = ["Communication", "Process"]

DEVICE_FIELDS = [
    "uid", "asset_id", "device_name", "local_name", "device_category",
    "device_subcategory", "device_type", "device_type_family", "manufacturer",
    "model", "site_name", "network_scope_list", "organization_zone_name",
    "recommended_zone_name", "edge_locations", "mac_list", "ip_list",
    "switch_name_list", "switch_port_list", "labels", "purdue_level",
    "risk_score", "os_name", "combined_os", "os_version", "detector_name",
    "endpoint_security_names", "edr_endpoint_status", "edr_is_up_to_date_text",
    "infected", "suspicious", "first_seen_list", "last_seen_list",
    "last_seen_reported", "visibility_score", "visibility_score_level",
    "data_sources_seen_reported_from", "integration_types_reported_from",
    "integrations_reported_from", "ot_criticality", "criticality",
    "equipment_class"
]


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
    octet2 = (i // 65025) % 255
    octet3 = (i // 255) % 255
    octet4 = i % 255
    return f"10.{octet2}.{octet3}.{octet4}"


def make_ipv6(i: int) -> str:
    return f"2001:db8::{i:x}"


def make_mac(i: int) -> str:
    return f"AA:BB:CC:{(i >> 16) & 255:02X}:{(i >> 8) & 255:02X}:{i & 255:02X}"


def criticality_from_risk(risk_score: int) -> str:
    if risk_score >= 90:
        return "Critical"
    if risk_score >= 70:
        return "High"
    if risk_score >= 40:
        return "Medium"
    return "Low"


def visibility_level(score: int) -> str:
    if score >= 75:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def maybe_null(value: Any, i: int, every: int) -> Any:
    return None if i % every == 0 else value


def make_device(i: int, tenant: str, requested_subcategories: list[str]) -> dict[str, Any]:
    now = int(time.time())
    subcategory = pick_subcategory(requested_subcategories, i)

    if subcategory == "Process":
        category = "OT"
    else:
        category = random.choice(["IT", "OT"])

    risk_score = random.choice([8, 15, 22, 35, 48, 63, 72, 81, 91, 100])
    crit = criticality_from_risk(risk_score)
    visibility_score = random.randint(1, 100)
    visibility_score_level = visibility_level(visibility_score)

    infected = random.random() < 0.05
    suspicious = (not infected) and (random.random() < 0.10)

    first_seen = now - random.randint(86400, 86400 * 30)
    last_seen = now - random.randint(0, 3600)

    os_name = random.choice(["Windows", "Linux", "VxWorks", "RTOS"])
    os_version = f"{random.randint(1, 11)}.{random.randint(0, 9)}"
    combined_os = f"{os_name} {os_version}"

    manufacturer = random.choice(["Siemens", "Schneider", "ABB", "Honeywell", "Rockwell"])
    device_type = random.choice(["Controller", "Sensor", "PLC", "HMI", "RTU"])
    equipment_class = random.choice(["PLC", "HMI", "RTU", "SCADA"])
    purdue_level = random.choice([1.0, 2.0, 2.5, 3.0, 4.0, None])

    device = {
        "uid": f"{tenant}-uid-{i}",
        "asset_id": f"{tenant}-asset-{i}",
        "device_name": f"device-{i}",
        "local_name": maybe_null(f"local-device-{i}", i, 17),
        "device_category": category,
        "device_subcategory": subcategory,
        "device_type": device_type,
        "device_type_family": random.choice(["Industrial", "Automation", "Field"]),
        "manufacturer": manufacturer,
        "model": f"Model-{i % 20}",
        "site_name": f"Site-{(i % 10) + 1}",
        "network_scope_list": [f"scope-{i % 5}", f"scope-{(i + 1) % 5}"],
        "organization_zone_name": f"Org-Zone-{i % 6}",
        "recommended_zone_name": maybe_null(f"Rec-Zone-{i % 6}", i, 13),
        "edge_locations": [f"Edge-{i % 3}"],
        "mac_list": [make_mac(i), make_mac(i + 1)],
        "ip_list": [make_ipv4(i), make_ipv6(i)],
        "switch_name_list": [f"switch-{i % 15}"],
        "switch_port_list": [f"Gi1/0/{(i % 48) + 1}"],
        "labels": [
            f"label-{i % 4}",
            f"env-{'prod' if i % 2 == 0 else 'dev'}",
            f"region-{(i % 3) + 1}"
        ],
        "purdue_level": purdue_level,
        "risk_score": risk_score,
        "os_name": os_name,
        "combined_os": combined_os,
        "os_version": os_version,
        "detector_name": f"detector-{i % 8}",
        "endpoint_security_names": [f"security-{i % 3}"],
        "edr_endpoint_status": random.choice(["enabled", "disabled", "partial"]),
        "edr_is_up_to_date_text": random.choice(["up_to_date", "outdated"]),
        "infected": infected,
        "suspicious": suspicious,
        "first_seen_list": [first_seen],
        "last_seen_list": [last_seen],
        "last_seen_reported": last_seen,
        "visibility_score": visibility_score,
        "visibility_score_level": visibility_score_level,
        "data_sources_seen_reported_from": [f"source-{i % 4}"],
        "integration_types_reported_from": [f"integration-type-{i % 3}"],
        "integrations_reported_from": [f"integration-{i % 5}"],
        "ot_criticality": crit,
        "criticality": crit,
        "equipment_class": equipment_class
    }

    return device


def extract_requested_subcategories(payload: dict[str, Any]) -> list[str]:
    try:
        operands = payload.get("filter_by", {}).get("operands", [])
        for operand in operands:
            if (
                operand.get("field") == "device_subcategory"
                and operand.get("operation") == "in"
            ):
                value = operand.get("value", [])
                if isinstance(value, list):
                    return [str(v) for v in value]
    except Exception:
        pass
    return ALLOWED_SUBCATEGORIES


def project_device(device: dict[str, Any], requested_fields: list[str]) -> dict[str, Any]:
    if not requested_fields:
        return device
    return {field: device.get(field) for field in requested_fields}


@app.post("/api/devices")
def get_devices(
    payload: dict[str, Any] = Body(...),
    authorization: Optional[str] = Header(None)
):
    check_auth(authorization)

    offset = max(int(payload.get("offset", 0)), 0)
    limit = int(payload.get("limit", DEFAULT_PAGE_SIZE))
    limit = max(1, min(limit, 5000))

    include_count = bool(payload.get("include_count", False))

    total = int(payload.get("total", DEFAULT_TOTAL))
    total = max(1, min(total, 5_000_000))

    tenant = str(payload.get("tenant", "tenant-a"))
    delay_ms = int(payload.get("delay_ms", 0))
    delay_ms = max(0, min(delay_ms, 10_000))

    if delay_ms:
        time.sleep(delay_ms / 1000.0)

    requested_subcategories = extract_requested_subcategories(payload)
    requested_fields = payload.get("fields", DEVICE_FIELDS)
    if not isinstance(requested_fields, list) or not requested_fields:
        requested_fields = DEVICE_FIELDS

    start = offset
    end = min(start + limit, total)

    if start >= total:
        response = {"devices": []}
        if include_count:
            response["count"] = total
        return response

    devices = []
    for i in range(start, end):
        device = make_device(i, tenant, requested_subcategories)
        devices.append(project_device(device, requested_fields))

    response = {"devices": devices}
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

    page = max(page, 1)
    page_size = max(1, min(page_size, 5000))
    total = max(1, min(total, 5_000_000))
    delay_ms = max(0, min(delay_ms, 10_000))

    if delay_ms:
        time.sleep(delay_ms / 1000.0)

    start = (page - 1) * page_size
    end = min(start + page_size, total)

    items = []
    for i in range(start, end):
        items.append({
            "id": f"{tenant}-finding-{i}",
            "device_id": f"{tenant}-uid-{i % 100000}",
            "severity": random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
            "title": f"Mock finding {i}",
            "status": "open" if i % 3 else "resolved",
            "updated_at": int(time.time()) - random.randint(0, 7200)
        })

    return {
        "items": items,
        "page": page,
        "page_size": page_size,
        "total": total,
        "has_more": end < total
    }
