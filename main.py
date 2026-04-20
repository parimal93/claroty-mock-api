from fastapi import FastAPI, Header, HTTPException, Body
from typing import Optional, Any
from datetime import datetime, timezone, timedelta
import time
import random
import uuid

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

PROCESS_DEVICE_TYPES = [
    ("Power Meter", "Power Meter"),
    ("Vision Sensor", "Vision Sensor"),
    ("Autonomous Vehicle", "Autonomous Vehicle"),
    ("PLC", "PLC"),
    ("RTU", "RTU"),
    ("HMI", "HMI"),
]

COMM_DEVICE_TYPES = [
    ("VoIP Phone", "VoIP Phone"),
    ("Wireless Access Point", "Wireless Access Point"),
    ("Managed Switch", "Managed Switch"),
    ("IP Camera", "IP Camera"),
    ("Printer", "Printer"),
]

MANUFACTURERS = [
    "Siemens", "Cisco", "Honeywell", "JBT Corporation",
    "Keyence", "Schneider Electric", "ABB", "Rockwell"
]

MODELS = [
    "CB4500", "CP-7861", "SICAM Q100", "CV-X400 Series",
    "Model-X1", "Model-A9", "Series-7", "Edge-200"
]

SITES = ["Albany", "Clinton", "ATL-06", "Dallas", "Phoenix", "Austin"]
ZONE_NAMES = ["No Zone", "Communication", "Process"]
LABELS = ["Tier-01", "Tier-02", "OT Assets without Assignees", "Critical Assets"]
DATA_SOURCES = ["Passive Collection"]
DETECTORS = ["Medemo", "SensorGrid", "NetCollector"]

RISK_LEVELS = ["Low", "Medium", "High", "Critical"]
PURDUE_LEVELS = ["Level 0", "Level 1", "Level 2", "Level 3", "Level 4"]


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
    octet2 = 10 + ((i // 65025) % 20)
    octet3 = 1 + ((i // 255) % 50)
    octet4 = 1 + (i % 254)
    return f"10.{octet2}.{octet3}.{octet4}"


def make_mac(i: int) -> str:
    return f"{(i >> 40) & 255:02x}:{(i >> 32) & 255:02x}:{(i >> 24) & 255:02x}:{(i >> 16) & 255:02x}:{(i >> 8) & 255:02x}:{i & 255:02x}"


def iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def maybe_null(value: Any, chance: float) -> Any:
    return None if random.random() < chance else value


def choose_risk_score(subcategory: str) -> str:
    if subcategory == "Process":
        return random.choices(
            RISK_LEVELS,
            weights=[10, 20, 35, 35],
            k=1
        )[0]
    return random.choices(
        RISK_LEVELS,
        weights=[20, 30, 35, 15],
        k=1
    )[0]


def ot_criticality_from_risk(risk_score: str, subcategory: str) -> Optional[str]:
    if subcategory != "Process":
        return None if random.random() < 0.8 else risk_score
    return risk_score


def visibility_level(score: int) -> str:
    if score >= 95:
        return "Excellent"
    if score >= 80:
        return "Good"
    if score >= 60:
        return "Fair"
    return "Poor"


def choose_device_profile(subcategory: str) -> tuple[str, str]:
    if subcategory == "Process":
        return random.choice(PROCESS_DEVICE_TYPES)
    return random.choice(COMM_DEVICE_TYPES)


def choose_device_category(subcategory: str) -> str:
    if subcategory == "Process":
        return "OT"
    return random.choices(["IoT", "OT"], weights=[75, 25], k=1)[0]


def choose_os_fields(subcategory: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    if subcategory == "Process":
        if random.random() < 0.75:
            return None, None, None
        os_name = random.choice(["Proprietary", "Embedded Linux", "RTOS"])
    else:
        if random.random() < 0.45:
            return None, None, None
        os_name = random.choice(["Proprietary", "Embedded Linux", "Linux"])

    if os_name == "Proprietary":
        return os_name, None, os_name

    os_version = f"{random.randint(1, 10)}.{random.randint(0, 9)}"
    return os_name, os_version, f"{os_name} {os_version}"


def choose_purdue_level(subcategory: str) -> str:
    if subcategory == "Process":
        return random.choices(
            PURDUE_LEVELS,
            weights=[55, 20, 10, 10, 5],
            k=1
        )[0]
    return random.choices(
        PURDUE_LEVELS,
        weights=[5, 5, 10, 20, 60],
        k=1
    )[0]


def choose_switch_port() -> list[Optional[str]]:
    if random.random() < 0.25:
        return [None]
    prefix = random.choice(["Fa", "Gi"])
    return [f"{prefix}/{random.randint(0, 1)}/{random.randint(1, 48)}"]


def choose_switch_name() -> list[Optional[str]]:
    if random.random() < 0.65:
        return [None]
    return [f"switch-{random.randint(1, 50)}"]


def choose_labels(subcategory: str) -> list[str]:
    if subcategory == "Process":
        return [random.choice(["Tier-01", "Critical Assets", "OT Assets without Assignees"])]
    return [random.choice(["Tier-01", "Tier-02", "Communication Assets"])]


def choose_detector() -> str:
    return random.choice(DETECTORS)


def make_device(i: int, tenant: str, requested_subcategories: list[str]) -> dict[str, Any]:
    subcategory = pick_subcategory(requested_subcategories, i)
    device_type, device_type_family = choose_device_profile(subcategory)
    category = choose_device_category(subcategory)

    now = datetime.now(timezone.utc)
    first_seen_dt = now - timedelta(days=random.randint(1, 300), hours=random.randint(0, 23), minutes=random.randint(0, 59))
    last_seen_dt = now - timedelta(minutes=random.randint(0, 60 * 24))
    if last_seen_dt < first_seen_dt:
        last_seen_dt = first_seen_dt + timedelta(minutes=random.randint(1, 120))

    first_seen = iso_utc(first_seen_dt)
    last_seen = iso_utc(last_seen_dt)

    ip = make_ipv4(i)
    uid = str(uuid.uuid4())
    asset_id = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=7))

    risk_score = choose_risk_score(subcategory)
    ot_criticality = ot_criticality_from_risk(risk_score, subcategory)
    criticality = risk_score

    visibility_score = random.randint(70, 100) if subcategory == "Process" else random.randint(60, 100)
    visibility_score_level = visibility_level(visibility_score)

    os_name, os_version, combined_os = choose_os_fields(subcategory)
    purdue_level = choose_purdue_level(subcategory)

    manufacturer = random.choice(MANUFACTURERS)
    model = random.choice(MODELS)

    device_name = ip if random.random() < 0.8 else f"{device_type.lower().replace(' ', '-')}-{i}"

    device = {
        "uid": uid,
        "asset_id": asset_id,
        "device_name": device_name,
        "local_name": None if random.random() < 0.9 else f"local-{i}",
        "device_category": category,
        "device_subcategory": subcategory,
        "device_type": device_type,
        "device_type_family": device_type_family,
        "manufacturer": manufacturer,
        "model": model,
        "site_name": random.choice(SITES),
        "network_scope_list": ["Default"],
        "organization_zone_name": random.choice(["No Zone", "No Zone", "No Zone", subcategory]),
        "recommended_zone_name": random.choice(["No Zone", subcategory]),
        "edge_locations": [],
        "mac_list": [make_mac(i)],
        "ip_list": [ip],
        "switch_name_list": choose_switch_name(),
        "switch_port_list": choose_switch_port(),
        "labels": choose_labels(subcategory),
        "purdue_level": purdue_level,
        "risk_score": risk_score,
        "os_name": os_name,
        "combined_os": combined_os,
        "os_version": os_version,
        "detector_name": choose_detector(),
        "endpoint_security_names": [] if random.random() < 0.85 else [f"security-{i % 5}"],
        "edr_endpoint_status": None if random.random() < 0.9 else random.choice(["enabled", "disabled", "partial"]),
        "edr_is_up_to_date_text": None if random.random() < 0.9 else random.choice(["up_to_date", "outdated"]),
        "infected": None if random.random() < 0.98 else False,
        "suspicious": [],
        "first_seen_list": [first_seen],
        "last_seen_list": [last_seen],
        "last_seen_reported": last_seen,
        "visibility_score": visibility_score,
        "visibility_score_level": visibility_score_level,
        "data_sources_seen_reported_from": DATA_SOURCES,
        "integration_types_reported_from": [],
        "integrations_reported_from": [],
        "ot_criticality": ot_criticality,
        "criticality": criticality,
        "equipment_class": None if random.random() < 0.9 else random.choice(["PLC", "RTU", "HMI"])
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


@app.post("/api/v1/devices")
def get_devices(
    payload: dict[str, Any] = Body(...),
    authorization: Optional[str] = Header(None)
):
    check_auth(authorization)

    offset = max(int(payload.get("offset", 0)), 0)
    limit = max(1, min(int(payload.get("limit", DEFAULT_PAGE_SIZE)), 5000))
    include_count = bool(payload.get("include_count", False))

    total = max(1, min(int(payload.get("total", DEFAULT_TOTAL)), 5_000_000))
    tenant = str(payload.get("tenant", "tenant-a"))
    delay_ms = max(0, min(int(payload.get("delay_ms", 0)), 10_000))

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
            "device_id": str(uuid.uuid4()),
            "severity": random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
            "title": f"Mock finding {i}",
            "status": "open" if i % 3 else "resolved",
            "updated_at": iso_utc(datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 7200)))
        })

    return {
        "items": items,
        "page": page,
        "page_size": page_size,
        "total": total,
        "has_more": end < total
    }
