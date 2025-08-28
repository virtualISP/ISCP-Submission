#!/usr/bin/env python3

import sys
import re
import json
import pandas as pd
from typing import Dict, Tuple, Any

RE_PHONE_STRICT = re.compile(r'(?<!\d)(?:\+?91[-\s]?)?([6-9]\d{9})(?!\d)')
RE_AADHAR = re.compile(r'(?<!\d)(\d{4})[\s-]?(\d{4})[\s-]?(\d{4})(?!\d)')
RE_PASSPORT_IN = re.compile(r'(?<![A-Za-z0-9])([A-PR-WYa-pr-wy])[ ]?(\d{7})(?![A-Za-z0-9])')
RE_UPI = re.compile(r'([a-zA-Z0-9.\-_]{2,})@([a-zA-Z]{2,})')
RE_EMAIL = re.compile(r'([a-zA-Z0-9._%+\-]{2,})@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})')
RE_IP = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')
RE_NAME_TWO_PARTS = re.compile(r'^[A-Za-z]{2,}[ ,]+[A-Za-z]{2,}$')
RE_PINCODE = re.compile(r'(?<!\d)(\d{6})(?!\d)')

PHONE_LIKE_KEYS = {"phone", "contact", "mobile", "alt_phone", "phone_number"}
ADDRESS_KEYS = {"address", "shipping_address", "billing_address"}
NAME_KEYS = {"name", "full_name"}

SAFE_NUMERIC_ID_KEYS = {
    "order_id", "transaction_id", "product_id", "ticket_id", "warehouse_code", "customer_id",
    "gst_number", "state_code", "booking_reference"
}

def mask_phone(val: str) -> str:
    m = RE_PHONE_STRICT.search(val)
    if not m:
        return val
    num = m.group(1)
    masked = num[:2] + "XXXXXX" + num[-2:]
    return RE_PHONE_STRICT.sub(masked, val)

def mask_aadhar(val: str) -> str:
    return RE_AADHAR.sub(lambda m: "XXXX-XXXX-XXXX", val)

def mask_passport(val: str) -> str:
    return RE_PASSPORT_IN.sub(lambda m: m.group(1).upper() + "XXXXXX" + m.group(2)[-1], val)

def mask_upi(val: str) -> str:
    return RE_UPI.sub(lambda m: m.group(1)[:2] + "*" * max(1, len(m.group(1)) - 3) + m.group(1)[-1:] + "@" + m.group(2), val)

def mask_email(val: str) -> str:
    return RE_EMAIL.sub(lambda m: m.group(1)[:2] + "*" * max(1, len(m.group(1)) - 2) + "@" + m.group(2), val)

def mask_ip(val: str) -> str:
    return RE_IP.sub(lambda m: ".".join(m.group(1).split(".")[:2]) + ".*.*", val)

def mask_name_like(val: str) -> str:
    parts = re.split(r'\s+', val.strip())
    return " ".join(p[0].upper() + "XXX" for p in parts if p)

def is_phone_value(key: str, val: Any) -> bool:
    if not isinstance(val, str):
        val = str(val)
    if key in SAFE_NUMERIC_ID_KEYS:
        return False
    if key.lower() in PHONE_LIKE_KEYS and RE_PHONE_STRICT.search(val):
        return True
    val_stripped = re.sub(r'\D', '', val)
    return len(val_stripped) == 10 and RE_PHONE_STRICT.search(val) is not None

def contains_aadhar(val: Any) -> bool:
    return isinstance(val, str) and RE_AADHAR.search(val) is not None

def contains_passport(val: Any) -> bool:
    return isinstance(val, str) and RE_PASSPORT_IN.search(val) is not None

def contains_upi(val: Any) -> bool:
    return isinstance(val, str) and RE_UPI.search(val) is not None

def contains_email(val: Any) -> bool:
    return isinstance(val, str) and RE_EMAIL.search(val) is not None

def looks_like_full_name(val: Any) -> bool:
    return isinstance(val, str) and RE_NAME_TWO_PARTS.match(val.strip()) is not None

def contains_ip(val: Any) -> bool:
    if not isinstance(val, str):
        return False
    m = RE_IP.search(val)
    if not m:
        return False
    parts = m.group(1).split(".")
    for p in parts:
        try:
            n = int(p)
            if n < 0 or n > 255:
                return False
        except:
            return False
    return True

def contains_address(val: Any) -> bool:
    if not isinstance(val, str):
        return False
    if not RE_PINCODE.search(val):
        return False
    street_tokens = ["street", "st.", "road", "rd.", "lane", "block", "sector", "apt", "apartment", "floor", "phase"]
    has_street = any(t in val.lower() for t in street_tokens)
    has_number = re.search(r'\d+', val) is not None
    return has_street and has_number

def detect_and_redact(record: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    standalone_found = False
    combo_signals = set()
    red = dict(record)

    for key, val in record.items():
        lowkey = str(key).lower()
        sval = val if isinstance(val, str) else (json.dumps(val) if isinstance(val, (dict, list)) else str(val))

        if is_phone_value(lowkey, sval):
            standalone_found = True
            red[key] = mask_phone(sval)
            continue
        if contains_aadhar(sval):
            standalone_found = True
            red[key] = mask_aadhar(sval)
            continue
        if contains_passport(sval):
            standalone_found = True
            red[key] = mask_passport(sval)
            continue
        if contains_upi(sval):
            standalone_found = True
            red[key] = mask_upi(sval)
            continue

        if (lowkey in NAME_KEYS and looks_like_full_name(sval)) or (lowkey in {"first_name", "last_name"} and isinstance(sval, str) and len(sval.strip()) >= 2):
            combo_signals.add("name")
        if contains_email(sval):
            combo_signals.add("email")
        if lowkey in ADDRESS_KEYS and contains_address(sval):
            combo_signals.add("address")
        if lowkey in {"device_id"} and isinstance(sval, str) and len(sval.strip()) >= 6:
            combo_signals.add("device")
        if lowkey in {"ip_address"} and contains_ip(sval):
            combo_signals.add("ip")

    combo_score = len(combo_signals)
    if combo_score >= 2:
        if (("device" in combo_signals or "ip" in combo_signals) and not (("name" in combo_signals) or ("email" in combo_signals) or ("address" in combo_signals))):
            is_pii = standalone_found
        else:
            is_pii = True
    else:
        is_pii = standalone_found

    if is_pii and combo_score > 0:
        for key, val in record.items():
            lowkey = str(key).lower()
            sval = val if isinstance(val, str) else str(val)

            if (lowkey in NAME_KEYS and looks_like_full_name(sval)):
                red[key] = mask_name_like(sval)
            elif lowkey == "first_name" and isinstance(sval, str):
                red[key] = (sval[0].upper() + "XXX") if sval else sval
            elif lowkey == "last_name" and isinstance(sval, str):
                red[key] = (sval[0].upper() + "XXX") if sval else sval
            elif contains_email(sval):
                red[key] = mask_email(sval)
            elif lowkey in ADDRESS_KEYS and contains_address(sval):
                red[key] = "[REDACTED_ADDRESS]"
            elif lowkey == "ip_address" and contains_ip(sval):
                red[key] = mask_ip(sval)
            elif lowkey == "device_id" and isinstance(sval, str) and len(sval.strip()) >= 6:
                red[key] = "[REDACTED_DEVICE_ID]"

    if is_pii:
        for key, val in list(red.items()):
            if not isinstance(val, str):
                continue
            v = val
            v = mask_phone(v)
            v = mask_aadhar(v)
            v = mask_passport(v)
            v = mask_upi(v)
            v = mask_email(v)
            v = mask_ip(v)
            red[key] = v

    return is_pii, red

def process_csv(in_path: str, out_path: str):
    df = pd.read_csv(in_path)
    cols = {c.lower(): c for c in df.columns}
    if "record_id" not in cols or ("data_json" not in cols and "data" not in cols):
        raise ValueError("Input CSV must have columns: record_id, data_json")
    rid_col = cols["record_id"]
    data_col = cols.get("data_json", cols.get("data"))

    out_rows = []
    for _, row in df.iterrows():
        rid = row[rid_col]
        raw = row[data_col]
        try:
            data = json.loads(raw)
        except Exception:
            try:
                fixed = raw.replace("'", '"')
                data = json.loads(fixed)
            except Exception:
                data = {"__raw__": str(raw)}

        is_pii, red = detect_and_redact(data)
        out_rows.append({
            "record_id": rid,
            "redacted_data_json": json.dumps(red, ensure_ascii=False),
            "is_pii": bool(is_pii)
        })

    out_df = pd.DataFrame(out_rows, columns=["record_id", "redacted_data_json", "is_pii"])
    out_df.to_csv(out_path, index=False)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detector_virtualISP.py iscp_pii_dataset.csv")
        sys.exit(1)
    in_csv = sys.argv[1]
    out_csv = "redacted_virtualISP.csv"
    process_csv(in_csv, out_csv)
    print(f"Wrote: {out_csv}")

if __name__ == "__main__":
    main()
