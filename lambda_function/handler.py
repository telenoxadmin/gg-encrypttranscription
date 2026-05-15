"""
Hotel PII Redaction Lambda  —  Production
==========================================
Triggered by S3 ObjectCreated events.

Cold start fix:
  - Models load lazily on first invocation (not at module import time)
  - Lambda timeout set to 600s in Terraform to cover cold start + processing
  - Provisioned concurrency (optional) eliminates cold starts entirely
  - Memory set to 5120 MB in Terraform (required for spaCy lg + names-dataset)
"""

import os
import json
import time
import hashlib
import logging
import boto3
import psycopg2
from urllib.parse import unquote_plus
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")

# ── Env vars validated at cold start ─────────────────────────────────────────
def _require_env(key):
    val = os.environ.get(key, "").strip()
    if not val:
        raise RuntimeError(f"Required env var '{key}' is not set.")
    return val

OUTPUT_BUCKET    = _require_env("OUTPUT_BUCKET")
TOKEN_MAP_BUCKET = _require_env("TOKEN_MAP_BUCKET")
MODE             = os.environ.get("MODE", "redact")
CONFIDENCE       = float(os.environ.get("CONFIDENCE_THRESHOLD", "0.6"))
MAX_FILE_BYTES   = int(os.environ.get("MAX_FILE_MB", "50")) * 1024 * 1024

# Postgres connection (HotelDetails.IsEncryptionEnabled gating)
DB_HOST     = os.environ.get("DB_HOST", "").strip()
DB_PORT     = int(os.environ.get("DB_PORT", "5432"))
DB_NAME     = os.environ.get("DB_NAME", "").strip()
DB_USER     = os.environ.get("DB_USER", "").strip()
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

# In-memory cache: { hotel_code: (is_enabled: bool, expires_at: float) }
_HOTEL_CACHE = {}
_HOTEL_CACHE_TTL = 300  # seconds


def _is_hotel_encryption_enabled(hotel_code):
    """
    Look up HotelDetails.IsEncryptionEnabled for the given HotelCode.
    Cached for _HOTEL_CACHE_TTL seconds per cold container.
    Returns False on any DB error (fail-closed: do not process if we can't verify).
    """
    now = time.time()
    cached = _HOTEL_CACHE.get(hotel_code)
    if cached and cached[1] > now:
        return cached[0]

    if not (DB_HOST and DB_NAME and DB_USER):
        logger.error(json.dumps({"action": "db_config_missing", "hotel": hotel_code}))
        return False

    try:
        with psycopg2.connect(
            host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_PASSWORD,
            connect_timeout=5,
        ) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT "IsAnonymization" FROM "public.hoteldetails" WHERE "ggHotelId" = %s LIMIT 1',
                    (hotel_code,),
                )
                row = cur.fetchone()
        enabled = bool(row[0]) if row else False
        _HOTEL_CACHE[hotel_code] = (enabled, now + _HOTEL_CACHE_TTL)
        return enabled
    except Exception as e:
        logger.error(json.dumps({
            "action": "db_lookup_failed",
            "hotel": hotel_code,
            "error": str(e),
        }))
        return False


def _hotel_code_from_key(src_key):
    """Extract HotelCode = first path segment of the S3 key."""
    parts = src_key.split("/", 1)
    return parts[0] if parts and parts[0] else None

# ── Lazy singleton — models load on FIRST invocation, not at import ───────────
# This avoids the Lambda init phase timing out before models finish loading.
# Lambda allows up to timeout seconds for the handler to complete,
# but the init phase (module-level code) has a separate 10s hard limit on
# some runtimes. By loading inside the handler we avoid that limit.
_redactor = None

def get_redactor():
    global _redactor
    if _redactor is None:
        t0 = time.time()
        logger.info(json.dumps({"action": "model_load_start", "mode": MODE}))

        # Import here so module-level import doesn't count against init timeout
        from redactor import HotelPIIRedactor
        _redactor = HotelPIIRedactor(mode=MODE, confidence_threshold=CONFIDENCE)

        elapsed = round(time.time() - t0, 1)
        logger.info(json.dumps({"action": "model_load_complete", "seconds": elapsed}))
    return _redactor


def _out_key(src_key):
    base = src_key.rsplit(".", 1)[0]
    ext  = src_key.rsplit(".", 1)[-1] if "." in src_key else "txt"
    return f"{base}_redacted.{ext}"

def _map_key(src_key):
    return f"{src_key.rsplit('.', 1)[0]}_token_map.json"

def _already_processed(src_key):
    """
    Idempotency: return True if output already exists.
    Treats 403 Forbidden as "not processed" (safe fallback) so a KMS
    or IAM misconfiguration on HeadObject does not kill the whole job.
    Fix the underlying permission issue via Terraform — do not rely on this fallback.
    """
    try:
        s3.head_object(Bucket=OUTPUT_BUCKET, Key=_out_key(src_key))
        return True
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("404", "NoSuchKey"):
            return False
        if code in ("403", "AccessDenied"):
            # Log a warning but continue — file will be re-processed
            logger.warning(json.dumps({
                "action": "idempotency_check_denied",
                "key": src_key,
                "reason": "HeadObject returned 403 — check KMS key policy and IAM role permissions",
            }))
            return False
        raise


def _process_record(record, redactor):
    src_bucket = record["s3"]["bucket"]["name"]
    src_key    = unquote_plus(record["s3"]["object"]["key"])
    file_size  = record["s3"]["object"].get("size", 0)

    logger.info(json.dumps({"action": "start", "key": src_key, "bytes": file_size}))

    # Guard: hotel must be enabled for encryption (HotelDetails.IsEncryptionEnabled)
    hotel_code = _hotel_code_from_key(src_key)
    if not hotel_code:
        logger.warning(json.dumps({"action": "skip", "key": src_key, "reason": "no_hotel_code"}))
        return {"source": src_key, "status": "skipped", "reason": "no_hotel_code"}

    if not _is_hotel_encryption_enabled(hotel_code):
        logger.info(json.dumps({
            "action": "skip", "key": src_key, "hotel": hotel_code,
            "reason": "encryption_disabled",
        }))
        return {"source": src_key, "status": "skipped", "reason": "encryption_disabled"}

    # Guard: file size
    if file_size > MAX_FILE_BYTES:
        raise ValueError(
            f"{src_key}: {file_size//1024//1024} MB exceeds "
            f"{MAX_FILE_BYTES//1024//1024} MB limit. Split and resubmit."
        )

    # Guard: idempotency
    if _already_processed(src_key):
        logger.info(json.dumps({"action": "skip", "key": src_key, "reason": "already_processed"}))
        return {"source": src_key, "status": "skipped"}

    # Download
    raw = s3.get_object(Bucket=src_bucket, Key=src_key)["Body"].read().decode("utf-8", errors="replace")
    input_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]

    # Redact
    redacted, token_map = redactor.process(raw)

    # Upload redacted transcript
    ok = _out_key(src_key)
    s3.put_object(
        Bucket=OUTPUT_BUCKET, Key=ok,
        Body=redacted.encode("utf-8"), ContentType="text/plain",
        Metadata={"source-key": src_key, "input-hash": input_hash, "mode": MODE},
    )

    # Upload token map
    mk = _map_key(src_key)
    if token_map:
        s3.put_object(
            Bucket=TOKEN_MAP_BUCKET, Key=mk,
            Body=json.dumps(token_map, indent=2).encode("utf-8"),
            ContentType="application/json",
            Metadata={"source-key": src_key},
        )

    # Log counts only — never log raw PII values
    counts = redactor.last_stats
    logger.info(json.dumps({"action": "complete", "key": src_key, "pii_counts": counts}))

    return {
        "source": f"s3://{src_bucket}/{src_key}",
        "redacted": f"s3://{OUTPUT_BUCKET}/{ok}",
        "token_map": f"s3://{TOKEN_MAP_BUCKET}/{mk}",
        "pii_counts": counts,
        "status": "ok",
    }


def lambda_handler(event, context):
    records = event.get("Records", [])
    logger.info(json.dumps({
        "action": "event_received",
        "record_count": len(records),
        "request_id": getattr(context, "aws_request_id", None),
        "event_sources": sorted({r.get("eventSource", "unknown") for r in records}),
        "keys": [
            unquote_plus(r.get("s3", {}).get("object", {}).get("key", ""))
            for r in records
        ],
    }))

    # Load models on first invocation (inside handler, not at module level)
    redactor = get_redactor()
    results  = []

    for record in records:
        event_name = record.get("eventName", "unknown")
        src_bucket = record.get("s3", {}).get("bucket", {}).get("name", "unknown")
        src_key    = unquote_plus(record.get("s3", {}).get("object", {}).get("key", "unknown"))
        logger.info(json.dumps({
            "action": "event_record",
            "event_name": event_name,
            "bucket": src_bucket,
            "key": src_key,
        }))

        try:
            results.append(_process_record(record, redactor))
        except Exception as e:
            logger.error(json.dumps({"action": "error", "key": src_key, "error": str(e)}))
            results.append({"source": src_key, "status": "error", "error": str(e)})
            raise  # triggers DLQ

    return {"statusCode": 200, "body": json.dumps(results)}
