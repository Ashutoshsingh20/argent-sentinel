from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Text, JSON, text, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import hashlib
import logging
import os
import threading
import time
from uuid import uuid4

from runtime_settings import settings

try:
    import redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None

logger = logging.getLogger(__name__)


def hash_passphrase(passphrase: str, salt: str = None) -> str:
    salt = salt or uuid4().hex
    digest = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt.encode("utf-8"), 120000)
    return f"pbkdf2_sha256${salt}${digest.hex()}"


class HotStateStore:
    def __init__(self):
        self._data = {}
        self._lock = threading.Lock()

    def set(self, key: str, value: any):
        with self._lock:
            self._data[key] = value

    def get(self, key: str, default=None):
        with self._lock:
            return self._data.get(key, default)

    def get_all(self):
        with self._lock:
            return self._data.copy()


class RedisHotStateStore:
    def __init__(self, redis_url: str):
        if redis is None:
            raise RuntimeError("redis package is unavailable")
        self._redis = redis.Redis.from_url(redis_url, decode_responses=True)

    def set(self, key: str, value: any):
        self._redis.set(key, value)

    def get(self, key: str, default=None):
        value = self._redis.get(key)
        if value is None:
            return default
        return value

    def get_all(self):
        # Intentional no-op for production Redis paths.
        return {}


def _build_hot_state_store():
    print(f"[{time.time()}] DEBUG: _build_hot_state_store check: redis_enabled={settings.redis_enabled}, redis={redis is not None}", flush=True)
    if settings.redis_enabled and redis is not None:
        try:
            store = RedisHotStateStore(settings.redis_url)
            store._redis.ping()
            logger.info("Using Redis-backed hot state", extra={"redis_url": settings.redis_url})
            return store
        except Exception as exc:
            logger.warning("Falling back to in-memory hot state", extra={"error": str(exc)})
    return HotStateStore()

print(f"[{time.time()}] DEBUG: Building hot state store...", flush=True)
hot_state = _build_hot_state_store()
print(f"[{time.time()}] DEBUG: Hot state store ready", flush=True)

# Config
DB_URL = os.getenv("DB_URL", "sqlite:///outputs/vanguard_v3_live.db")
os.makedirs("outputs", exist_ok=True)

Base = declarative_base()
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Entity(Base):
    __tablename__ = "entities"
    
    id = Column(String, primary_key=True, index=True) # ENT-001
    entity_type = Column(String)
    cloud_env = Column(String)
    current_trust_score = Column(Float, default=75.0)
    historical_trust = Column(Float, default=0.75)
    status = Column(String, default="ALLOW") # ALLOW, RATE_LIMIT, ISOLATE
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    telemetry = relationship("Telemetry", back_populates="owner")
    enforcements = relationship("EnforcementAction", back_populates="entity")

class Telemetry(Base):
    __tablename__ = "telemetry"
    
    id = Column(Integer, primary_key=True, index=True)
    entity_id = Column(String, ForeignKey("entities.id"))
    timestamp = Column(Float)
    timestep = Column(Integer, nullable=True)
    api_rate = Column(Float)
    payload_size = Column(Float)
    traversal_depth = Column(Integer)
    session_duration = Column(Float)
    failed_auth_count = Column(Integer)
    geo_anomaly_flag = Column(Integer)
    protocol_type = Column(String)
    is_attack = Column(Integer, default=0)
    
    owner = relationship("Entity", back_populates="telemetry")

class EnforcementAction(Base):
    __tablename__ = "enforcements"
    
    id = Column(Integer, primary_key=True, index=True)
    entity_id = Column(String, ForeignKey("entities.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    decision = Column(String)
    reason = Column(Text)
    trust_score_at_action = Column(Float)
    confidence_score = Column(Float, default=85.0)
    is_correct = Column(Integer, default=1) # 1 for correct, 0 for wrong
    
    # Trust Components for Observability (Phase 5)
    b_score = Column(Float, nullable=True) # Behavioral B(t)
    c_score = Column(Float, nullable=True) # Context
    h_score = Column(Float, nullable=True) # Historical
    a_score = Column(Float, nullable=True) # Anomaly A(t)
    a_prime_score = Column(Float, nullable=True) # Fusion A'(t)
    
    # Audit trail (redundant but helpful for snapshots)
    api_rate = Column(Float, nullable=True)
    payload_size = Column(Float, nullable=True)
    
    entity = relationship("Entity", back_populates="enforcements")


class DecisionRecord(Base):
    __tablename__ = "decision_records"

    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(String, index=True)
    timestamp = Column(String, index=True)
    source = Column(String, index=True)
    entity_id = Column(String, nullable=True, index=True)
    input_features = Column(JSON, nullable=True)
    risk_score = Column(Float, nullable=True)
    trust_score = Column(Float, nullable=True)
    policy_decision = Column(String, nullable=True)
    final_action = Column(String, nullable=True, index=True)
    latency_ms = Column(Float, nullable=True)
    status = Column(String, index=True)
    error_message = Column(Text, nullable=True)
    extra = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class UISession(Base):
    __tablename__ = "ui_sessions"

    session_id = Column(String, primary_key=True, index=True)
    user_id = Column(String, index=True)
    device_hash = Column(String)
    ip_hash = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    risk_level = Column(Float, default=0.0)
    is_active = Column(Integer, default=1)
    elevated_until = Column(DateTime, nullable=True)


class UIUserAuth(Base):
    __tablename__ = "ui_user_auth"

    user_id = Column(String, primary_key=True, index=True)
    totp_secret = Column(String)
    mfa_enabled = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuthAuditEvent(Base):
    __tablename__ = "auth_audit_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    user_id = Column(String, index=True, nullable=True)
    session_id = Column(String, index=True, nullable=True)
    event_type = Column(String, index=True)
    status = Column(String, index=True)
    detail = Column(Text, nullable=True)


class PolicyAuditLog(Base):
    """Phase A — immutable record of every policy evaluation outcome."""
    __tablename__ = "policy_audit_log"

    id = Column(Integer, primary_key=True, index=True)
    # Identifiers
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    entity_id = Column(String(128), nullable=False, index=True)
    timestamp = Column(Float, nullable=False, index=True)
    # Policy outcome
    rule_id = Column(String(128), nullable=False)
    policy_version = Column(String(64), nullable=False)
    action = Column(String(32), nullable=False, index=True)
    reason = Column(Text, nullable=True)
    confidence = Column(Float, nullable=True)
    # Override info
    override_id = Column(String(64), nullable=True)        # set if an override forced the action
    override_type = Column(String(64), nullable=True)
    # Model context
    trust_score = Column(Float, nullable=True)
    source = Column(String(32), nullable=True)             # "authorize" | "gateway" | "manual"
    # Matched rules (JSON list of rule_id strings)
    matched_rules = Column(JSON, nullable=True)
    # Simulation flag
    simulation = Column(Integer, default=0)


class ShadowPromotionEvent(Base):
    __tablename__ = "shadow_promotion_events"

    id = Column(Integer, primary_key=True, index=True)
    promoted_at = Column(DateTime, default=datetime.utcnow, index=True)
    promoted_f1 = Column(Float, nullable=False)
    main_f1 = Column(Float, nullable=True)
    shadow_f1 = Column(Float, nullable=True)
    margin = Column(Float, nullable=True)
    model_source = Column(String, nullable=True)

def init_db():
    try:
        # Enable WAL mode for high-concurrency ingestion (Phase 8 Hardening)
        with engine.begin() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL"))
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        logger.warning("Database init warning", extra={"error": str(e)})
    _ensure_live_schema()

def reset_live_data():
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM enforcements"))
        conn.execute(text("DELETE FROM telemetry"))
        conn.execute(text("DELETE FROM entities"))

def _ensure_live_schema():
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS ui_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT,
                    device_hash TEXT,
                    ip_hash TEXT,
                    created_at DATETIME,
                    last_seen DATETIME,
                    risk_level FLOAT DEFAULT 0,
                    is_active INTEGER DEFAULT 1,
                    elevated_until DATETIME
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS ui_user_auth (
                    user_id TEXT PRIMARY KEY,
                    totp_secret TEXT,
                    mfa_enabled INTEGER DEFAULT 1,
                    created_at DATETIME
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS auth_audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    user_id TEXT,
                    session_id TEXT,
                    event_type TEXT,
                    status TEXT,
                    detail TEXT
                )
                """
            )
        )

        cols = conn.execute(text("PRAGMA table_info(telemetry)")).fetchall()
        existing = {row[1] for row in cols}
        if "is_attack" not in existing:
            conn.execute(text("ALTER TABLE telemetry ADD COLUMN is_attack INTEGER DEFAULT 0"))
        if "tenant_id" not in existing:
            conn.execute(text("ALTER TABLE telemetry ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'"))

        entity_cols = conn.execute(text("PRAGMA table_info(entities)")).fetchall()
        entity_existing = {row[1] for row in entity_cols}
        if "historical_trust" not in entity_existing:
            conn.execute(text("ALTER TABLE entities ADD COLUMN historical_trust FLOAT DEFAULT 0.75"))
        if "tenant_id" not in entity_existing:
            conn.execute(text("ALTER TABLE entities ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'"))

        enf_cols = conn.execute(text("PRAGMA table_info(enforcements)")).fetchall()
        enf_existing = {row[1] for row in enf_cols}
        for col in ["b_score", "c_score", "h_score", "a_score", "a_prime_score", "api_rate", "payload_size"]:
            if col not in enf_existing:
                conn.execute(text(f"ALTER TABLE enforcements ADD COLUMN {col} FLOAT"))
        if "is_correct" not in enf_existing:
            conn.execute(text("ALTER TABLE enforcements ADD COLUMN is_correct INTEGER DEFAULT 1"))
        if "tenant_id" not in enf_existing:
            conn.execute(text("ALTER TABLE enforcements ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'"))

        # Phase A — Policy Audit Log table
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS policy_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                entity_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                rule_id TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT,
                confidence REAL,
                override_id TEXT,
                override_type TEXT,
                trust_score REAL,
                source TEXT,
                matched_rules TEXT,
                simulation INTEGER DEFAULT 0
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_pal_entity ON policy_audit_log(entity_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_pal_tenant ON policy_audit_log(tenant_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_pal_ts ON policy_audit_log(timestamp)"))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS platform_users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                full_name TEXT,
                role TEXT DEFAULT 'Analyst',
                department TEXT DEFAULT 'SOC Analyst',
                created_at DATETIME,
                role_updated_at DATETIME,
                role_updated_by TEXT,
                password_hash TEXT,
                last_login_at DATETIME
            )
        """))
        user_cols = conn.execute(text("PRAGMA table_info(platform_users)")).fetchall()
        user_existing = {row[1] for row in user_cols}
        if "role_updated_at" not in user_existing:
            conn.execute(text("ALTER TABLE platform_users ADD COLUMN role_updated_at DATETIME"))
        if "role_updated_by" not in user_existing:
            conn.execute(text("ALTER TABLE platform_users ADD COLUMN role_updated_by TEXT"))
        if "password_hash" not in user_existing:
            conn.execute(text("ALTER TABLE platform_users ADD COLUMN password_hash TEXT"))
        if "last_login_at" not in user_existing:
            conn.execute(text("ALTER TABLE platform_users ADD COLUMN last_login_at DATETIME"))
        if "tenant_id" not in user_existing:
            conn.execute(text("ALTER TABLE platform_users ADD COLUMN tenant_id TEXT DEFAULT 'default'"))
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_platform_users_email ON platform_users(email)"))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS shadow_promotion_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                promoted_at DATETIME,
                promoted_f1 REAL NOT NULL,
                main_f1 REAL,
                shadow_f1 REAL,
                margin REAL,
                model_source TEXT
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_shadow_promotion_at ON shadow_promotion_events(promoted_at)"))

        alex = conn.execute(
            text("SELECT id, role FROM platform_users WHERE email = :email"),
            {"email": "alex@argent.local"},
        ).fetchone()
        now = datetime.utcnow()
        if alex is None:
            conn.execute(
                text("""
                    INSERT INTO platform_users
                    (id, email, full_name, role, department, created_at, role_updated_at, role_updated_by)
                    VALUES (:id, :email, :full_name, :role, :department, :created_at, :role_updated_at, :role_updated_by)
                """),
                {
                    "id": "dev-alex-001",
                    "email": "alex@argent.local",
                    "full_name": "Alex Mercer",
                    "role": "Administrator",
                    "department": "Threat Operations",
                    "created_at": now,
                    "role_updated_at": now,
                    "role_updated_by": "system_seed",
                },
            )
        elif alex[1] != "Administrator":
            conn.execute(
                text("""
                    UPDATE platform_users
                    SET role = 'Administrator', role_updated_at = :role_updated_at, role_updated_by = :role_updated_by
                    WHERE email = :email
                """),
                {"email": "alex@argent.local", "role_updated_at": now, "role_updated_by": "system_seed"},
            )

        demo = conn.execute(
            text("SELECT id FROM platform_users WHERE email = :email"),
            {"email": "demo@argent.local"},
        ).fetchone()
        if demo is None:
            conn.execute(
                text("""
                    INSERT INTO platform_users
                    (id, email, full_name, role, department, created_at, role_updated_at, role_updated_by, password_hash)
                    VALUES (:id, :email, :full_name, :role, :department, :created_at, :role_updated_at, :role_updated_by, :password_hash)
                """),
                {
                    "id": "demo-admin-001",
                    "email": "demo@argent.local",
                    "full_name": "Demo Admin",
                    "role": "Administrator",
                    "department": "Control Plane",
                    "created_at": now,
                    "role_updated_at": now,
                    "role_updated_by": "system_seed",
                    "password_hash": hash_passphrase("demo123"),
                },
            )
        else:
            conn.execute(
                text("""
                    UPDATE platform_users
                    SET full_name = 'Demo Admin',
                        role = 'Administrator',
                        department = 'Control Plane',
                        role_updated_at = :role_updated_at,
                        role_updated_by = :role_updated_by,
                        password_hash = COALESCE(password_hash, :password_hash)
                    WHERE email = :email
                """),
                {
                    "email": "demo@argent.local",
                    "role_updated_at": now,
                    "role_updated_by": "system_seed",
                    "password_hash": hash_passphrase("demo123"),
                },
            )

if __name__ == "__main__":
    logger.info("Initializing Argent Autonomous Database")
    init_db()
    logger.info("Database ready", extra={"db_url": DB_URL})


class PlatformUser(Base):
    __tablename__ = "platform_users"
    
    id = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    role = Column(String, default="Analyst")
    department = Column(String, default="SOC Analyst")
    created_at = Column(DateTime, default=datetime.utcnow)
    role_updated_at = Column(DateTime, nullable=True)
    role_updated_by = Column(String, nullable=True)
    password_hash = Column(String, nullable=True)
    last_login_at = Column(DateTime, nullable=True)
    tenant_id = Column(String, default="default", index=True)

class UserSetting(Base):
    __tablename__ = "user_settings"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("platform_users.id"))
    theme = Column(String, default="light")
    timezone = Column(String, default="UTC")
    email_alerts = Column(Integer, default=1)
