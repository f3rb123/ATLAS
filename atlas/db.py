"""Durable SQL entities; PostgreSQL in production, SQLite for isolated development."""
import hashlib, json, uuid
from datetime import datetime, timezone
from sqlalchemy import create_engine, String, Text, Integer, Float, ForeignKey, UniqueConstraint, event, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from .config import settings

def uid(): return str(uuid.uuid4())
def now(): return datetime.now(timezone.utc).isoformat()
def canonical(v): return json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
def digest(v): return hashlib.sha256(v.encode() if isinstance(v,str) else v).hexdigest()
class Base(DeclarativeBase): pass
class Document(Base):
    __tablename__='documents'
    id: Mapped[str]=mapped_column(String(36),primary_key=True,default=uid)
    kind: Mapped[str]=mapped_column(String(40),index=True)
    owner: Mapped[str]=mapped_column(String(36),index=True)
    data: Mapped[str]=mapped_column(Text,default='{}')
    version: Mapped[int]=mapped_column(Integer,default=1)
    created: Mapped[str]=mapped_column(String(40),default=now)
    def value(self): return json.loads(self.data)
class User(Base):
    __tablename__='users'
    id: Mapped[str]=mapped_column(String(36),primary_key=True,default=uid)
    email: Mapped[str]=mapped_column(String(255),unique=True)
    password: Mapped[str]=mapped_column(Text)
    role: Mapped[str]=mapped_column(String(20),default='owner_admin')
    totp: Mapped[str|None]=mapped_column(Text,nullable=True)
    totp_counter: Mapped[int]=mapped_column(Integer,default=-1)
    mfa: Mapped[int]=mapped_column(Integer,default=0)
class Session(Base):
    __tablename__='sessions'
    id: Mapped[str]=mapped_column(String(36),primary_key=True,default=uid)
    user_id: Mapped[str]=mapped_column(ForeignKey('users.id'))
    token_hash: Mapped[str]=mapped_column(String(64),unique=True)
    csrf_hash: Mapped[str]=mapped_column(String(64))
    created: Mapped[float]=mapped_column(Float)
    used: Mapped[float]=mapped_column(Float)
    expires: Mapped[float]=mapped_column(Float)
    mfa: Mapped[int]=mapped_column(Integer,default=0)
    stepup: Mapped[float]=mapped_column(Float,default=0)
    scopes: Mapped[str]=mapped_column(Text,default='browser')
class Journal(Base):
    __tablename__='journal'
    __table_args__=(UniqueConstraint('stream','sequence'),)
    id: Mapped[str]=mapped_column(String(36),primary_key=True,default=uid)
    stream: Mapped[str]=mapped_column(String(36),index=True)
    sequence: Mapped[int]=mapped_column(Integer)
    payload: Mapped[str]=mapped_column(Text)
    previous: Mapped[str]=mapped_column(String(64))
    hash: Mapped[str]=mapped_column(String(64))
class Knowledge(Base):
    __tablename__='knowledge'
    id: Mapped[str]=mapped_column(String(36),primary_key=True)
    owner: Mapped[str]=mapped_column(String(36),default='public',index=True)
    canonical_key: Mapped[str]=mapped_column(String(255),unique=True)
    category: Mapped[str]=mapped_column(String(60),index=True)
    source: Mapped[str]=mapped_column(String(50),index=True)
    title: Mapped[str]=mapped_column(Text)
    content_hash: Mapped[str]=mapped_column(String(64),index=True)
    record: Mapped[str]=mapped_column(Text)
class Alias(Base):
    __tablename__='knowledge_aliases'
    alias: Mapped[str]=mapped_column(String(255),primary_key=True)
    record_id: Mapped[str]=mapped_column(ForeignKey('knowledge.id'),index=True)
class Chunk(Base):
    __tablename__='knowledge_chunks'
    id: Mapped[str]=mapped_column(String(36),primary_key=True,default=uid)
    record_id: Mapped[str]=mapped_column(ForeignKey('knowledge.id'),index=True)
    position: Mapped[int]=mapped_column(Integer)
    text: Mapped[str]=mapped_column(Text)
    embedding: Mapped[str]=mapped_column(Text)

_engine=None
_factory=None
def engine():
    global _engine,_factory
    if _engine is None:
        from pathlib import Path
        Path(settings().data_dir).mkdir(mode=0o700,parents=True,exist_ok=True)
        _engine=create_engine(settings().database_url,connect_args={'check_same_thread':False} if settings().database_url.startswith('sqlite') else {},pool_pre_ping=True,hide_parameters=True)
        if settings().database_url.startswith('sqlite'):
            @event.listens_for(_engine,'connect')
            def sqlite_pragmas(conn, _):
                conn.execute('PRAGMA foreign_keys=ON'); conn.execute('PRAGMA journal_mode=WAL')
        _factory=sessionmaker(_engine,expire_on_commit=False)
    return _engine

def session():
    engine(); return _factory()
def document(db,kind,owner,data,id=None):
    d=Document(id=id or uid(),kind=kind,owner=owner,data=canonical(data));db.add(d);db.flush();return d

def append(db,stream,actor,event_type,payload,campaign_id=None):
    # Caller holds the stream document row lock; SQLite serializes writes in tests.
    if db.bind.dialect.name=='postgresql':
        lock=int.from_bytes(hashlib.sha256(stream.encode()).digest()[:8],signed=True)
        db.execute(text('SELECT pg_advisory_xact_lock(:lock)'),{'lock':lock})
    tail=db.query(Journal).filter_by(stream=stream).order_by(Journal.sequence.desc()).first()
    seq=tail.sequence+1 if tail else 1;prev=tail.hash if tail else '0'*64
    value=canonical({'actor':actor,'type':event_type,'payload':payload,'timestamp':now(),'correlation_id':uid(),'campaign_id':campaign_id,'run_id':stream})
    j=Journal(stream=stream,sequence=seq,payload=value,previous=prev,hash=digest(prev+str(seq)+value));db.add(j);db.flush();return j

@event.listens_for(Journal,'before_update')
@event.listens_for(Journal,'before_delete')
def immutable(*_): raise ValueError('journal is append-only')
