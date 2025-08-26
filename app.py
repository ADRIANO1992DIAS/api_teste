from fastapi import FastAPI, Header, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime
import base64, json, io
import os

# PDF
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm

# Banco
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Numeric
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import JSONB

load_dotenv()

DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "pgdasd")
DB_USER = os.getenv("DB_USER", "app_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "pg_password")

DATABASE_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()

class DeclaracaoLog(Base):
    __tablename__ = "declaracao_log"
    id = Column(Integer, primary_key=True, index=True)
    cnpj = Column(String(14), index=True, nullable=True)
    pa = Column(String(6), index=True, nullable=True)
    tipo_declaracao = Column(Integer, nullable=True)
    receita_interno = Column(Numeric(18, 2), nullable=True)
    receita_externo = Column(Numeric(18, 2), nullable=True)
    payload = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class DasLog(Base):
    __tablename__ = "das_log"
    id = Column(Integer, primary_key=True, index=True)
    cnpj = Column(String(14), index=True, nullable=True)
    pa = Column(String(6), index=True, nullable=True)
    payload = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Mock SERPRO PGDAS-D", version="1.3.1")

# Dependência de sessão (sem decorators que alteram assinatura)
def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def pdf_b64_from_text(lines: List[str]) -> str:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    x = 20 * mm
    y = height - 20 * mm
    leading = 7 * mm
    c.setFont("Helvetica", 11)
    for line in lines:
        c.drawString(x, y, line)
        y -= leading
        if y < 20 * mm:
            c.showPage()
            c.setFont("Helvetica", 11)
            y = height - 20 * mm
    c.showPage()
    c.save()
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")

def ok_payload(dados_obj: Dict[str, Any], mensagens: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    return {"mensagens": mensagens or [], "dados": json.dumps(dados_obj)}

def get_effective_jwt_token(request: Request, jwt_token_param: Optional[str]) -> Optional[str]:
    if jwt_token_param:
        return jwt_token_param
    h = request.headers
    return h.get("jwt-token") or h.get("jwt_token") or h.get("Jwt-Token") or h.get("Jwt_Token")

class AuthenticateResponse(BaseModel):
    access_token: str
    jwt_token: str
    token_type: str = "bearer"
    expires_in: int = 3600

@app.post("/authenticate")
def authenticate(
    authorization: Optional[str] = Header(None),
    role_type: Optional[str] = Header(None, alias="role-type"),
    content_type: Optional[str] = Header(None, alias="content-type"),
):
    if not authorization or not authorization.startswith("Basic "):
        raise HTTPException(status_code=400, detail="Missing or invalid Authorization header (Basic expected)")
    if role_type != "TERCEIROS":
        raise HTTPException(status_code=400, detail="Missing or invalid role-type")
    if content_type != "application/x-www-form-urlencoded":
        raise HTTPException(status_code=400, detail="Invalid content-type")
    return AuthenticateResponse(access_token="mock_access_token_123", jwt_token="mock_jwt_token_abc", expires_in=3600)

@app.post("/integra-contador/v1/Declarar")
async def declarar(
    body: Dict[str, Any],
    request: Request,
    authorization: Optional[str] = Header(None),
    jwt_token: Optional[str] = Header(None, alias="jwt-token"),
    content_type: Optional[str] = Header(None, alias="Content-Type"),
    db: Session = Depends(get_db),
):
    # Headers
    effective_jwt = get_effective_jwt_token(request, jwt_token)
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: Bearer token missing")
    if not effective_jwt:
        raise HTTPException(status_code=401, detail="Unauthorized: jwt_token header missing")
    if content_type != "application/json":
        raise HTTPException(status_code=400, detail="Content-Type must be application/json")

    # Parse body
    try:
        pedido = body["pedidoDados"]
        dados_str = pedido["dados"]
        dados = json.loads(dados_str)

        cnpj = dados.get("cnpjCompleto")
        pa = dados.get("pa")
        declaracao = dados.get("declaracao", {}) or {}

        tipo_declaracao = declaracao.get("tipoDeclaracao")
        receita_interno = declaracao.get("receitaPaCompetenciaInterno")
        receita_externo = declaracao.get("receitaPaCompetenciaExterno")
        folhas = declaracao.get("folhasSalario", [])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid body structure: {e}")

    # Persistência
    try:
        reg = DeclaracaoLog(
            cnpj=(cnpj or None),
            pa=(str(pa) if pa is not None else None),
            tipo_declaracao=tipo_declaracao,
            receita_interno=receita_interno if receita_interno is not None else None,
            receita_externo=receita_externo if receita_externo is not None else None,
            payload=dados,
        )
        db.add(reg)
        db.commit()
    except Exception:
        db.rollback()

    # PDFs simulados
    agora = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    id_declaracao = f"DEC-{cnpj}-{pa}-{agora}"

    lines_common = [
        "PGDAS-D MOCK - Declaracao",
        f"ID Declaracao: {id_declaracao}",
        f"CNPJ: {cnpj}",
        f"PA: {pa}",
        f"Tipo Declaracao: {tipo_declaracao}",
        f"Receita Interno (PA): {receita_interno}",
        f"Receita Externo (PA): {receita_externo}",
        f"Folhas Salario (qtd): {len(folhas)}",
    ]
    if folhas:
        lines_common.append("Detalhe Folhas:")
        for f in folhas[:50]:
            lines_common.append(f"- PA: {f.get('pa')} | Valor: {f.get('valor')}")

    declaracao_pdf_b64 = pdf_b64_from_text(["DECLARACAO"] + lines_common)
    recibo_pdf_b64 = pdf_b64_from_text(["RECIBO"] + lines_common)
    maed_pdf_b64 = pdf_b64_from_text(["NOTIFICACAO MAED"] + lines_common)
    darf_pdf_b64 = pdf_b64_from_text(["DARF"] + lines_common)

    retorno = {
        "idDeclaracao": id_declaracao,
        "declaracao": declaracao_pdf_b64,
        "recibo": recibo_pdf_b64,
        "notificacaoMaed": maed_pdf_b64,
        "darf": darf_pdf_b64,
    }
    return JSONResponse(content=ok_payload(retorno))

@app.post("/integra-contador/v1/Emitir")
async def emitir(
    body: Dict[str, Any],
    request: Request,
    authorization: Optional[str] = Header(None),
    jwt_token: Optional[str] = Header(None, alias="jwt-token"),
    content_type: Optional[str] = Header(None, alias="Content-Type"),
    db: Session = Depends(get_db),
):
    # Headers
    effective_jwt = get_effective_jwt_token(request, jwt_token)
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: Bearer token missing")
    if not effective_jwt:
        raise HTTPException(status_code=401, detail="Unauthorized: jwt_token header missing")
    if content_type != "application/json":
        raise HTTPException(status_code=400, detail="Content-Type must be application/json")

    # Parse body
    try:
        pedido = body["pedidoDados"]
        dados_str = pedido["dados"]
        dados = json.loads(dados_str)
        pa = dados.get("periodoApuracao")
        cnpj_contrib = body.get("contribuinte", {}).get("numero") or body.get("contribuinte", {}).get("cnpj")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid body structure: {e}")

    # Persistência
    try:
        reg = DasLog(
            cnpj=(cnpj_contrib or None),
            pa=(str(pa) if pa is not None else None),
            payload=dados,
        )
        db.add(reg)
        db.commit()
    except Exception:
        db.rollback()

    das_lines = [
        "PGDAS-D MOCK - DAS",
        f"CNPJ Contribuinte: {cnpj_contrib}",
        f"Periodo Apuracao (PA): {pa}",
        "Este DAS é simulado para testes integrados.",
    ]
    das_pdf_b64 = pdf_b64_from_text(das_lines)

    das_item = {"id": f"DAS-{pa}", "pdf": das_pdf_b64}
    return JSONResponse(content=ok_payload([das_item]))
