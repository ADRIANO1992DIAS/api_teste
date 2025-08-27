from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime
import base64, json, io

# ReportLab para gerar PDF em memória
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm

app = FastAPI(title="Mock SERPRO PGDAS-D", version="1.1.0")

# --------------- utils ---------------

def pdf_bytes_from_text(lines: List[str]) -> bytes:
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
    return buf.read()

def pdf_b64_from_text(lines: List[str]) -> str:
    data = pdf_bytes_from_text(lines)
    return base64.b64encode(data).decode("utf-8")

def ok_payload(dados_obj: Dict[str, Any], mensagens: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    return {"mensagens": mensagens or [], "dados": json.dumps(dados_obj)}

def get_effective_jwt_token(request: Request, jwt_token_param: Optional[str]) -> Optional[str]:
    if jwt_token_param:
        return jwt_token_param
    h = request.headers
    # Starlette normaliza para minúsculas; tentamos variações por compatibilidade
    return h.get("jwt-token") or h.get("jwt_token") or h.get("Jwt-Token") or h.get("Jwt_Token")

# --------------- modelos ---------------

class AuthenticateResponse(BaseModel):
    access_token: str
    jwt_token: str
    token_type: str = "bearer"
    expires_in: int = 3600

# --------------- rotas ---------------

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
    request: Request,
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
    jwt_token: Optional[str] = Header(None, alias="jwt-token"),
    content_type: Optional[str] = Header(None, alias="Content-Type"),
):
    effective_jwt = get_effective_jwt_token(request, jwt_token)
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: Bearer token missing")
    if not effective_jwt:
        raise HTTPException(status_code=401, detail="Unauthorized: jwt_token header missing")
    if content_type != "application/json":
        raise HTTPException(status_code=400, detail="Content-Type must be application/json")

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

    agora = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    id_declaracao = f"DEC-{cnpj}-{pa}-{agora}"

    # PDFs com conteúdo do body
    lines_common = [
        f"PGDAS-D MOCK - Declaracao",
        f"ID Declaracao: {id_declaracao}",
        f"CNPJ: {cnpj}",
        f"PA: {pa}",
        f"Tipo Declaracao: {tipo_declaracao}",
        f"Receita Interno: {receita_interno}",
        f"Receita Externo: {receita_externo}",
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
    request: Request,
    body: Dict[str, Any],
    authorization: Optional[str] = Header(None),
    jwt_token: Optional[str] = Header(None, alias="jwt-token"),
    content_type: Optional[str] = Header(None, alias="Content-Type"),
):
    effective_jwt = get_effective_jwt_token(request, jwt_token)
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: Bearer token missing")
    if not effective_jwt:
        raise HTTPException(status_code=401, detail="Unauthorized: jwt_token header missing")
    if content_type != "application/json":
        raise HTTPException(status_code=400, detail="Content-Type must be application/json")

    try:
        pedido = body["pedidoDados"]
        dados_str = pedido["dados"]
        dados = json.loads(dados_str)
        pa = dados.get("periodoApuracao")
        cnpj_contrib = body.get("contribuinte", {}).get("numero") or body.get("contribuinte", {}).get("cnpj")  # caso exista
        # também aceitar que não venha contribuinte no Emitir; se não vier, fica None
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid body structure: {e}")

    # PDF do DAS com informações recebidas (CNPJ, PA)
    das_lines = [
        "PGDAS-D MOCK - DAS",
        f"CNPJ Contribuinte: {cnpj_contrib}",
        f"Periodo Apuracao (PA): {pa}",
        "Este DAS é simulado para testes integrados.",
    ]
    das_pdf_b64 = pdf_b64_from_text(das_lines)

    das_item = {
        "id": f"DAS-{pa}",
        "pdf": das_pdf_b64,
    }
    # seu cliente aceita lista ou item único; retornamos lista
    return JSONResponse(content=ok_payload([das_item]))