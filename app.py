from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
import base64
import json

app = FastAPI(title="Mock SERPRO PGDAS-D", version="1.0.0")

# ---------- util ----------

def pdf_base64_fake(texto: str) -> str:
    fake = f"%PDF-1.4\n%fake\n{texto}\n%%EOF".encode("utf-8")
    return base64.b64encode(fake).decode("utf-8")

def ok_payload(dados_obj: Dict[str, Any], mensagens: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    return {
        "mensagens": mensagens or [],
        "dados": json.dumps(dados_obj),
    }

def get_effective_jwt_token(request: Request, jwt_token_param: Optional[str]) -> Optional[str]:
    # 1) se já veio pelo Header(alias="jwt-token"), usar esse
    if jwt_token_param:
        return jwt_token_param
    # 2) fallback: tentar variantes no dicionário de headers bruto
    # FastAPI/Starlette normaliza para minúsculas
    h = request.headers
    return (
        h.get("jwt-token")
        or h.get("jwt_token")
        or h.get("Jwt-Token")
        or h.get("Jwt_Token")
    )

# ---------- modelos ----------

class AuthenticateResponse(BaseModel):
    access_token: str
    jwt_token: str
    token_type: str = "bearer"
    expires_in: int = 3600

# ---------- rotas ----------

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

    return AuthenticateResponse(
        access_token="mock_access_token_123",
        jwt_token="mock_jwt_token_abc",
        expires_in=3600,
    )

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
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid body structure: {e}")

    agora = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    retorno = {
        "idDeclaracao": f"DEC-{cnpj}-{pa}-{agora}",
        "declaracao": pdf_base64_fake("DECLARACAO_FAKE"),
        "recibo": pdf_base64_fake("RECIBO_FAKE"),
        "notificacaoMaed": pdf_base64_fake("MAED_FAKE"),
        "darf": pdf_base64_fake("DARF_FAKE"),
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
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid body structure: {e}")

    das_item = {
        "id": f"DAS-{pa}",
        "pdf": pdf_base64_fake(f"DAS_FAKE_{pa}"),
    }
    return JSONResponse(content=ok_payload([das_item]))
