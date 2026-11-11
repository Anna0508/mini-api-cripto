from typing import Annotated

from pydantic import BaseModel, Field


class NomeEntrada(BaseModel):
    nome:str

class AssinarEntrada(BaseModel):
    nome:str
    texto:str

class VerificarEntrada(BaseModel):
    nome:str
    texto:str
    assinatura:str

class CifrarEntrada(BaseModel):
    nome:str
    texto:str

class DecifrarEntrada(BaseModel):
    nome:str
    iv:str
    cifrado:str

class MonitoramentoSaida(BaseModel):
    tempo_no_ar:float
    total_operacoes:int
    operacoes_por_rota:dict
    total_de_chaves:int
    bytes_em_disco:int
    chaves_por_tipo:dict
    bytes_em_disco_legivel:str
    tempo_no_ar_legivel:str
    limite_chaves: int
    chaves_do_cofre: dict | None = None
    chaves_em_uso: int | None = None
    cofre_disponivel: bool


NomeSeguro = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")]


class NomeSeguroEntrada(NomeEntrada):
    nome: NomeSeguro


class CifrarSeguroEntrada(CifrarEntrada):
    nome: NomeSeguro


class DecifrarSeguroEntrada(DecifrarEntrada):
    nome: NomeSeguro


class AssinarSeguroEntrada(AssinarEntrada):
    nome: NomeSeguro


class VerificarSeguroEntrada(VerificarEntrada):
    nome: NomeSeguro
