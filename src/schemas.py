from pydantic import BaseModel

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