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