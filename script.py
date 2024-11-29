#!/usr/bin/env python3

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import getpass

# Função para derivar uma chave a partir de uma senha
def gerar_chave(senha: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(senha.encode())

# Função para criptografar um arquivo
def criptografar_arquivo(caminho_arquivo: str, chave: bytes):
    with open(caminho_arquivo, 'rb') as f:
        dados = f.read()

    padder = PKCS7(128).padder()
    dados_padded = padder.update(dados) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    dados_criptografados = encryptor.update(dados_padded) + encryptor.finalize()

    with open(caminho_arquivo + '.enc', 'wb') as f:
        f.write(iv + dados_criptografados)

    os.remove(caminho_arquivo)

# Função para descriptografar um arquivo
def descriptografar_arquivo(caminho_arquivo: str, chave: bytes):
    with open(caminho_arquivo, 'rb') as f:
        dados = f.read()

    iv = dados[:16]
    dados_criptografados = dados[16:]

    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    dados_padded = decryptor.update(dados_criptografados) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()
    dados = unpadder.update(dados_padded) + unpadder.finalize()

    caminho_original = caminho_arquivo.replace('.enc', '')
    with open(caminho_original, 'wb') as f:
        f.write(dados)

    os.remove(caminho_arquivo)

# Criptografar todos os arquivos em uma pasta
def criptografar_pasta(caminho_pasta: str, senha: str):
    salt = os.urandom(16)
    chave = gerar_chave(senha, salt)

    with open(os.path.join(caminho_pasta, 'salt.key'), 'wb') as f:
        f.write(salt)

    for raiz, _, arquivos in os.walk(caminho_pasta):
        for arquivo in arquivos:
            if arquivo == 'salt.key':
                continue
            caminho_arquivo = os.path.join(raiz, arquivo)
            criptografar_arquivo(caminho_arquivo, chave)

# Descriptografar todos os arquivos em uma pasta
def descriptografar_pasta(caminho_pasta: str, senha: str):
    salt_path = os.path.join(caminho_pasta, 'salt.key')
    if not os.path.exists(salt_path):
        print("Arquivo de salt não encontrado!")
        return

    with open(salt_path, 'rb') as f:
        salt = f.read()

    chave = gerar_chave(senha, salt)

    for raiz, _, arquivos in os.walk(caminho_pasta):
        for arquivo in arquivos:
            if arquivo == 'salt.key':
                continue
            caminho_arquivo = os.path.join(raiz, arquivo)
            descriptografar_arquivo(caminho_arquivo, chave)

# Menu principal
def main():
    print("=== Sistema de Criptografia de Arquivos ===")
    opcao = input("Deseja (C)riptografar ou (D)escriptografar uma pasta? ").lower()

    caminho_pasta = input("Digite o caminho da pasta: ")
    if not os.path.isdir(caminho_pasta):
        print("Caminho inválido!")
        return

    senha = getpass.getpass("Digite a senha: ")

    if opcao == 'c':
        criptografar_pasta(caminho_pasta, senha)
        print("Pasta criptografada com sucesso!")
    elif opcao == 'd':
        descriptografar_pasta(caminho_pasta, senha)
        print("Pasta descriptografada com sucesso!")
    else:
        print("Opção inválida!")

if __name__ == "__main__":
    main()
