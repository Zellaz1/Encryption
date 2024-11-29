#!/usr/bin/env python3

import os
from tkinter import Tk, Label, Button, filedialog, Entry, messagebox
import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

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

# Função para criptografar uma pasta
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

# Função para descriptografar uma pasta
def descriptografar_pasta(caminho_pasta: str, senha: str):
    salt_path = os.path.join(caminho_pasta, 'salt.key')
    if not os.path.exists(salt_path):
        messagebox.showerror("Erro", "Arquivo de salt não encontrado!")
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

# Função para selecionar pasta
def selecionar_pasta():
    pasta = filedialog.askdirectory()
    if pasta:
        entry_pasta.delete(0, "end")
        entry_pasta.insert(0, pasta)

# Função para iniciar criptografia
def iniciar_criptografia():
    caminho_pasta = entry_pasta.get()
    senha = entry_senha.get()
    if not caminho_pasta or not senha:
        messagebox.showwarning("Aviso", "Preencha todos os campos!")
        return

    try:
        criptografar_pasta(caminho_pasta, senha)
        messagebox.showinfo("Sucesso", "Pasta criptografada com sucesso!")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao criptografar: {e}")

# Função para iniciar descriptografia
def iniciar_descriptografia():
    caminho_pasta = entry_pasta.get()
    senha = entry_senha.get()
    if not caminho_pasta or not senha:
        messagebox.showwarning("Aviso", "Preencha todos os campos!")
        return

    try:
        descriptografar_pasta(caminho_pasta, senha)
        messagebox.showinfo("Sucesso", "Pasta descriptografada com sucesso!")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao descriptografar: {e}")

# Interface Gráfica
root = Tk()
root.title("Criptografia de Arquivos")

Label(root, text="Selecione a pasta:").grid(row=0, column=0, padx=10, pady=10)
entry_pasta = Entry(root, width=40)
entry_pasta.grid(row=0, column=1, padx=10, pady=10)
Button(root, text="Procurar", command=selecionar_pasta).grid(row=0, column=2, padx=10, pady=10)

Label(root, text="Senha:").grid(row=1, column=0, padx=10, pady=10)
entry_senha = Entry(root, width=40, show="*")
entry_senha.grid(row=1, column=1, padx=10, pady=10)

Button(root, text="Criptografar", command=iniciar_criptografia, bg="green", fg="white").grid(row=2, column=0, padx=10, pady=20)
Button(root, text="Descriptografar", command=iniciar_descriptografia, bg="blue", fg="white").grid(row=2, column=1, padx=10, pady=20)

root.mainloop()
