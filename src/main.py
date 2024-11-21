import csv
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from getpass import getpass

# Função que gera as chaves RSA
def gerar_chaves():
    private_key = rsa.generate_private_key( public_exponent=65537,key_size=2048,)

    private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Armazenar as chaves em arquivos
    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)

    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)

# Função para carregar a chave pública
def carregar_chave_publica():
    with open('public_key.pem', 'rb') as f:
        public_pem = f.read()

    public_key = serialization.load_pem_public_key(public_pem)
    return public_key

# Função para carregar a chave privada
def carregar_chave_privada():
    with open('private_key.pem', 'rb') as f:
        private_pem = f.read()

    private_key = serialization.load_pem_private_key(private_pem, password=None)
    return private_key

# Função para criptografar a mensagem
def criptografar_mensagem(mensagem, chave_publica):
    ciphertext = chave_publica.encrypt(mensagem.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return base64.b64encode(ciphertext).decode()

# Função para descriptografar a mensagem
def descriptografar_mensagem(ciphertext_base64, chave_privada):
    ciphertext = base64.b64decode(ciphertext_base64)
    plaintext = chave_privada.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return plaintext.decode()

# Função para validar o login
def validar_login(email, senha):
    # Para simplicidade, vamos criar um dicionário com um único usuário pré-cadastrado
    usuarios = {'jose@gmail.com': 'senha123',
                'maria@gmail.com': 'senha123'}
    if email in usuarios and usuarios[email] == senha:
        return True
    return False

# Função para escrever mensagem
def escrever_mensagem(email_usuario):
    print("\nEscrevendo mensagem...")
    email_destino = input("Digite o email de destino: ")
    mensagem = input("Digite sua mensagem: ")

    # Criptografar a mensagem
    chave_publica = carregar_chave_publica()
    mensagem_criptografada = criptografar_mensagem(mensagem, chave_publica)

    # Armazenar no CSV
    with open('mensagens.csv', 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([email_usuario, email_destino, mensagem_criptografada])

    print("Mensagem enviada com sucesso!")

# Função para acessar mensagens recebidas
def acessar_mensagens(email_usuario):
    if not os.path.exists('mensagens.csv'):
        print("Nenhuma mensagem encontrada.")
        return

    with open('mensagens.csv', 'r', newline='') as csvfile:
        reader = csv.reader(csvfile)
        chave_privada = carregar_chave_privada()
        for row in reader:
            email_destino = row[1]
            mensagem_criptografada = row[2]
            if email_destino == email_usuario:
                mensagem_original = descriptografar_mensagem(mensagem_criptografada, chave_privada)
                print(f"Mensagem de {row[0]}: {mensagem_original}")

# Função principal para o menu
def main():
    # Login
    print('\n+=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-')
    print("|                    LOGIN                   |")
    print('+=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+')
    email = input("Digite seu e-mail: ")
    senha = getpass("Digite sua senha: ")

    if not validar_login(email, senha):
        print("E-mail ou senha inválidos!")
        return

    # Gerar chaves se não existirem
    if not os.path.exists('private_key.pem') or not os.path.exists('public_key.pem'):
        print("Gerando chaves RSA...")
        gerar_chaves()

    # Menu
    while True:
        print('\n+=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+')
        print("|                   MENU                   |")
        print('+=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+')
        print("1. Escrever mensagem")
        print("2. Acessar mensagens recebidas")
        print("3. Sair")

        escolha = input("Escolha uma opção: ")

        if escolha == '1':
            escrever_mensagem(email)
        elif escolha == '2':
            acessar_mensagens(email)
        elif escolha == '3':
            print("Saindo...")
            break
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()
