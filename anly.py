import requests
import socket
import platform
import ssl
import re
import os
import time

requests.packages.urllib3.disable_warnings()

def cabecalho():
    print("=" * 60)
    print("        🛡️ ANALISADOR DE SITES - MODO TERMINAL 🛡️")
    print("=" * 60)

def menu():
    cabecalho()
    print("Escolha o modo de análise:")
    print("[1] Análise Simples")
    print("[2] Análise Completa")
    print("[0] Sair")
    print("-" * 60)
    return input(">> Opção: ")

def limpar():
    os.system("clear" if os.name != "nt" else "cls")

def obter_headers(url):
    try:
        res = requests.get(url, timeout=5, verify=False)
        return res.headers, res.status_code
    except Exception as e:
        return None, str(e)

def verificar_seguranca(headers, url):
    print("\n🔍 Verificando segurança do site:")
    print(f"- HTTPS: {'Sim' if url.startswith('https://') else 'Não'}")

    checks = {
        'Content-Security-Policy': "CSP (proteção XSS)",
        'X-Frame-Options': "Clickjacking",
        'X-Content-Type-Options': "MIME sniffing",
        'Strict-Transport-Security': "HSTS (HTTPS obrigatório)"
    }

    for header, descricao in checks.items():
        if header in headers:
            print(f"[✓] {descricao}")
        else:
            print(f"[!] {descricao} AUSENTE")

def info_usuario():
    print("\n📱 Informações do Usuário (Sistema):")
    print(f"- Sistema: {platform.system()} {platform.release()}")
    print(f"- Hostname: {socket.gethostname()}")
    try:
        print(f"- IP local: {socket.gethostbyname(socket.gethostname())}")
    except:
        print("- IP local: Não detectado")
    print(f"- Python: {platform.python_version()}")

def scan_portas(host):
    print("\n🌐 Escaneando portas:")
    for porta in [80, 443]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        resultado = sock.connect_ex((host, porta))
        status = "ABERTA" if resultado == 0 else "FECHADA"
        print(f"- Porta {porta}: {status}")
        sock.close()

def analise_simples(url):
    print(f"\n⏳ Analisando: {url}\n")
    headers, status = obter_headers(url)
    if not headers:
        print(f"Erro ao acessar o site: {status}")
        return
    print(f"✅ Status HTTP: {status}")
    print("\n📄 Cabeçalhos HTTP:")
    for k, v in headers.items():
        print(f"  - {k}: {v}")
    verificar_seguranca(headers, url)

def analise_completa(url):
    analise_simples(url)
    try:
        host = url.replace("http://", "").replace("https://", "").split("/")[0]
        scan_portas(host)
    except Exception as e:
        print(f"Erro ao analisar host: {e}")
    info_usuario()

def executar():
    while True:
        limpar()
        op = menu()
        if op == "0":
            print("Saindo...")
            break

        url = input("\nDigite a URL (ex: https://example.com): ").strip()
        if not re.match(r'^https?://', url):
            url = "http://" + url  # Assume http se não tiver

        limpar()
        cabecalho()
        if op == "1":
            analise_simples(url)
        elif op == "2":
            analise_completa(url)
        else:
            print("❌ Opção inválida.")

        input("\n🔁 Pressione ENTER para continuar...")

if __name__ == "__main__":
    executar()
0
