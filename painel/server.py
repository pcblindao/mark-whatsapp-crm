# Painel local do WhatsApp: leitura + envio pela ponte local (http://127.0.0.1:8080).
# Serve em http://localhost:8780, escutando apenas em 127.0.0.1. Nada é publicado fora desta máquina.
# Rodar com: uv run --no-project -p 3.12 --with "av<16" --with pillow --with numpy python -I -X utf8 painel\server.py
# PAINEL_DRYRUN=1 faz /api/enviar e /api/lida só simularem (não chamam a ponte).
import gzip, json, shutil, mimetypes, os, re, secrets, sqlite3, threading, time, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote

HOST = os.environ.get("PAINEL_HOST") or "0.0.0.0"  # rede local com senha; ver ACESSO.txt (PAINEL_HOST=127.0.0.1 volta a ser só local)
# [escutaip] PAINEL_HOST aceita vários endereços separados por vírgula (ex.: "127.0.0.1,172.25.0.1" = local + rede
# docker do proxy). O 1º é o principal (falhou = sai); os outros esperam a interface existir (docker sobe depois).
HOSTS = [h.strip() for h in HOST.split(",") if h.strip()] or ["0.0.0.0"]
HOST = HOSTS[0]
PORT = int(os.environ.get("PAINEL_PORTA") or 8780)  # 8765 é usada pelo login do google-ads-mcp
AQUI = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(AQUI)  # WhatsApp-Assistente
STORE = os.environ.get("BRIDGE_STORE", os.path.join(BASE, "store"))
MSG_DB = os.path.join(STORE, "messages.db")
WA_DB = os.path.join(STORE, "whatsapp.db")
TRANS_DB = os.path.join(BASE, "transcricoes.db")
DEMANDAS = os.path.join(BASE, "demandas.md")
CONFIG = os.path.join(BASE, "vigilancia_config.json")
PONTE = "http://127.0.0.1:8080"
BRIDGE = PONTE + "/api/download"
HOSTS_OK = {f"localhost:{PORT}", f"127.0.0.1:{PORT}", f"[::1]:{PORT}"}
# [vps] atrás do Nginx Proxy Manager: PAINEL_PROXY=crm.example.com. O TLS fica com o proxy; o IP do
# cliente vem do X-Forwarded-For (só quando a conexão chega de IP privado, isto é, do proxy no Docker).
PROXY = (os.environ.get("PAINEL_PROXY") or "").strip().lower()
ORIGENS_OK = {"http://" + h for h in HOSTS_OK}

# ---------- acesso pela rede local: só IPs privados, com senha ----------
import base64, hashlib, hmac, ipaddress, socket as _socket
CONFIG_PAINEL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
ACESSO_TXT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ACESSO.txt")
REDES_OK = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128",
                                               "100.64.0.0/10", "fd7a:115c:a1e0::/48")]  # 100.64/10 e fd7a:115c:a1e0::/48 = Tailscale (VPN privada; login do painel continua valendo)
HTTPS_ATIVO = False  # ligado na partida, se o certificado foi criado
SESSAO_SEG = 30 * 86400  # aparelho fica conectado 30 dias (renovado a cada uso)
_sessoes = {}          # token -> (expira, hash da senha quando logou)
_falhas = {}           # ip -> [horários das tentativas erradas]
_falhas_total = []     # todas as tentativas erradas (contra tentativa espalhada por vários IPs)
_acesso_lock = threading.Lock()
_bloqueios = []         # [segaviso] bloqueios de login das últimas 24 h (hora, IP, motivo), para o painel avisar o operador


def ip_cliente_ok(ip):
    try:
        a = ipaddress.ip_address(ip)
        if getattr(a, "ipv4_mapped", None):
            a = a.ipv4_mapped
        return any(a in n for n in REDES_OK)
    except ValueError:
        return False


def ip_local(ip):
    try:
        a = ipaddress.ip_address(ip)
        a = getattr(a, "ipv4_mapped", None) or a
        return a.is_loopback
    except ValueError:
        return False


def host_ok(host):
    """Proteção contra DNS rebinding: o Host tem que ser localhost, um IP privado ou o nome deste PC."""
    if host in HOSTS_OK:
        return True
    if PROXY and host.lower() == PROXY:
        return True
    h, _, porta = host.rpartition(":")
    if porta != str(PORT) or not h:
        return False
    if h.lower() in {_socket.gethostname().lower(), _socket.gethostname().lower() + ".local"}:
        return True
    if h.lower().startswith(_socket.gethostname().lower() + ".") and h.lower().endswith(".ts.net"):  # nome MagicDNS do Tailscale
        return True
    return ip_cliente_ok(h.strip("[]"))


def _hash_senha(senha, sal=None, it=200_000):
    sal = sal or secrets.token_hex(16)
    return f"pbkdf2_sha256${it}${sal}${hashlib.pbkdf2_hmac('sha256', senha.encode('utf-8'), bytes.fromhex(sal), it).hex()}"


def _cfg_painel():
    try:
        with open(CONFIG_PAINEL, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


# [perf-patch v1] arquivos JSON pequenos: relê só quando o arquivo muda (mtime/tamanho) ou depois de alguns segundos
CACHE_TTL = 3.0  # segundos; limite de "atraso" de qualquer cache curto deste arquivo
_arq_cache = {}
_arq_lock = threading.Lock()


def _marca_arq(path):
    try:
        s = os.stat(path)
        return (s.st_mtime_ns, s.st_size)
    except OSError:
        return None


def _marca_wa_db():
    """Inclui o WAL: novos vínculos LID/número invalidam os caches imediatamente."""
    return (_marca_arq(WA_DB), _marca_arq(WA_DB + "-wal"))


def _marca_db():
    """Muda a cada gravação da ponte (o WAL cresce/é reescrito; o .db muda no checkpoint)."""
    return (_marca_arq(MSG_DB), _marca_arq(MSG_DB + "-wal"))


def _json_arq(path, ttl=2.0):
    """json.load com cache. Devolve o objeto COMPARTILHADO (não alterar) ou levanta OSError/ValueError como json.load."""
    m, agora = _marca_arq(path), time.monotonic()
    with _arq_lock:
        c = _arq_cache.get(path)
        if c and c[0] == m and m is not None and agora - c[1] < ttl:
            return c[2]
    with open(path, encoding="utf-8") as f:
        v = json.load(f)
    with _arq_lock:
        _arq_cache[path] = (m, agora, v)
    return v


def definir_senha(senha):
    cfg = _cfg_painel()
    cfg["senha_hash"] = _hash_senha(senha)
    tmp = CONFIG_PAINEL + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG_PAINEL)
    ips = []
    try:
        ips = [i for i in _socket.gethostbyname_ex(_socket.gethostname())[2] if ip_cliente_ok(i) and not i.startswith("127.")]
    except OSError:
        pass
    with open(ACESSO_TXT, "w", encoding="utf-8") as f:
        f.write("ACESSO AO PAINEL DO WHATSAPP PELA REDE LOCAL\n\n")
        f.write("Senha: " + senha + "\n\n")
        f.write("Endereço para abrir em outro aparelho da mesma rede (celular, notebook):\n")
        for i in ips or ["<IP deste computador>"]:
            f.write(f"  https://{i}:{PORT}   (microfone, câmera e avisos funcionam)\n")
        f.write("\nNa primeira vez o navegador avisa \"Sua conexão não é particular\": clique em Avançado > Continuar.\n")
        f.write("Para não ver mais o aviso, instale painel\\certificado\\painel-ca.crt no aparelho como certificado confiável.\n")
        f.write(f"\nNeste computador continua funcionando sem senha: http://localhost:{PORT}\n\n")
        f.write("Trocar a senha: dê dois cliques em C:\\Users\\operador\\WhatsApp-Assistente\\trocar-senha-painel.cmd\n")
        f.write("  (gera uma senha nova aleatória e abre este arquivo). Para escolher a senha, no terminal:\n")
        f.write("  trocar-senha-painel.cmd MinhaSenhaNova123   (mínimo 8 caracteres)\n")
        f.write("  Não precisa reiniciar o painel; quem estava logado precisa entrar de novo.\n\n")
        f.write("Segurança: só aparelhos da rede local (IP privado) conseguem abrir; IP de fora é recusado mesmo se o roteador\n")
        f.write("redirecionar a porta. Depois de 5 senhas erradas o aparelho fica bloqueado por 15 minutos.\n")
        f.write("Não compartilhe este arquivo: quem tem a senha lê suas conversas e envia mensagens como você.\n")


CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certificado")


def preparar_https():
    """Cria (uma vez) uma autoridade certificadora só do painel e um certificado para os IPs/nome deste PC.
    Retorna um ssl.SSLContext ou None (se a biblioteca cryptography não estiver disponível)."""
    import ssl, datetime, ipaddress as _ip
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError:
        print("Aviso: sem a biblioteca 'cryptography' — painel só em http.")
        return None
    os.makedirs(CERT_DIR, exist_ok=True)
    ca_crt, ca_key = os.path.join(CERT_DIR, "painel-ca.crt"), os.path.join(CERT_DIR, "painel-ca.key")
    srv_crt, srv_key = os.path.join(CERT_DIR, "painel.crt"), os.path.join(CERT_DIR, "painel.key")
    agora = datetime.datetime.now(datetime.timezone.utc)
    if not (os.path.exists(ca_crt) and os.path.exists(ca_key)):
        k = ec.generate_private_key(ec.SECP256R1())
        nome = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Painel WhatsApp do operador (CA local)")])
        c = (x509.CertificateBuilder().subject_name(nome).issuer_name(nome).public_key(k.public_key())
             .serial_number(x509.random_serial_number()).not_valid_before(agora - datetime.timedelta(days=1))
             .not_valid_after(agora + datetime.timedelta(days=3650))
             .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
             .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                          key_encipherment=False, data_encipherment=False, key_agreement=False,
                                          encipher_only=False, decipher_only=False), critical=True)
             .sign(k, hashes.SHA256()))
        open(ca_key, "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        open(ca_crt, "wb").write(c.public_bytes(serialization.Encoding.PEM))
    ca_k = serialization.load_pem_private_key(open(ca_key, "rb").read(), None)
    ca_c = x509.load_pem_x509_certificate(open(ca_crt, "rb").read())
    ips = {"127.0.0.1"}
    try:
        ips |= {i for i in _socket.gethostbyname_ex(_socket.gethostname())[2] if ip_cliente_ok(i)}
    except OSError:
        pass
    nomes = {"localhost", _socket.gethostname().lower()}
    try:  # Tailscale instalado: põe o IP 100.x e o nome MagicDNS no certificado (acesso pelo iPhone no 4G)
        import subprocess as _sp, shutil as _sh
        _ts = _sh.which("tailscale") or os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Tailscale", "tailscale.exe")
        if os.path.exists(_ts):
            _st = json.loads(_sp.run([_ts, "status", "--json"], capture_output=True, timeout=8, creationflags=0x08000000).stdout or b"{}")
            _eu = _st.get("Self") or {}
            ips |= {i for i in (_eu.get("TailscaleIPs") or []) if ":" not in i}
            if _eu.get("DNSName"):
                nomes.add(_eu["DNSName"].rstrip(".").lower())
    except Exception:
        pass
    refazer = True
    if os.path.exists(srv_crt) and os.path.exists(srv_key):
        try:
            atual = x509.load_pem_x509_certificate(open(srv_crt, "rb").read())
            san = atual.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            tem_ips = {str(i) for i in san.get_values_for_type(x509.IPAddress)}
            tem_nomes = set(san.get_values_for_type(x509.DNSName))
            refazer = not ips <= tem_ips or not nomes <= tem_nomes or atual.not_valid_after_utc < agora + datetime.timedelta(days=30)
        except Exception:
            refazer = True
    if refazer:  # IP do PC mudou ou certificado perto de vencer: gera outro (a CA continua a mesma)
        k = ec.generate_private_key(ec.SECP256R1())
        c = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Painel WhatsApp")]))
             .issuer_name(ca_c.subject).public_key(k.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(agora - datetime.timedelta(days=1)).not_valid_after(agora + datetime.timedelta(days=397))
             .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in sorted(nomes)] + [x509.IPAddress(_ip.ip_address(i)) for i in sorted(ips)]), critical=False)
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
             .sign(ca_k, hashes.SHA256()))
        open(srv_key, "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        open(srv_crt, "wb").write(c.public_bytes(serialization.Encoding.PEM) + ca_c.public_bytes(serialization.Encoding.PEM))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(srv_crt, srv_key)
    return ctx


def gerar_senha():
    alfabeto = "abcdefghjkmnpqrstuvwxyz23456789"
    return "-".join("".join(secrets.choice(alfabeto) for _ in range(4)) for _ in range(4))


def senha_confere(senha):
    h = _cfg_painel().get("senha_hash", "")
    try:
        _, it, sal, _dig = h.split("$")
        return hmac.compare_digest(_hash_senha(senha, sal, int(it)), h)
    except ValueError:
        return False


# As sessões ficam salvas em disco (só o hash do token), para o login sobreviver a reinícios do painel.
SESSOES_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sessoes.json")


def _chave(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _marca_senha():
    return hashlib.sha256((_cfg_painel().get("senha_hash") or "").encode()).hexdigest()[:16]


def _sessoes_carregar():
    try:
        with open(SESSOES_JSON, encoding="utf-8") as f:
            _sessoes.update({k: tuple(v) for k, v in json.load(f).items()})
    except (OSError, ValueError):
        pass


def _sessoes_gravar():
    agora = time.time()
    tmp = SESSOES_JSON + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({k: list(v) for k, v in _sessoes.items() if v[0] > agora}, f)
    os.replace(tmp, SESSOES_JSON)


def sessao_valida(token):
    if not token:
        return False
    k, agora = _chave(token), time.time()
    with _acesso_lock:
        s_ = _sessoes.get(k)
        if not s_:
            return False
        if s_[0] < agora or s_[1] != _marca_senha():
            _sessoes.pop(k, None)
            _sessoes_gravar()
            return False
        if s_[0] - agora < SESSAO_SEG - 86400:  # renova o prazo enquanto o aparelho continua usando (no máx. 1x/dia)
            _sessoes[k] = (agora + SESSAO_SEG, s_[1])
            _sessoes_gravar()
        return True


def _bloqueio_anotar(ip, motivo, agora):
    """[segaviso] Chamado com _acesso_lock já preso. Uma entrada por bloqueio (não por tentativa recusada):
    o mesmo aparelho/motivo só conta de novo depois dos 15 min da janela."""
    ip = ip[7:] if ip.startswith("::ffff:") else ip
    _bloqueios[:] = [b for b in _bloqueios if time.time() - b["t"] < 86400][-50:]  # [segpers] relógio real
    if any(b["ip"] == ip and b["motivo"] == motivo and agora - b["t"] < 900 for b in _bloqueios):
        return
    _bloqueios.append({"t": agora, "ip": ip[:45], "motivo": motivo})


def seg_resumo():
    """[segaviso] Resumo para /api/saude: quantos bloqueios em 24 h e o último (sem senha, sem nada da conversa)."""
    agora = time.time()
    with _acesso_lock:
        recentes = [b for b in _bloqueios if agora - b["t"] < 86400]
    if not recentes:
        return None
    u = recentes[-1]
    lt = time.localtime(u["t"])
    try:  # [segvisto] "Entendi" dado em qualquer aparelho vale para todos
        visto = int(estado_ler_cache().get("seg_visto") or 0)
    except Exception:
        visto = 0
    return {"bloqueios": len(recentes), "visto": visto, "ultimo": {"id": int(u["t"]), "hora": time.strftime("%H:%M", lt),
            "data": time.strftime("%d/%m", lt), "hoje": lt[:3] == time.localtime(agora)[:3],
            "ip": u["ip"], "motivo": u["motivo"]}}


def seg_visto_salvar(dados):
    """[segvisto] Guarda no painel_estado o id (hora) do último bloqueio que o operador já viu. Só avança, nunca volta,
    e não aceita id do futuro nem de bloqueio que não existe (evita esconder um aviso que ainda vai acontecer)."""
    try:
        id_ = int(dados.get("id") or 0)
    except (TypeError, ValueError):
        raise ErroEnvio("id inválido")
    with _acesso_lock:
        ids = {int(b["t"]) for b in _bloqueios}
    if id_ not in ids:
        raise ErroEnvio("bloqueio desconhecido")
    with _estado_lock:
        e = estado_ler()
        if id_ > int(e.get("seg_visto") or 0):
            e["seg_visto"] = id_
            estado_gravar(e)
        return {"success": True, "visto": int(e.get("seg_visto") or 0)}


def bloqueios_do_log():
    """[segpers] Na partida, refaz a lista de bloqueios das últimas 24 h a partir do painel_log.txt (e do .1 da
    rotação). Sem isso, reiniciar o painel apagava o aviso de senha errada antes de o operador ver."""
    agora = time.time()
    achados = []
    for arq in (LOG_PAINEL + ".1", LOG_PAINEL):
        try:
            with open(arq, encoding="utf-8", errors="replace") as f:
                for linha in f:
                    if " login_bloqueado " not in linha[:40]:
                        continue
                    p = linha.split()
                    try:
                        t = time.mktime(time.strptime(p[0] + " " + p[1], "%Y-%m-%d %H:%M:%S"))
                    except (ValueError, IndexError):
                        continue
                    if not 0 <= agora - t < 86400:
                        continue
                    campos = dict(x.split("=", 1) for x in p[3:] if "=" in x)
                    ip, motivo = campos.get("ip", ""), campos.get("motivo", "")
                    if ip and motivo in ("aparelho", "geral"):
                        achados.append((t, ip, motivo))
        except OSError:
            pass
    with _acesso_lock:
        for t, ip, motivo in sorted(achados):
            _bloqueio_anotar(ip, motivo, t)
        _bloqueios.sort(key=lambda b: b["t"])
        n = len(_bloqueios)
    return n


def tentar_login(ip, senha):
    """(ok, token|mensagem). Limite: 5 erros por IP em 15 min, 30 no total."""
    agora = time.time()
    with _acesso_lock:
        _falhas[ip] = [t for t in _falhas.get(ip, []) if agora - t < 900]
        _falhas_total[:] = [t for t in _falhas_total if agora - t < 900]
        if len(_falhas[ip]) >= 5 or len(_falhas_total) >= 30:
            registrar("login_bloqueado", ip, repetir=60, motivo="aparelho" if len(_falhas[ip]) >= 5 else "geral")
            _bloqueio_anotar(ip, "aparelho" if len(_falhas[ip]) >= 5 else "geral", agora)
            return False, "Muitas tentativas erradas. Espere 15 minutos."
    if senha and senha_confere(senha):
        token = secrets.token_urlsafe(32)
        with _acesso_lock:
            _falhas.pop(ip, None)
            for t in [t for t, v in _sessoes.items() if v[0] < agora]:
                _sessoes.pop(t, None)
            _sessoes[_chave(token)] = (agora + SESSAO_SEG, _marca_senha())
            _sessoes_gravar()
        registrar("login_ok", ip)
        return True, token
    time.sleep(0.6)
    with _acesso_lock:
        _falhas.setdefault(ip, []).append(agora)
        _falhas_total.append(agora)
        resta = max(0, 5 - len(_falhas[ip]))
    registrar("login_errado", ip, restam=resta)
    return False, f"Senha incorreta. Restam {resta} tentativa(s)."


# ---------- [limite] freio nas APIs de escrita: um script em laço ou aba travada não vira rajada no WhatsApp ----------
# (máximo, janela em s) por aparelho (IP) e por tipo de ação. Folgado para uso humano (álbum de 30 fotos passa);
# o login tem o freio próprio acima, e as campanhas/agendadas não passam por aqui (rodam dentro do painel).
from collections import deque as _deque
LIMITES = {"envio": (60, 60), "upload": (60, 60), "ia": (10, 60), "escrita": (300, 60),
           "busca": (120, 60), "midia": (900, 60)}  # leituras caras, só valem para aparelho de fora do PC
ROTAS_ENVIO = {"/api/enviar", "/api/encaminhar", "/api/reagir", "/api/apagar", "/api/editar", "/api/reenviar-audio",
               "/api/agendar", "/api/historico"}
_ritmo = {}            # (ip, classe) -> horários das últimas chamadas
_ritmo_lock = threading.Lock()


def classe_rota(caminho):
    if caminho == "/api/buscar":
        return "busca"
    if caminho == "/api/midia":
        return "midia"
    if caminho == "/api/upload":
        return "upload"
    if caminho.startswith("/api/ia/"):
        return "ia"
    return "envio" if caminho in ROTAS_ENVIO else "escrita"


def ritmo_espera(ip, caminho, agora=None):
    """0 se a chamada pode seguir (e já fica contada); senão, quantos segundos esperar."""
    classe = classe_rota(caminho)
    maximo, janela = LIMITES[classe]
    agora = time.monotonic() if agora is None else agora
    with _ritmo_lock:
        if len(_ritmo) > 500:  # só IP privado chega aqui, mas não deixa crescer para sempre
            for k in [k for k, v in _ritmo.items() if not v or agora - v[-1] > 120]:
                _ritmo.pop(k, None)
        fila = _ritmo.setdefault((ip, classe), _deque())
        while fila and agora - fila[0] >= janela:
            fila.popleft()
        if len(fila) >= maximo:
            return max(1, int(janela - (agora - fila[0]) + 0.999))
        fila.append(agora)
        return 0


# ---------- [log] registro de segurança: quem bateu na porta, sem nada do que foi conversado ----------
# Uma linha por evento em painel_log.txt: partida, login (certo, errado, bloqueado), saída, troca de senha,
# pedido recusado (IP de fora, Host estranho, origem errada, sem login) e limite de ritmo (429).
# NUNCA entra aqui: texto de mensagem, senha, token de sessão, nome ou número de contato.
LOG_PAINEL = os.environ.get("PAINEL_LOG") or os.path.join(AQUI, "painel_log.txt")
LOG_MAX = 512 * 1024   # ao passar disso vira painel_log.txt.1 (fica só uma geração: no máx. ~1 MB em disco)
_log_lock = threading.Lock()
_log_visto = {}        # (evento, ip, classe) -> [hora do último registro, quantos iguais ficaram de fora]


def _log_limpo(v, n=80):
    """Valor vindo de fora (Host, Origin, caminho) não pode quebrar a linha nem forjar outra entrada."""
    s = "".join(c if c.isprintable() and c not in '"\\' else "?" for c in str(v))
    return s if len(s) <= n else s[:n] + "…"


def registrar(evento, ip="", repetir=0, **campos):
    """Grava um evento. repetir=N: o mesmo evento do mesmo aparelho só volta ao arquivo depois de N segundos,
    levando junto quantos ficaram de fora (um laço de pedidos recusados não enche o disco)."""
    try:
        agora = time.monotonic()
        if ip.startswith("::ffff:"):  # IPv4 que chegou pela escuta IPv6: mostra como o roteador mostra
            ip = ip[7:]
        with _log_lock:
            if repetir:
                chave = (evento, ip, str(campos.get("classe", "")))
                v = _log_visto.get(chave)
                if v and agora - v[0] < repetir:
                    v[1] += 1
                    return
                if len(_log_visto) > 500:
                    for k in [k for k, x in _log_visto.items() if agora - x[0] > 3600]:
                        _log_visto.pop(k, None)
                    if len(_log_visto) > 500:  # 500 aparelhos diferentes em 1 h: recomeça em vez de crescer
                        _log_visto.clear()
                _log_visto[chave] = [agora, 0]
                if v and v[1]:
                    campos["omitidos"] = v[1]
            partes = [time.strftime("%Y-%m-%d %H:%M:%S"), evento]
            if ip:
                partes.append("ip=" + _log_limpo(ip, 45))
            for k, x in campos.items():
                x = _log_limpo(x)
                partes.append(f'{k}="{x}"' if (" " in x or not x) else f"{k}={x}")
            try:
                if os.path.getsize(LOG_PAINEL) > LOG_MAX:
                    os.replace(LOG_PAINEL, LOG_PAINEL + ".1")
            except OSError:
                pass
            with open(LOG_PAINEL, "a", encoding="utf-8") as f:
                f.write(" ".join(partes) + "\n")
    except Exception:
        pass  # o registro nunca pode derrubar um pedido


# ---------- respostas leves: gzip e cache do index (menos bytes no celular e na rede local) ----------
GZIP_TIPOS = ("text/", "application/json", "image/svg+xml")
GZIP_MIN = 1024  # abaixo disso comprimir custa mais do que economiza
_index_cache = {}
_index_lock = threading.Lock()


def comprimir(dados):
    return gzip.compress(dados, 6)


# [enxugar] O index.html leva ~60 KB de comentários (CSS /* */ e linhas // no JS) que o navegador não usa.
# Tirados na hora de servir (uma vez por versão do arquivo, junto com o gzip): ~13 KB gzip a menos no celular
# e nenhum comentário interno exposto. Conservador: só linha inteira de //, nunca dentro de `template`,
# e só quando a linha anterior termina como código. Desliga com PAINEL_ENXUGAR=0.
_ENX_SCRIPT = re.compile(rb"(<script(?![^>]*\bsrc=)[^>]*>)(.*?)(</script>)", re.S)
_ENX_STYLE = re.compile(rb"(<style[^>]*>)(.*?)(</style>)", re.S)
_ENX_LINHA = re.compile(rb"^\s*//(?!#)")
_ENX_ANTES = re.compile(rb"[;{}()\[\],:]\s*$")


def _enx_js(m):
    saida, crase, ant = [], 0, b";"
    for ln in m.group(2).split(b"\n"):
        if crase % 2 == 0 and _ENX_LINHA.match(ln) and (not ant.strip() or _ENX_ANTES.search(ant)):
            continue
        saida.append(ln)
        crase += ln.count(b"`") - ln.count(b"\\`")
        ant = ln
    if crase % 2:
        return m.group(0)  # contagem de crases estranha: devolve o script intacto
    return m.group(1) + b"\n".join(saida) + m.group(3)


def _enx_css(m):
    return m.group(1) + re.sub(rb"/\*.*?\*/", b"", m.group(2), flags=re.S) + m.group(3)


def enxugar_html(corpo):
    if os.environ.get("PAINEL_ENXUGAR", "1") == "0":
        return corpo
    try:
        novo = _ENX_STYLE.sub(_enx_css, corpo)
        novo = _ENX_SCRIPT.sub(_enx_js, novo)
        # Rede de segurança: a quantidade de blocos tem de ser a mesma.
        for rx in (_ENX_SCRIPT, _ENX_STYLE):
            if len(rx.findall(novo)) != len(rx.findall(corpo)):
                return corpo
        return novo
    except Exception:
        return corpo


_DEM_GZ = {}  # etag do demandas.md -> corpo gzip


# Política de segurança de conteúdo (CSP). O script embutido entra por hash, então não precisa de
# 'unsafe-inline': um texto de mensagem que virasse <script> no DOM não roda. O index.html ainda
# traz um <meta> com as diretivas que não dependem de hash, como rede de apoio.
CSP_COMUM = (
    "default-src 'none'; img-src 'self' data: blob:; media-src 'self' blob:; "
    "font-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; "
    "form-action 'self'; base-uri 'none'; object-src 'none'; frame-src 'none'; "
    "worker-src 'none'; manifest-src 'self'; frame-ancestors 'none'"
)
CSP_API = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"
# Só a própria página usa microfone (áudio de voz), câmera (foto) e GPS (enviar localização).
# Nada de pagamento, USB, gravação de tela ou sensores, aqui nem em quadro embutido.
POLITICA_PERMISSOES = (
    "accelerometer=(), camera=(self), display-capture=(), geolocation=(self), gyroscope=(), "
    "magnetometer=(), microphone=(self), midi=(), payment=(), usb=()"
)


def csp_com_scripts(html):
    """CSP_COMUM + script-src com o sha256 de cada <script> embutido do HTML."""
    if isinstance(html, str):
        html = html.encode("utf-8")
    fontes = []
    for m in re.finditer(rb"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S):
        # O navegador normaliza CRLF/CR para LF antes de calcular o hash do script.
        corpo = re.sub(rb"\r\n?", b"\n", m.group(1))
        h = base64.b64encode(hashlib.sha256(corpo).digest()).decode("ascii")
        fontes.append("'sha256-%s'" % h)
    return "script-src %s; %s" % (" ".join(fontes) or "'none'", CSP_COMUM)


def index_html():
    """(corpo, corpo_gzip, etag, csp) do index.html; só relê, recomprime e re-hasheia quando muda."""
    caminho = os.path.join(AQUI, "index.html")
    st = os.stat(caminho)
    chave = (st.st_mtime_ns, st.st_size)
    with _index_lock:
        if _index_cache.get("chave") == chave:
            return (_index_cache["corpo"], _index_cache["gz"],
                    _index_cache["etag"], _index_cache["csp"])
    with open(caminho, "rb") as f:
        corpo = enxugar_html(f.read())  # [enxugar]
    gz = comprimir(corpo)
    etag = '"%x-%x"' % (st.st_mtime_ns, st.st_size)
    csp = csp_com_scripts(corpo)
    with _index_lock:
        _index_cache.update(chave=chave, corpo=corpo, gz=gz, etag=etag, csp=csp)
    return corpo, gz, etag, csp


# ---------- cache de avatar: memória + disco + ETag (foto repetida não vai à ponte nem desce de novo) ----------
# A ponte já guarda as fotos em disco, mas cada pedido do painel abria uma conexão nova para ela
# (~150 ms por foto, e são ~160 numa carga de lista). Aqui a foto fica na memória do painel e também
# em painel\cache\avatares, para continuar rápida depois de reiniciar. O ETag deixa o navegador
# revalidar sem baixar os bytes de novo (304) quando o max-age de 6 h vence.
AVATAR_DIR = os.path.join(AQUI, "cache", "avatares")
AVATAR_TTL = 6 * 3600        # foto guardada: só pergunta à ponte de novo depois disso
AVATAR_TTL_VAZIO = 3600      # contato sem foto: tenta de novo em 1 h (a ponte lembra por 24 h)
AVATAR_MAX_MEM = 500         # fotos na memória (~3 KB cada); acima disso saem as mais antigas
AVATAR_IDADE_MAX = 30 * 86400  # arquivo de cache não tocado nesse tempo é apagado na partida
_avatares = {}               # jid -> (bytes|None, etag|None, quando)
_avatar_lock = threading.Lock()
_avatar_locks = {}
# [fotosh2] no máximo 3 idas à ponte ao mesmo tempo para buscar foto (o navegador pede até 6 por vez em HTTP/2;
# acertos de memória/disco não passam por aqui, só o que precisa perguntar ao WhatsApp)
_avatar_ponte_sem = threading.BoundedSemaphore(3)


class AvatarErro(Exception):
    """Falha ao buscar a foto, sem nada guardado para mostrar no lugar."""

    def __init__(self, code, texto):
        super().__init__(texto)
        self.code = code
        self.texto = texto


def _avatar_cadeado(jid):
    """Um cadeado por contato: dois pedidos da mesma foto não viram duas consultas à ponte."""
    with _avatar_lock:
        lk = _avatar_locks.get(jid)
        if lk is None:
            if len(_avatar_locks) > 2000:
                _avatar_locks.clear()
            lk = _avatar_locks[jid] = threading.Lock()
        return lk


def _avatar_caminhos(jid):
    nome = hashlib.sha256(jid.encode("utf-8")).hexdigest()[:32]  # nome derivado: nada de jid no caminho
    return os.path.join(AVATAR_DIR, nome + ".jpg"), os.path.join(AVATAR_DIR, nome + ".vazio")


def _avatar_ttl(dados):
    return AVATAR_TTL if dados else AVATAR_TTL_VAZIO


def _avatar_guardar(jid, dados, quando=None):
    """Põe na memória e devolve (bytes|None, etag|None)."""
    quando = quando or time.time()
    etag = ('"a%s"' % hashlib.sha256(dados).hexdigest()[:20]) if dados else None
    with _avatar_lock:
        _avatares[jid] = (dados, etag, quando)
        if len(_avatares) > AVATAR_MAX_MEM:
            sobra = len(_avatares) - AVATAR_MAX_MEM
            for velho in sorted(_avatares, key=lambda k: _avatares[k][2])[:sobra]:
                _avatares.pop(velho, None)
    return dados, etag


def _avatar_do_disco(jid):
    """(bytes|None, quando). quando=0 quer dizer "nada guardado"; (None, quando) é "sem foto"."""
    jpg, vazio = _avatar_caminhos(jid)
    try:
        st = os.stat(jpg)
        with open(jpg, "rb") as f:
            return f.read(), st.st_mtime
    except OSError:
        pass
    try:
        return None, os.stat(vazio).st_mtime
    except OSError:
        return None, 0.0


def _avatar_no_disco(jid, dados):
    """Grava a foto (ou a marca de "sem foto") em cache\avatares. Falhar aqui não atrapalha o pedido."""
    jpg, vazio = _avatar_caminhos(jid)
    quero, sobra = (jpg, vazio) if dados else (vazio, jpg)
    try:
        os.makedirs(AVATAR_DIR, exist_ok=True)
        tmp = quero + ".tmp"
        with open(tmp, "wb") as f:
            f.write(dados or b"")
        os.replace(tmp, quero)
        try:
            os.remove(sobra)  # foto nova apaga o "sem foto" e vice-versa
        except OSError:
            pass
    except OSError:
        pass


def avatar_limpar_antigos():
    """Na partida: apaga do cache em disco o que ninguém pediu no último mês."""
    try:
        agora, apagados = time.time(), 0
        for nome in os.listdir(AVATAR_DIR):
            caminho = os.path.join(AVATAR_DIR, nome)
            try:
                if agora - os.stat(caminho).st_mtime > AVATAR_IDADE_MAX:
                    os.remove(caminho)
                    apagados += 1
            except OSError:
                pass
        return apagados
    except OSError:
        return 0


def avatar_aquecer():
    """Na partida: carrega para a memória as fotos do disco das conversas mais recentes (no prazo ou não).
    Só lê disco; as vencidas das mais recentes vão para a fila de renovação (1 por vez) depois de 20 s."""
    try:
        db = ro(MSG_DB)
        jids = [r[0] for r in db.execute(
            "select jid from chats order by last_message_time desc limit ?", (AVATAR_MAX_MEM,))]
        db.close()
    except Exception:
        return 0
    # [aqvenc] as vencidas também vão para a memória (a 1ª lista não lê o disco de novo) e as das conversas
    # mais recentes já entram na fila de renovação, devagar, depois que a ponte teve tempo de conectar
    n, agora, vencidas = 0, time.time(), []
    for jid in jids:
        try:
            dados, quando = _avatar_do_disco(jid)
            if not quando:
                continue
            _avatar_guardar(jid, dados, quando)
            n += 1
            if agora - quando >= _avatar_ttl(dados) and len(vencidas) < AVATAR_AQUECER_RENOVA:
                vencidas.append(jid)
        except Exception:
            pass
    if vencidas:
        def _renovar():
            time.sleep(AVATAR_AQUECER_ESPERA)
            for j in vencidas:
                _avatar_renovar_depois(j)
        threading.Thread(target=_renovar, name="fotos-aquecer", daemon=True).start()
    return n


AVATAR_AQUECER_RENOVA = 80    # vencidas das conversas mais recentes renovadas na partida (~0,6 s cada na ponte)
AVATAR_AQUECER_ESPERA = 20    # segundos antes de começar (a ponte pode estar reconectando)


# [fotoswr] foto vencida não segura a lista: devolve a que já tem (memória ou disco) na hora e renova por trás,
# numa fila de 1 só trabalhador (a ponte faz 1 consulta por vez ao WhatsApp de qualquer jeito). Só espera a ponte
# quem nunca teve foto guardada. Falha na renovação: não tenta de novo por 10 min.
import queue as _fotos_q
_avatar_fila = _fotos_q.Queue()
_avatar_na_fila = set()
_avatar_falha = {}            # jid -> quando a última renovação falhou
_avatar_trab = []
AVATAR_ESPERA_FALHA = 600
AVATAR_FILA_MAX = 1000


def _avatar_da_ponte(jid, velho, quando, _conferir=False):
    """Pergunta à ponte e guarda. Devolve (bytes|None, etag|None, fonte) ou levanta AvatarErro."""
    try:
        url = PONTE + "/api/avatar?jid=" + quote(jid) + ("&refresh=1" if _conferir else "")
        with _avatar_ponte_sem, urllib.request.urlopen(url, timeout=20) as r:
            novo = r.read()
        d, etag = _avatar_guardar(jid, novo)
        _avatar_no_disco(jid, novo)
        return d, etag, "ponte"
    except urllib.error.HTTPError as e:
        # [404conf] depois de um erro passageiro a ponte grava um marcador e responde 404 por 10 min, igual a
        # "sem foto". Se o painel tem foto guardada, confere uma vez direto no WhatsApp (refresh=1) antes de apagá-la:
        # 404 de novo = o contato tirou a foto mesmo; erro = mostra a antiga e tenta mais tarde.
        if e.code == 404 and velho and not _conferir:
            return _avatar_da_ponte(jid, velho, quando, _conferir=True)
        if e.code == 404:  # sem foto, ou foto que o contato não mostra
            _avatar_guardar(jid, None)
            _avatar_no_disco(jid, None)
            return None, None, "ponte"
        if quando:  # ponte reclamando: mostra o que já tinha
            d, etag = _avatar_guardar(jid, velho, quando)
            return d, etag, "antigo"
        raise AvatarErro(502, "erro na ponte")
    except Exception:
        if quando:  # ponte fora do ar: foto antiga é melhor do que buraco na lista
            d, etag = _avatar_guardar(jid, velho, quando)
            return d, etag, "antigo"
        raise AvatarErro(503, "ponte indisponível")


def _avatar_trabalhador():
    while True:
        jid = _avatar_fila.get()
        try:
            with _avatar_cadeado(jid):
                with _avatar_lock:
                    g = _avatares.get(jid)
                if g and time.time() - g[2] < _avatar_ttl(g[0]):
                    continue  # alguém já renovou
                velho, quando = _avatar_do_disco(jid)
                _d, _e, fonte = _avatar_da_ponte(jid, velho, quando)
                if fonte == "antigo":
                    _avatar_falha[jid] = time.time()
                else:
                    _avatar_falha.pop(jid, None)
        except Exception:
            _avatar_falha[jid] = time.time()
        finally:
            with _avatar_lock:
                _avatar_na_fila.discard(jid)


# [semponte] canais (@newsletter), status@broadcast e jids sem número ("0@s...") nunca têm resposta da ponte:
# cada pedido estourava os 15 s dela, segurando a fila de fotos (1 por vez), e voltava a cada 10 min.
def _avatar_sem_ponte(jid):
    u, _, srv = (jid or "").partition("@")
    u = u.split(":")[0]
    return srv in ("newsletter", "broadcast") or not u.isdigit() or not u.strip("0")


def _avatar_renovar_depois(jid):
    if _avatar_sem_ponte(jid):
        return
    if time.time() - _avatar_falha.get(jid, 0) < AVATAR_ESPERA_FALHA:
        return
    with _avatar_lock:
        if jid in _avatar_na_fila or len(_avatar_na_fila) >= AVATAR_FILA_MAX:
            return
        _avatar_na_fila.add(jid)
        if not _avatar_trab:
            t = threading.Thread(target=_avatar_trabalhador, name="fotos-renovar", daemon=True)
            _avatar_trab.append(t)
            t.start()
    _avatar_fila.put(jid)


def avatar(jid):
    """(bytes|None, etag|None, fonte) da foto do contato; None nos bytes = contato sem foto."""
    if _avatar_sem_ponte(jid):
        return None, None, "sem"
    with _avatar_lock:
        guardado = _avatares.get(jid)
    if guardado:
        if time.time() - guardado[2] >= _avatar_ttl(guardado[0]):
            _avatar_renovar_depois(jid)  # vencida: mostra a que tem e renova por trás
            return guardado[0], guardado[1], "vencida"
        return guardado[0], guardado[1], "memoria"
    with _avatar_cadeado(jid):
        with _avatar_lock:  # outra thread pode ter buscado enquanto esperávamos o cadeado
            guardado = _avatares.get(jid)
        if guardado:
            return guardado[0], guardado[1], "memoria"
        velho, quando = _avatar_do_disco(jid)
        if quando:
            d, etag = _avatar_guardar(jid, velho, quando)
            if time.time() - quando >= _avatar_ttl(velho):
                _avatar_renovar_depois(jid)
                return d, etag, "vencida"
            return d, etag, "disco"
        return _avatar_da_ponte(jid, velho, quando)


def avatar_completo(jid):
    """Foto maior fornecida pelo WhatsApp, com cache separado da miniatura."""
    if _avatar_sem_ponte(jid):
        return None, None, "sem"
    chave = jid + ":completo"
    with _avatar_cadeado(chave):
        velho, quando = _avatar_do_disco(chave)
        if quando and time.time() - quando < _avatar_ttl(velho):
            dados, etag = _avatar_guardar(chave, velho, quando)
            return dados, etag, "completo-cache"
        try:
            with _avatar_ponte_sem:
                with urllib.request.urlopen(PONTE + "/api/avatar?info=1&jid=" + quote(jid), timeout=20) as r:
                    info = json.load(r)
                if not info.get("success") or not info.get("url"):
                    raise AvatarErro(404, "foto maior indisponível")
                url = info["url"]
                u = urlparse(url)
                host = (u.hostname or "").lower()
                if u.scheme != "https" or not any(host == d or host.endswith("." + d) for d in ("whatsapp.net", "fbcdn.net")):
                    raise AvatarErro(502, "endereço de foto inválido")
                with urllib.request.urlopen(url, timeout=20) as r:
                    dados = r.read(5 * 1024 * 1024 + 1)
                if not dados or len(dados) > 5 * 1024 * 1024:
                    raise AvatarErro(502, "foto inválida")
                from PIL import Image
                import io
                with Image.open(io.BytesIO(dados)) as img:
                    img.verify()
            _avatar_no_disco(chave, dados)
            dados, etag = _avatar_guardar(chave, dados)
            return dados, etag, "completo"
        except Exception:
            if velho:
                dados, etag = _avatar_guardar(chave, velho, quando)
                return dados, etag, "completo-antigo"
            # Sem foto maior disponível, mantém a foto atual e tenta novamente em 10 min.
            dados, etag, _ = avatar(jid)
            _avatar_no_disco(chave, dados)
            caminho = _avatar_caminhos(chave)[0 if dados else 1]
            try:
                t = time.time() - _avatar_ttl(dados) + 600
                os.utime(caminho, (t, t))
            except OSError:
                pass
            return dados, etag, "miniatura"


PAGINA_LOGIN = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Entrar · Painel WhatsApp</title><style>
:root{--f:#efeae2;--c:#fff;--t:#111b21;--s:#667781;--v:#008069;--e:#d93025}
@media (prefers-color-scheme:dark){:root{--f:#0b141a;--c:#202c33;--t:#e9edef;--s:#8696a0;--v:#00a884;--e:#f15c6d}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--f);color:var(--t);font:15px/1.4 "Segoe UI",Helvetica,Arial,sans-serif;padding:16px}
form{background:var(--c);border-radius:14px;padding:28px 24px;width:100%;max-width:360px;box-shadow:0 2px 12px rgba(0,0,0,.15)}
h1{font-size:20px;margin:0 0 4px}p{color:var(--s);margin:0 0 18px;font-size:14px}
input{width:100%;padding:12px 14px;border:1px solid rgba(127,127,127,.4);border-radius:10px;background:transparent;color:var(--t);font:inherit;font-size:16px;margin-bottom:12px}
button{width:100%;padding:12px;border:0;border-radius:24px;background:var(--v);color:#fff;font:inherit;font-weight:600;cursor:pointer}
#erro{color:var(--e);font-size:13.5px;min-height:20px;margin:-4px 0 8px}</style></head><body>
<form id="f"><h1>🔒 Painel WhatsApp</h1><p>Digite a senha de acesso pela rede (está no arquivo ACESSO.txt do computador).</p>
<input id="senha" type="password" autocomplete="current-password" placeholder="Senha" autofocus required>
<div id="erro"></div><button>Entrar</button></form>
<script>
document.getElementById("f").onsubmit = async e => { e.preventDefault(); const b = e.target.querySelector("button"); b.disabled = true;
  try { const r = await fetch("/api/login", {method: "POST", headers: {"Content-Type": "application/json", "X-Painel": "1"}, body: JSON.stringify({senha: document.getElementById("senha").value})});
    const j = await r.json(); if(j.success){ location.href = "/"; return; } document.getElementById("erro").textContent = j.erro || "Não foi possível entrar"; }
  catch(err){ document.getElementById("erro").textContent = "Sem conexão com o painel"; }
  b.disabled = false; document.getElementById("senha").select(); };
</script></body></html>"""

CSP_LOGIN = csp_com_scripts(PAGINA_LOGIN)
UPLOADS = os.path.join(AQUI, "uploads")
MAX_UPLOAD = 200 * 1024 * 1024
DRYRUN = os.environ.get("PAINEL_DRYRUN") == "1"


def ro(path):
    c = sqlite3.connect("file:" + path.replace("\\", "/") + "?mode=ro", uri=True, timeout=5)
    return c


def config():
    cfg = {"ignorar_grupos_com": [], "ignorar_jids": ["status@broadcast"]}
    try:
        if os.path.exists(CONFIG):
            c = _json_arq(CONFIG)  # [perf-patch v1] só lido (não alterado)
            for k in cfg:
                if isinstance(c.get(k), list):
                    cfg[k] = c[k]
    except Exception:
        pass
    return cfg


# ---- nomes de contatos (mesma lógica do novas.py) ----
_nomes_cache = {"t": 0, "nomes": {}, "lid2pn": {}}
_lock = threading.Lock()


def carregar_nomes():
    import time
    with _lock:
        marca = _marca_wa_db()
        if _nomes_cache.get("marca") == marca and time.time() - _nomes_cache["t"] < 60:
            return _nomes_cache["nomes"], _nomes_cache["lid2pn"]
        nomes, lid2pn = {}, {}
        try:
            wa = ro(WA_DB)
            lid2pn = {l: p for l, p in wa.execute("select lid, pn from whatsmeow_lid_map")}
            for jid, first, full, push, biz in wa.execute(
                    "select their_jid, first_name, full_name, push_name, business_name from whatsmeow_contacts"):
                n = full or push or biz or first
                if n:
                    nomes[jid.split("@")[0]] = n
            wa.close()
            for lid, pn in lid2pn.items():
                if pn in nomes and lid not in nomes:
                    nomes[lid] = nomes[pn]
                if lid in nomes and pn not in nomes:
                    nomes[pn] = nomes[lid]
        except Exception:
            pass
        _nomes_cache.update(t=time.time(), marca=marca, nomes=nomes, lid2pn=lid2pn)
        return nomes, lid2pn


def nome(jid, nomes, lid2pn):
    u = (jid or "").split("@")[0].split(":")[0]
    if not u:
        return ""
    return nomes.get(u) or (("+" + lid2pn[u]) if u in lid2pn else ("+" + u if u.isdigit() else u))


def nome_chat(jid, nome_db, nomes, lid2pn):
    if jid.endswith("@g.us"):
        return nome_db or jid
    if nome_db and not nome_db.isdigit():
        return nome_db
    return nome(jid, nomes, lid2pn)


def tipo_chat(jid):
    if jid.endswith("@g.us"):
        return "grupo"
    if jid.endswith("@newsletter"):
        return "canal"
    if jid.endswith("@broadcast"):
        return "broadcast"
    return "individual"


def oculto(jid, titulo, cfg):
    if jid in cfg["ignorar_jids"] or jid.endswith("@newsletter") or jid == "status@broadcast":
        return True
    t = (titulo or "").lower()
    return jid.endswith("@g.us") and any(p.lower() in t for p in cfg["ignorar_grupos_com"])


# ---- API ----
# ---------- estado local do painel: até onde cada conversa foi vista e quais estão silenciadas ----------
ESTADO = os.path.join(AQUI, "painel_estado.json")
_estado_lock = threading.Lock()


def estado_ler():
    """Lê o estado para ALTERAR e gravar. Nunca devolve {} por causa de um erro de leitura: um {} aqui, seguido de
    estado_gravar(), apagaria etiquetas, fichas, campanhas e rascunhos. Tenta de novo, depois usa a cópia .bak e,
    se nada servir, levanta erro (a gravação não acontece)."""
    e, erro = None, None
    for _ in range(4):
        try:
            with open(ESTADO, encoding="utf-8") as f:
                e = json.load(f)
            if isinstance(e, dict):
                break
            e, erro = None, ValueError("estado não é um objeto")
        except FileNotFoundError:
            e = {}
            break
        except (OSError, ValueError) as ex:
            erro = ex
            time.sleep(0.05)
    if e is None:
        try:
            with open(ESTADO + ".bak", encoding="utf-8") as f:
                e = json.load(f)
            if not isinstance(e, dict):
                raise ValueError("bak inválido")
            print("[estado] painel_estado.json ilegível (%s): usando a cópia .bak" % erro, flush=True)
        except (OSError, ValueError):
            raise RuntimeError("painel_estado.json ilegível e sem cópia: gravação recusada para não perder dados (%s)" % erro)
    e.setdefault("vistos", {})
    e.setdefault("silenciados", [])
    return e


def estado_gravar(e):
    tmp = ESTADO + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(e, f, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    try:  # guarda a versão anterior (se for íntegra) antes de trocar: é de onde estado_ler() se recupera
        with open(ESTADO, encoding="utf-8") as f:
            json.load(f)
        shutil.copyfile(ESTADO, ESTADO + ".bak")
    except (OSError, ValueError):
        pass
    os.replace(tmp, ESTADO)
    with _arq_lock:  # [perf-patch v1] a próxima leitura já vê o que foi gravado
        _arq_cache.pop(ESTADO, None)


def estado_ler_cache():
    """[perf-patch v1] Igual a estado_ler(), mas sem reler o arquivo a cada chamada. SÓ LEITURA: não alterar o
    objeto devolvido (quem vai alterar e gravar continua usando estado_ler() dentro do _estado_lock)."""
    try:
        e = _json_arq(ESTADO)
    except (OSError, ValueError):
        e = {}
    if not isinstance(e, dict):
        return estado_ler()
    if "vistos" not in e or "silenciados" not in e:
        e = dict(e)
        e.setdefault("vistos", {})
        e.setdefault("silenciados", [])
    return e


def marcar_visto(jid):
    """Zera as não lidas: guarda o horário da última mensagem de cada chat da conversa."""
    db = ro(MSG_DB)
    tss = {j: str((db.execute("select max(timestamp) from messages where chat_jid=?", (j,)).fetchone() or [""])[0] or "")
           for j in jids_da_conversa(jid)}
    db.close()
    with _estado_lock:
        e = estado_ler()
        mudou = False
        for j, ts in tss.items():
            if ts and ts > e["vistos"].get(j, ""):
                e["vistos"][j] = ts
                mudou = True
        if mudou:
            estado_gravar(e)
    return {"success": True, "visto": max(tss.values(), default="")}


def silenciar(dados):
    jid = str(dados.get("jid") or "")
    if not jid or not jid_conhecido(jid):
        raise ErroEnvio("conversa desconhecida")
    with _estado_lock:
        e = estado_ler()
        sil = set(e["silenciados"])
        sil.add(jid) if dados.get("mudo") else sil.discard(jid)
        e["silenciados"] = sorted(sil)
        estado_gravar(e)
    return {"success": True, "mudo": jid in sil}


def rascunho_chat_salvar(dados):
    """Rascunho digitado por conversa, igual em todos os aparelhos (estado["rascunhos_chat"]). Só guarda texto; não envia nada."""
    jid = str(dados.get("jid") or "")
    if not jid or len(jid) > 120 or not jid_conhecido(jid):
        raise ErroEnvio("conversa desconhecida")
    t = str(dados.get("t") or "")[:4000]
    try:
        em = int(dados.get("em") or 0)
    except (TypeError, ValueError):
        em = 0
    em = em if 0 < em <= int(time.time() * 1000) + 60000 else int(time.time() * 1000)
    with _estado_lock:
        e = estado_ler()
        r = e.setdefault("rascunhos_chat", {})
        atual = r.get(jid)
        if atual and int(atual.get("em") or 0) > em:  # outro aparelho escreveu depois: vale o mais novo
            return {"success": True, "t": atual.get("t", ""), "em": atual.get("em")}
        if t.strip():
            r[jid] = {"t": t, "em": em}
        else:
            r.pop(jid, None)
        corte = int(time.time() * 1000) - 30 * 86400000
        for k in [k for k, v in r.items() if int((v or {}).get("em") or 0) < corte]:
            r.pop(k, None)
        for k in sorted(r, key=lambda k: int(r[k].get("em") or 0), reverse=True)[60:]:
            r.pop(k, None)
        estado_gravar(e)
    return {"success": True}


def contar_naolidas(db):
    """Mensagens recebidas depois da última resposta do operador e depois da última vez que a conversa foi aberta no painel
    (só dos últimos 7 dias, para conversas antigas não aparecerem como não lidas)."""
    piso = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 7 * 86400))
    vistos = estado_ler_cache()["vistos"]
    # [perf-patch v1] uma linha por conversa (em vez de milhares de mensagens para o Python): para cada chat, conta as
    # recebidas depois do maior entre piso, "visto no painel" e a última resposta do operador (só olha a janela de 7 dias,
    # pelo índice idx_messages_chat_ts que a ponte já cria). Mesmo resultado da consulta antiga para os chats da tabela chats
    # (os únicos que o api_chats usa). Se o SQLite não tiver json_each, cai na consulta antiga.
    try:
        return {cj: n for cj, n in db.execute("""
            with v(k, t) as materialized (select key, value from json_each(?))
            select c.jid, (select count(*) from messages m where m.chat_jid = c.jid and m.is_from_me = 0
                             and (coalesce(m.media_type, '') <> 'call' or m.extra like '%"status":"missed"%')
                             and m.timestamp > max(?, coalesce(v.t, ''),
                                 coalesce((select x.timestamp from messages x where x.chat_jid = c.jid and x.is_from_me = 1
                                           and x.timestamp > ? order by x.timestamp desc limit 1), '')))
            from chats c left join v on v.k = c.jid""", (json.dumps(vistos), piso, piso)) if n}
    except sqlite3.Error:
        pass
    cont = {}
    for cj, ts in db.execute("""
            select m.chat_jid, m.timestamp from messages m
            left join (select chat_jid, max(timestamp) t from messages where is_from_me=1 group by chat_jid) e
              on e.chat_jid = m.chat_jid
            where m.is_from_me = 0 and m.timestamp > ? and (e.t is null or m.timestamp > e.t)
              and (coalesce(m.media_type, '') <> 'call' or m.extra like '%"status":"missed"%')""", (piso,)):
        if str(ts) > vistos.get(cj, ""):
            cont[cj] = cont.get(cj, 0) + 1
    return cont


# ---------- conversas duplicadas (@lid + número): mostradas como uma só ----------
_alias_cache = {"t": 0, "de": {}, "para": {}}


def aliases():
    """{jid_canônico: [jids extras]} e {jid_extra: jid_canônico}. O canônico é o chat pelo número."""
    marca = (_marca_db(), _marca_wa_db())
    if _alias_cache.get("marca") == marca and time.time() - _alias_cache["t"] < 60:
        return _alias_cache["de"], _alias_cache["para"]
    _, lid2pn = carregar_nomes()
    de, para = {}, {}
    try:
        db = ro(MSG_DB)
        chats = {j for (j,) in db.execute("select jid from chats")}
        db.close()
        for j in chats:
            if j.endswith("@lid"):
                pn = lid2pn.get(j.split("@")[0])
                if pn and pn + "@s.whatsapp.net" in chats:
                    de.setdefault(pn + "@s.whatsapp.net", []).append(j)
                    para[j] = pn + "@s.whatsapp.net"
    except sqlite3.Error:
        pass
    _alias_cache.update(t=time.time(), marca=marca, de=de, para=para)
    return de, para


def jids_da_conversa(jid):
    de, para = aliases()
    canon = para.get(jid, jid)
    return [canon] + de.get(canon, [])


# ---------- presença, informações do contato/grupo e busca global ----------
def ponte_get(rota, timeout=20):
    with urllib.request.urlopen(PONTE + rota, timeout=timeout) as r:
        return json.load(r)


def api_vivo():
    """Quem está digitando/gravando e quem está online, já com os chats juntados e nomes."""
    try:
        d = ponte_get("/api/live", timeout=5)
    except Exception:
        return {"digitando": {}, "presenca": {}}
    nomes, lid2pn = carregar_nomes()
    para = aliases()[1]
    dig = {}
    for chat, t in (d.get("typing") or {}).items():
        dig[para.get(chat, chat)] = {"midia": t.get("media") or "", "quem": nome(t.get("sender") or "", nomes, lid2pn)}
    pres = {}
    for j, p_ in (d.get("presence") or {}).items():
        info = {"online": bool(p_.get("online")), "visto": p_.get("last_seen") or ""}
        pres[para.get(j, j)] = info
        u = j.split("@")[0]
        if j.endswith("@lid") and u in lid2pn:  # presença chega pelo LID; o chat pode estar pelo número
            pres.setdefault(lid2pn[u] + "@s.whatsapp.net", info)
    cham = []  # [chamadas] tocando agora (o painel só avisa; atender é no celular)
    for ch in (d.get("calls") or []):
        cj = str(ch.get("chat") or "")
        if not cj or ch.get("from_me"):
            continue
        item = {"id": str(ch.get("id") or ""), "jid": para.get(cj, cj), "video": bool(ch.get("video")),
                "grupo": cj.endswith("@g.us") or bool(ch.get("group")), "nome": nome(str(ch.get("from") or ""), nomes, lid2pn)}
        if cj.endswith("@g.us"):
            try:
                db = ro(MSG_DB)
                r = db.execute("select name from chats where jid=?", (cj,)).fetchone()
                db.close()
                item["grupo_nome"] = (r[0] if r else "") or ""
            except sqlite3.Error:
                pass
        cham.append(item)
    return {"digitando": dig, "presenca": pres, "chamadas": cham}


def presenca(dados):
    estado = str(dados.get("estado") or "")
    if estado not in ("composing", "recording", "paused", "available", "unavailable", "subscribe"):
        raise ErroEnvio("estado inválido")
    jid = str(dados.get("jid") or "")
    if estado == "subscribe":
        if not jid_conhecido(jid) or not jid.endswith(("@s.whatsapp.net", "@lid")):
            return {"success": False}
        return chamar_ponte("/api/subscribe", {"jid": jid}, timeout=15)
    if estado in ("composing", "recording", "paused") and not jid_conhecido(jid):
        raise ErroEnvio("conversa desconhecida")
    if DRYRUN or dados.get("dry_run"):
        return {"success": True, "dry_run": True}
    return chamar_ponte("/api/presence", {"chat_jid": jid, "state": estado}, timeout=15)


def api_info(jid):
    if not jid_conhecido(jid):
        return {"success": False, "erro": "conversa desconhecida"}
    nomes, lid2pn = carregar_nomes()
    try:
        if jid.endswith("@g.us"):
            d = ponte_get("/api/group?jid=" + quote(jid))
            for pa in d.get("participants") or []:
                if not pa.get("name") or pa.get("name", "").isdigit():
                    pa["name"] = nome(pa.get("phone") or pa.get("jid") or "", nomes, lid2pn)
            return d
        return ponte_get("/api/contact?jid=" + quote(jid))
    except Exception as e:
        return {"success": False, "erro": str(e)}


def api_buscar(q, limite=60, ocultos=False):
    q = (q or "").strip()
    if len(q) < 2:
        return []
    nomes, lid2pn = carregar_nomes()
    para = aliases()[1]
    cfg = config()  # [autonomia] conversas ocultas (grupos ignorados, canais...) ficam fora da busca
    db = ro(MSG_DB)
    nomes_chat = {j: n for j, n in db.execute("select jid, name from chats")}
    padrao = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    rows = db.execute("""select id, chat_jid, sender, content, timestamp, is_from_me from messages
                         where content like ? escape '\\' and coalesce(revoked, 0) = 0 order by timestamp desc limit ?""", (padrao, limite * 3)).fetchall()
    achados = [(mid, cj, snd, content, ts, me, False) for mid, cj, snd, content, ts, me in rows]
    if os.path.exists(TRANS_DB):  # [autonomia] áudios: procura também na transcrição
        try:
            t = ro(TRANS_DB)
            trs = t.execute("""select id, chat_jid, texto from transcricoes where texto like ? escape '\\'
                               order by timestamp desc limit ?""", (padrao, limite * 2)).fetchall()
            t.close()
            for mid, cj, tx in trs:
                r = db.execute("select sender, timestamp, is_from_me from messages where id=? and chat_jid=? and coalesce(revoked, 0) = 0",
                               (mid, cj)).fetchone()
                if r:
                    achados.append((mid, cj, r[0], "🎤 " + (tx or ""), r[1], r[2], True))
        except Exception:
            pass
    db.close()
    achados.sort(key=lambda x: str(x[4] or ""), reverse=True)
    out, vistos = [], set()
    for mid, cj, snd, content, ts, me, aud in achados:
        canon = para.get(cj, cj)
        titulo = nome_chat(canon, nomes_chat.get(canon, ""), nomes, lid2pn)
        if (mid, cj) in vistos or (not ocultos and oculto(canon, titulo, cfg)):
            continue
        vistos.add((mid, cj))
        out.append({"id": mid, "jid": canon, "chat_real": cj, "nome": titulo, "audio": aud,
                    "quem": "Você" if me else nome(snd, nomes, lid2pn), "texto": (content or "")[:300], "hora": str(ts or "")})
        if len(out) >= limite:
            break
    return out


# ---------- vigia da ponte: mostra no painel quando cai e religa sozinho se o processo morrer ----------
VBS_PONTE = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup\WhatsApp Ponte.vbs")
saude = {"ponte": True, "conectado": True, "falhas": 0, "desde": "", "religou_em": "", "verificado": ""}


def _vigiar_ponte():
    ultimo_religar = 0.0
    while True:
        agora = time.time()
        try:
            d = ponte_get("/api/me", timeout=5)
            if not saude["ponte"] or not saude["conectado"]:
                saude["desde"] = ""
            saude.update(ponte=True, conectado=bool(d.get("connected")), falhas=0)
            if not saude["conectado"] and not saude["desde"]:
                saude["desde"] = time.strftime("%H:%M")
        except Exception:
            if saude["ponte"]:
                saude["desde"] = time.strftime("%H:%M")
            saude.update(ponte=False, conectado=False, falhas=saude["falhas"] + 1)
            # processo fora do ar por ~1,5 min: liga de novo (no máximo a cada 5 min)
            if saude["falhas"] >= 3 and agora - ultimo_religar > 300 and os.path.exists(VBS_PONTE):
                import subprocess
                try:
                    subprocess.Popen(["wscript.exe", VBS_PONTE], close_fds=True)
                    ultimo_religar = agora
                    saude["religou_em"] = time.strftime("%H:%M")
                except OSError:
                    pass
        try:
            saude["qr"] = os.path.exists(QR_PNG) and time.time() - os.path.getmtime(QR_PNG) < 120
        except OSError:
            saude["qr"] = False
        saude["verificado"] = time.strftime("%H:%M:%S")
        time.sleep(30 if not saude.get("qr") else 5)


def favoritar(dados):
    """⭐ marca/desmarca uma mensagem como favorita."""
    jid, mid, conversa = str(dados.get("jid") or ""), str(dados.get("id") or ""), str(dados.get("conversa") or "")
    if not jid or not mid:
        raise ErroEnvio("mensagem desconhecida")
    eu = False
    if dados.get("sim"):  # favoritar exige a mensagem no banco; desfavoritar não (ela pode ter sumido do banco)
        eu, _ = _msg_existe(jid, mid)
    para_ = aliases()[1]  # a favorita abre sempre no chat canônico (número), não no @lid juntado a ele
    conversa = para_.get(conversa, conversa) if conversa and jid_conhecido(conversa) else para_.get(jid, jid)
    with _estado_lock:
        e = estado_ler()
        favs = [f for f in e.get("favoritas", []) if not (f["id"] == mid and f["jid"] == jid)]
        if dados.get("sim"):
            db = ro(MSG_DB)
            r = db.execute("select content, timestamp, sender, media_type, filename from messages where id=? and chat_jid=?", (mid, jid)).fetchone()
            db.close()
            nomes, lid2pn = carregar_nomes()
            try:  # Desfazer: devolve a favorita à posição e à data em que estava (pos/em vêm do painel)
                pos = max(0, min(int(dados.get("pos")), len(favs)))
            except (TypeError, ValueError):
                pos = 0
            em_ = str(dados.get("em") or "")
            em_ = em_ if re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d", em_) else time.strftime("%Y-%m-%dT%H:%M")
            favs.insert(pos, {"jid": jid, "conversa": conversa or jid, "id": mid, "texto": (r[0] or "")[:500] if r else "",
                            "midia": (r[3] or "") if r else "", "arquivo": (r[4] or "") if r else "",
                            "hora": str(r[1] or "") if r else "", "quem": "Você" if eu else (nome(r[2], nomes, lid2pn) if r else ""),
                            "em": em_})
        e["favoritas"] = favs[:500]
        estado_gravar(e)
    return {"success": True}


def api_favoritas():
    """⭐ favoritas com o nome da conversa canônica (@lid juntado ao número) e o estado atual da mensagem:
    apagada para todos -> "apagada": true (sem o texto antigo); editada -> texto novo."""
    favs = estado_ler_cache().get("favoritas", [])
    para = aliases()[1]
    por = {c["jid"]: c for c in api_chats()}
    atual = {}
    ids = sorted({str(f.get("id") or "") for f in favs} - {""})
    if ids:
        db = ro(MSG_DB)
        try:
            for i in range(0, len(ids), 400):
                lote = ids[i:i + 400]
                for mid, cj, content, rev in db.execute(
                        f"select id, chat_jid, content, coalesce(revoked, 0) from messages where id in ({','.join('?' * len(lote))})", lote):
                    atual[(mid, cj)] = (content or "", bool(rev))
        except sqlite3.Error:
            atual = {}
        finally:
            db.close()
    out = []
    for f in favs:
        conv = str(f.get("conversa") or f.get("jid") or "")
        conv = para.get(conv, conv)
        c = por.get(conv)
        d = {**f, "conversa": conv, "nome": c["nome"] if c else conv}
        a = atual.get((f.get("id"), f.get("jid")))
        if a and a[1]:
            d["apagada"], d["texto"] = True, ""
        elif a and a[0].strip():
            d["texto"] = a[0][:500]
        out.append(d)
    return out


def pendentes_vivas(caixa):
    """Não respondidas (caixa_entrada.json do notificador.py) conferidas com o estado atual, com os mesmos critérios
    do "⏳ esperando" das conversas: sai o que já tem resposta do operador no banco (o notificador pode estar atrasado
    ou parado), o que foi resolvido ou adiado no painel e as conversas silenciadas ou ocultas."""
    caixa = [e for e in (caixa or []) if isinstance(e, dict) and e.get("chat_jid") and not e.get("respondida")]
    if not caixa:
        return []
    est = estado_ler_cache()
    resolvidas = est.get("resolvidas", {})
    agora_min = time.strftime("%Y-%m-%dT%H:%M")
    adiadas = {x.get("jid") for x in est.get("lembretes", []) if str(x.get("quando", "")) > agora_min}
    de, para = aliases()
    por = {c["jid"]: c for c in api_chats()}
    out = []
    db = ro(MSG_DB)
    try:
        for e in caixa:
            j0 = str(e["chat_jid"])
            canon = para.get(j0, j0)
            jids = list(dict.fromkeys([canon, j0] + de.get(canon, [])))
            c = por.get(canon)
            if c and (c.get("oculto") or c.get("mudo")):
                continue
            if any(j in adiadas for j in jids):
                continue
            desde = str(e.get("desde_ts") or "")
            ultimo = str(e.get("ultimo_ts") or desde)
            if ultimo and max(str(resolvidas.get(j, "")) for j in jids) >= ultimo:
                continue
            r = db.execute(f"select max(timestamp) from messages where is_from_me = 1 and chat_jid in ({','.join('?' * len(jids))})",
                           jids).fetchone()
            if desde and r and r[0] and str(r[0]) > desde:
                continue
            out.append(e)
    except sqlite3.Error:
        return caixa
    finally:
        db.close()
    return out


def exportar_conversa(jid):
    """Texto da conversa inteira (junta @lid + número), no formato do WhatsApp."""
    nomes, lid2pn = carregar_nomes()
    jids = jids_da_conversa(jid)
    db = ro(MSG_DB)
    r = db.execute("select name from chats where jid=?", (jid,)).fetchone()
    titulo = nome_chat(jid, r[0] if r else "", nomes, lid2pn)
    linhas = [f"Conversa do WhatsApp com {titulo} — exportada pelo painel em {time.strftime('%d/%m/%Y %H:%M')}", ""]
    rotulo = {"image": "<imagem>", "video": "<vídeo>", "audio": "<áudio>", "document": "<documento>", "sticker": "<figurinha>"}
    for content, ts, me, snd, mt, fn, rev in db.execute(f"""select content, timestamp, is_from_me, sender, media_type, filename, coalesce(revoked, 0) from messages
                                                      where chat_jid in ({','.join('?' * len(jids))}) order by timestamp""", jids):
        if rev:
            content, mt = "<mensagem apagada>", ""
        t = str(ts or "")
        quando = f"{t[8:10]}/{t[5:7]}/{t[0:4]} {t[11:16]}" if len(t) >= 16 else t
        quem = "Você" if me else nome(snd, nomes, lid2pn)
        texto = (content or "").strip()
        if mt:
            texto = (rotulo.get(mt, "<" + mt + ">") + (" " + fn if fn and mt == "document" else "") + ("\n" + texto if texto else ""))
        linhas.append(f"[{quando}] {quem}: {texto}")
    db.close()
    return titulo, "\n".join(linhas) + "\n"


_chats_cache = {"t": 0, "v": []}


def api_chats_cache():
    if time.time() - _chats_cache["t"] > 30:
        _chats_cache.update(t=time.time(), v=api_chats())
    return _chats_cache["v"]


def pedir_historico(dados):
    """Solicita um lote ou mede o avanço real, sem confundir mensagens novas."""
    jid = str(dados.get("jid") or "")
    if not jid or not jid_conhecido(jid):
        raise ErroEnvio("conversa desconhecida")
    jids = jids_da_conversa(jid)
    marc = ",".join("?" * len(jids))
    db = ro(MSG_DB)
    try:
        oldest = db.execute(f"select min(timestamp) from messages where chat_jid in ({marc})", jids).fetchone()[0]
        before = str(dados.get("antes") or "")
        older = db.execute(f"select count(*) from messages where chat_jid in ({marc}) and timestamp < ?", (*jids, before)).fetchone()[0] if before else 0
    finally:
        db.close()
    result = {"success": True, "mais_antiga": str(oldest or ""), "anteriores": older}
    if dados.get("consultar"):
        return result
    if DRYRUN or dados.get("dry_run"):
        return {**result, "dry_run": True}
    if not oldest:
        raise ErroEnvio("Sem mensagem de referência para buscar histórico")
    ok, erros = False, []
    for j in jids:
        try:
            r = chamar_ponte("/api/history", {"chat_jid": j, "count": 50}, timeout=30)
            ok = ok or bool(r.get("success"))
            if not r.get("success"):
                erros.append(r.get("message") or "pedido recusado")
        except Exception as e:
            erros.append(str(e))
    if not ok:
        raise ErroEnvio("; ".join(erros) or "pedido não enviado", 502)
    return {**result, "solicitado": True}


def api_midias(jid, tipo):
    """Mídia, documentos e links trocados na conversa (mais recentes primeiro)."""
    if not jid_conhecido(jid):
        return []
    jids = jids_da_conversa(jid)
    marc = ",".join("?" * len(jids))
    db = ro(MSG_DB)
    out = []
    if tipo == "links":
        for mid, cj, content, ts, me in db.execute(f"""select id, chat_jid, content, timestamp, is_from_me from messages
                where chat_jid in ({marc}) and content like '%http%' and coalesce(revoked, 0) = 0 order by timestamp desc limit 400""", jids):
            for url in re.findall(r"https?://[^\s<>\"']+", content or "")[:3]:
                out.append({"id": mid, "chat": cj, "url": url.rstrip(".,);"), "hora": str(ts or ""), "eu": bool(me)})
    else:
        tipos = ("image", "video") if tipo == "midia" else ("document",)
        for mid, cj, mt, fn, ts, me, extra in db.execute(f"""select id, chat_jid, media_type, filename, timestamp, is_from_me, extra from messages
                where chat_jid in ({marc}) and media_type in ({','.join('?' * len(tipos))}) and coalesce(revoked,0) = 0
                order by timestamp desc limit 300""", (*jids, *tipos)):
            item = {"id": mid, "chat": cj, "midia": mt, "arquivo": fn or "", "hora": str(ts or ""), "eu": bool(me)}
            try:
                x = json.loads(extra) if extra else {}
                item["bytes"] = x.get("bytes") or 0
            except ValueError:
                pass
            out.append(item)
    db.close()
    return out[:300]


def _backup_completo(pasta, dia):
    """Um .zip por dia com o que o estado JSON não cobre: figurinhas, mídias das campanhas, log de auditoria de envios,
    transcrições (cópia consistente do SQLite), config do painel e o estado. Guarda 7 dias. Roda uma vez por dia."""
    import zipfile, sqlite3 as _sq3, tempfile
    destino = os.path.join(pasta, f"completo-{dia}.zip")
    if os.path.exists(destino):
        return
    raiz = os.path.dirname(AQUI)
    tmp = destino + ".parcial"
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
            for rel in ("painel_estado.json", "config.json"):
                f = os.path.join(AQUI, rel)
                if os.path.isfile(f):
                    z.write(f, "painel/" + rel)
            for sub in ("figurinhas", "campanhas_midia"):
                for d, _, arqs in os.walk(os.path.join(AQUI, sub)):
                    for n in arqs:
                        f = os.path.join(d, n)
                        z.write(f, "painel/" + os.path.relpath(f, AQUI).replace(os.sep, "/"))
            for d, _, arqs in os.walk(os.path.join(raiz, "enviadas", "auditoria")):
                for n in arqs:
                    f = os.path.join(d, n)
                    z.write(f, "enviadas/auditoria/" + n)
            td = os.path.join(raiz, "transcricoes.db")
            if os.path.isfile(td):
                with tempfile.TemporaryDirectory() as t:
                    c1, c2 = _sq3.connect(f"file:{td}?mode=ro", uri=True), _sq3.connect(os.path.join(t, "t.db"))
                    c1.backup(c2); c1.close(); c2.close()
                    z.write(os.path.join(t, "t.db"), "transcricoes.db")
        os.replace(tmp, destino)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        return
    for n in sorted(x for x in os.listdir(pasta) if x.startswith("completo-") and x.endswith(".zip"))[:-7]:
        try:
            os.remove(os.path.join(pasta, n))
        except OSError:
            pass


def _backup():
    """Cópia diária do estado do painel (etiquetas, agendadas, respostas rápidas, fixadas...) — guarda 14 dias."""
    pasta = os.path.join(AQUI, "backups")
    while True:
        try:
            os.makedirs(pasta, exist_ok=True)
            hoje_ = time.strftime("%Y-%m-%d")
            destino = os.path.join(pasta, f"painel_estado-{hoje_}.json")
            if os.path.exists(ESTADO) and not os.path.exists(destino):
                with _estado_lock:
                    dados_ = open(ESTADO, encoding="utf-8").read()
                json.loads(dados_)  # só guarda se o arquivo estiver íntegro
                with open(destino, "w", encoding="utf-8") as f:
                    f.write(dados_)
            antigos = sorted(n for n in os.listdir(pasta) if n.startswith("painel_estado-"))
            for n in antigos[:-14]:
                os.remove(os.path.join(pasta, n))
            _backup_completo(pasta, hoje_)  # [backup] figurinhas, mídias das campanhas, auditoria, transcrições e config
        except (OSError, ValueError):
            pass
        time.sleep(3600)


# ---------- Integrações de IA (Claude / ChatGPT-Codex) com a chave de API do próprio usuário ----------
IA_MODELOS = {"claude": ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"], "openai": ["gpt-5", "gpt-5-mini"]}
IA_SISTEMA = ("Você ajuda a equipe a atender clientes pelo WhatsApp. "
              "Responda sempre em português do Brasil, com o tom dele: direto, cordial e informal na medida certa. "
              "Nunca invente preços, prazos, links ou promessas que não estejam na conversa; quando faltar informação, "
              "faça uma pergunta curta em vez de supor.")


def _ia_cfg():
    return _cfg_painel().get("ia", {})


def _mascara(k):
    return (k[:7] + "…" + k[-4:]) if k and len(k) > 14 else ("•••" if k else "")


def ia_config_publica():
    c = _ia_cfg()
    return {"provedor": c.get("provedor", ""), "modelos": IA_MODELOS,
            "claude": {"chave": _mascara(c.get("chave_claude", "")), "modelo": c.get("modelo_claude", IA_MODELOS["claude"][0])},
            "openai": {"chave": _mascara(c.get("chave_openai", "")), "modelo": c.get("modelo_openai", IA_MODELOS["openai"][0])},
            "ativa": bool(c.get("provedor") and c.get("chave_" + c.get("provedor", "x")))}


def ia_salvar(dados):
    cfg = _cfg_painel()
    ia = cfg.setdefault("ia", {})
    prov = str(dados.get("provedor") or "")
    if prov not in ("", "claude", "openai"):
        raise ErroEnvio("provedor inválido")
    ia["provedor"] = prov
    for pv in ("claude", "openai"):
        chave = str(dados.get("chave_" + pv) or "").strip()
        if chave == "-":  # remover
            ia.pop("chave_" + pv, None)
        elif chave:
            ia["chave_" + pv] = chave[:300]
        modelo = str(dados.get("modelo_" + pv) or "").strip()
        if modelo:
            ia["modelo_" + pv] = re.sub(r"[^\w.\-]", "", modelo)[:60]
    tmp = CONFIG_PAINEL + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG_PAINEL)
    return {"success": True, **ia_config_publica()}


def ia_chamar(instrucao, conteudo, max_tokens=2000):
    """Chama o provedor escolhido e devolve só o texto."""
    c = _ia_cfg()
    prov = c.get("provedor")
    if prov == "claude":
        chave = c.get("chave_claude")
        if not chave:
            raise ErroEnvio("cadastre a chave do Claude em Integrações")
        try:
            import anthropic
        except ImportError:
            raise ErroEnvio("biblioteca do Claude não instalada; reinicie o painel")
        cli = anthropic.Anthropic(api_key=chave, timeout=90)
        try:
            r = cli.beta.messages.create(
                model=c.get("modelo_claude", IA_MODELOS["claude"][0]), max_tokens=max_tokens,
                system=IA_SISTEMA, output_config={"effort": "low"},
                betas=["server-side-fallback-2026-07-01"], fallbacks="default",  # se um modelo recusar, outro assume
                messages=[{"role": "user", "content": conteudo + "\n\n" + instrucao}])
        except anthropic.AuthenticationError:
            raise ErroEnvio("chave do Claude inválida", 400)
        except anthropic.PermissionDeniedError:
            raise ErroEnvio("a chave do Claude não tem permissão para esse modelo", 400)
        except anthropic.NotFoundError:
            raise ErroEnvio("modelo do Claude não encontrado; escolha outro em Integrações", 400)
        except anthropic.RateLimitError:
            raise ErroEnvio("limite de uso do Claude atingido; tente em alguns segundos", 429)
        except anthropic.BadRequestError as e:
            raise ErroEnvio("o Claude recusou o pedido: " + str(e.message)[:200], 400)
        except anthropic.APIStatusError as e:
            raise ErroEnvio(f"erro no Claude ({e.status_code}); tente de novo", 502)
        except anthropic.APIConnectionError:
            raise ErroEnvio("sem conexão com o Claude (internet?)", 502)
        if r.stop_reason == "refusal":
            raise ErroEnvio("o Claude preferiu não responder a esse pedido", 400)
        return "".join(b.text for b in r.content if getattr(b, "type", "") == "text").strip()
    if prov == "openai":
        chave = c.get("chave_openai")
        if not chave:
            raise ErroEnvio("cadastre a chave da OpenAI em Integrações")
        try:
            import openai
        except ImportError:
            raise ErroEnvio("biblioteca da OpenAI não instalada; reinicie o painel")
        cli = openai.OpenAI(api_key=chave, timeout=90)
        try:
            r = cli.chat.completions.create(model=c.get("modelo_openai", IA_MODELOS["openai"][0]),
                                            messages=[{"role": "system", "content": IA_SISTEMA},
                                                      {"role": "user", "content": conteudo + "\n\n" + instrucao}])
        except openai.AuthenticationError:
            raise ErroEnvio("chave da OpenAI inválida", 400)
        except openai.NotFoundError:
            raise ErroEnvio("modelo da OpenAI não encontrado; escolha outro em Integrações", 400)
        except openai.RateLimitError:
            raise ErroEnvio("limite de uso da OpenAI atingido (ou sem créditos)", 429)
        except openai.APIStatusError as e:
            raise ErroEnvio(f"erro na OpenAI ({e.status_code})", 502)
        except openai.APIConnectionError:
            raise ErroEnvio("sem conexão com a OpenAI (internet?)", 502)
        return (r.choices[0].message.content or "").strip()
    raise ErroEnvio("escolha um provedor de IA em Integrações")


def _transcricao(jid, n=40):
    d = api_mensagens(jid, n)
    linhas = []
    for m in d["mensagens"]:
        if m.get("apagada"):
            continue
        t = m.get("texto") or m.get("transcricao") or ({"image": "[foto]", "video": "[vídeo]", "audio": "[áudio]", "document": "[documento " + (m.get("arquivo") or "") + "]", "sticker": "[figurinha]"}.get(m.get("midia"), ""))
        if t:
            linhas.append(f"[{m['hora'][:16]}] {'operador' if m['eu'] else (m.get('remetente') or d['nome'])}: {t}")
    return d["nome"], "\n".join(linhas)


_CORR_EMOJI = re.compile("[\U0001F300-\U0001FAFF☀-➿]")


def ia_corrigir(dados):
    """[corrigir] Corrige ortografia/acentos/pontuação/concordância em pt-BR mantendo o jeito do operador. Não envia nada."""
    texto = str(dados.get("texto") or "")
    if not texto.strip():
        raise ErroEnvio("escreva a mensagem primeiro")
    if len(texto) > 4000:
        raise ErroEnvio("texto longo demais para corrigir (máx. 4000 caracteres)")
    instr = ("Corrija SOMENTE ortografia, acentuação, pontuação e concordância do texto entre <texto> e </texto>, em português do Brasil. "
             "Mantenha o tom e o jeito de escrever do operador: informal, frases curtas, gírias e expressões como mano, pow, tmj, pra, tá, né, blz ficam como estão. "
             "Não formalize, não troque palavras por sinônimos, não acrescente nem tire conteúdo, não acrescente emojis. "
             "Mantenha emojis, links, números, nomes e as quebras de linha que já existem. "
             "Abreviações que são só pressa de digitação podem ir por extenso (vc→você, n→não quando for negação, q→que, pq→porque ou por que, tb→também). "
             "Se o texto já estiver correto, devolva igual. Responda APENAS com o texto corrigido, sem aspas, sem comentários e sem as marcas <texto>.")
    out = ia_chamar(instr, "<texto>\n" + texto + "\n</texto>", 1500).strip()
    out = re.sub(r"^\s*</?texto>\s*|\s*</?texto>\s*$", "", out).strip()
    aspas = "\"'“”"
    if len(out) >= 2 and out[0] in aspas and out[-1] in aspas and texto.strip()[:1] not in aspas:
        out = out[1:-1].strip()
    aviso = ""
    if not out:
        out, aviso = texto, "a IA não devolveu texto; mantive o seu"
    elif len(out) > max(40, len(texto) * 1.6):
        out, aviso = texto, "a IA mudou demais o texto; mantive o seu"
    elif len(_CORR_EMOJI.findall(out)) > len(_CORR_EMOJI.findall(texto)) and not _CORR_EMOJI.findall(texto):
        out = re.sub(r"\s{2,}", " ", _CORR_EMOJI.sub("", out)).strip()
    return {"success": True, "original": texto, "texto": out, "igual": out == texto, "aviso": aviso}


def ia_acao(dados, acao):
    jid = str(dados.get("jid") or "")
    if not jid or not jid_conhecido(jid):
        raise ErroEnvio("conversa desconhecida")
    nome_c, conversa = _transcricao(jid)
    if not conversa:
        raise ErroEnvio("a conversa ainda não tem mensagens de texto")
    base = f"Conversa de WhatsApp com {nome_c} (mais antigas primeiro):\n<conversa>\n{conversa}\n</conversa>"
    if acao == "sugerir":
        extra = str(dados.get("orientacao") or "").strip()[:500]
        instr = ("Escreva a PRÓXIMA mensagem que o operador deve mandar, pronta para enviar: só o texto da mensagem, "
                 "curta (1 a 4 frases), sem saudação repetida se a conversa já está em andamento, sem aspas e sem explicações."
                 + (f" Orientação do operador: {extra}" if extra else ""))
        return {"success": True, "texto": ia_chamar(instr, base, 1200)}
    instr = ("Resuma a conversa para o operador em português, em tópicos curtos: 1) do que se trata; 2) o que o cliente pediu; "
             "3) o que já foi combinado (valores, prazos, entregas); 4) o que está pendente e com quem; 5) próximo passo sugerido.")
    return {"success": True, "texto": ia_chamar(instr, base, 2000)}


# Whisper inventa estas frases em áudio sem fala (ruído/silêncio): não são do contato
_ALUCINA = re.compile(r"(legendas?\s+(pela|por|da)\s+comunidade|amara\.org|inscreva-se\s+no\s+canal|obrigad[oa]\s+por\s+assistir|legendado\s+por|tradu[cç][aã]o\s+e\s+legendas?)", re.I)
def limpar_transcricao(t):
    t = (t or "").strip()
    if not t or t.startswith("(falha"):
        return t
    partes = [p for p in re.split(r"(?<=[.!?])\s+", t) if p.strip() and not _ALUCINA.search(p)]
    return " ".join(partes).strip()


def reenviar_audio(dados):
    """Pega um áudio já enviado (arquivo local da ponte), recodifica em Opus padrão e manda de novo na mesma conversa.
    Para os áudios gravados antes da correção de 19/11, que davam "algo errado com o arquivo" no celular."""
    jid, mid = str(dados.get("jid") or ""), str(dados.get("id") or "")
    eu, mt = _msg_existe(jid, mid)
    if mt != "audio":
        raise ErroEnvio("essa mensagem não é um áudio")
    try:
        origem, _, _ = baixar_midia(mid, jid)
    except PonteIndisponivel:
        raise ErroEnvio("ponte do WhatsApp indisponível; tente de novo", 503)
    if not origem or not os.path.isfile(origem):
        raise ErroEnvio("não encontrei o arquivo desse áudio")
    import shutil
    copia = os.path.join(UPLOADS, time.strftime("%Y%m%d_%H%M%S") + "_" + secrets.token_hex(3) + "_reenvio.webm")
    shutil.copyfile(origem, copia)
    try:
        ogg = converter_voz(copia)
    finally:
        try:
            os.remove(copia)
        except OSError:
            pass
    return enviar_mensagem({"jid": jid, "path": ogg, "tipo": "voz", "nome": "voz.ogg"})


def resolver(dados):
    """Tira a conversa de "esperando resposta" sem responder (ex.: resolvido por ligação)."""
    jid = str(dados.get("jid") or "")
    if not jid or not jid_conhecido(jid):
        raise ErroEnvio("conversa desconhecida")
    db = ro(MSG_DB)
    jids = jids_da_conversa(jid)
    r = db.execute(f"select max(timestamp) from messages where chat_jid in ({','.join('?' * len(jids))})", jids).fetchone()
    db.close()
    with _estado_lock:
        e = estado_ler()
        res_ = e.setdefault("resolvidas", {})
        if dados.get("desfazer"):
            res_.pop(jid, None)
        else:
            res_[jid] = str(r[0] or "")
        estado_gravar(e)
    return {"success": True}


_resumo_mem = {"chave": None, "t": 0.0, "v": None}
_resumo_mem_lock = threading.Lock()


def api_resumo():
    """[perf-patch v1] Mesmo resultado de _api_resumo(), reaproveitado por até CACHE_TTL s se nada mudou."""
    chave = (_marca_db(), _marca_arq(ESTADO), time.strftime("%Y-%m-%d"))
    with _resumo_mem_lock:
        if not (_resumo_mem["chave"] == chave and time.monotonic() - _resumo_mem["t"] < CACHE_TTL):
            _resumo_mem.update(chave=chave, t=time.monotonic(), v=_api_resumo())
        v = _resumo_mem["v"]
    return {**v, "agendadas_hoje": [dict(x) for x in v["agendadas_hoje"]]}


def _api_resumo():
    """Números do dia para a tela inicial."""
    hoje_ = time.strftime("%Y-%m-%d")
    db = ro(MSG_DB)
    rec, env, conv = db.execute("""select sum(is_from_me = 0), sum(is_from_me = 1), count(distinct case when is_from_me = 0 then chat_jid end)
                                   from messages where timestamp >= ? and chat_jid not like '%@broadcast'""", (hoje_,)).fetchone()
    db.close()
    ag = [dict(x) for x in estado_ler_cache().get("agendadas", []) if x["status"] == "agendada" and x["quando"].startswith(hoje_)]
    return {"recebidas": rec or 0, "enviadas": env or 0, "conversas": conv or 0,
            "agendadas_hoje": sorted(ag, key=lambda x: x["quando"])}


# ---------- ⏱️ tempo de resposta (estatística por conversa) ----------
ATEND_H0, ATEND_H1 = 8, 20  # só o horário de atendimento conta no tempo de resposta
_tempos_mem = {}  # dias -> {"chave", "t", "v"}; no máximo 30 entradas (dias vai de 1 a 30)
_tempos_mem_lock = threading.Lock()


def _seg_atendimento(ini, fim):
    """Segundos entre dois instantes contando só das 8h às 20h (madrugada não conta como demora)."""
    from datetime import datetime as _dt, timedelta as _td
    if fim <= ini:
        return 0
    total, d, limite = 0.0, ini.date(), fim.date()
    while d <= limite and (d - ini.date()).days <= 31:
        a = max(ini, _dt.combine(d, _dt.min.time(), ini.tzinfo).replace(hour=ATEND_H0))
        b = min(fim, _dt.combine(d, _dt.min.time(), ini.tzinfo).replace(hour=ATEND_H1))
        if b > a:
            total += (b - a).total_seconds()
        d += _td(days=1)
    return int(total)


def _mediana(v):
    v = sorted(v)
    n = len(v)
    if not n:
        return 0
    return v[n // 2] if n % 2 else int((v[n // 2 - 1] + v[n // 2]) / 2)


def api_tempos(dias=7):
    """[tempos] Mesmo resultado de _api_tempos(), reaproveitado enquanto o banco não muda."""
    dias = max(1, min(30, int(dias or 7)))
    chave = (_marca_db(), _marca_arq(ESTADO))
    with _tempos_mem_lock:
        # [tempos-periodo] um resultado guardado por período: alternar 7/15/30 não refaz a conta
        g = _tempos_mem.get(dias)
        # [tempos-ttl] mensagem nova no banco nao derruba o resultado por 90 s; mudanca no estado refaz na hora
        idade = time.monotonic() - g["t"] if g else 1e9
        ok = bool(g) and g["chave"][1] == chave[1] and (idade < 90 or (g["chave"][0] == chave[0] and idade < 600))
        if not ok:
            g = _tempos_mem[dias] = {"chave": chave, "t": time.monotonic(), "v": _api_tempos(dias)}
        v = g["v"]
    return json.loads(json.dumps(v))  # cópia: ninguém altera o cache sem querer


def _api_tempos(dias):
    """Quanto tempo o operador leva para responder: por dia, no geral e por conversa.

    Uma "amostra" é um bloco: da primeira mensagem recebida sem resposta até a primeira resposta dele.
    Só conta o horário de atendimento (8h-20h) e blocos de até 7 dias; chamada perdida não conta como
    mensagem. Entram só conversas de trabalho (as mesmas que contam como "esperando resposta").
    """
    from datetime import datetime as _dt, timedelta as _td
    agora = _dt.now().astimezone()
    corte = (agora - _td(days=dias)).isoformat(" ", "seconds")
    para = aliases()[1]
    trabalho, info = set(), {}
    for c in api_chats_cache():
        tags = set(c.get("etiquetas") or [])
        if c["oculto"] or "Pessoal" in tags or "Família" in tags:
            continue
        if c["tipo"] == "individual" or (c["tipo"] == "grupo" and "Cliente" in tags):
            trabalho.add(c["jid"])
            info[c["jid"]] = c["nome"]
    db = ro(MSG_DB)
    try:
        linhas = db.execute("""select chat_jid, timestamp, is_from_me from messages
                where timestamp >= ? and coalesce(media_type, '') <> 'call'
                  and chat_jid not like '%@broadcast' and chat_jid not like '%@newsletter'
                order by chat_jid, timestamp""", (corte,)).fetchall()
    except sqlite3.Error:
        linhas = []
    db.close()
    por_jid, por_dia = {}, {}
    atual, aberta = None, None
    for cj, ts, me in linhas:
        canon = para.get(cj, cj)
        if canon not in trabalho:
            continue
        if cj != atual:  # a consulta vem agrupada por chat_jid; o alias é um bloco à parte
            atual, aberta = cj, None
        try:
            t = _dt.fromisoformat(str(ts))
        except ValueError:
            continue
        if not me:
            if aberta is None:
                aberta = t
        elif aberta is not None:
            if (t - aberta).total_seconds() <= 7 * 86400:
                seg = _seg_atendimento(aberta, t)
                if seg > 0 or (t - aberta).total_seconds() < 1:  # [fora-horario] bloco todo fora das 8h-20h não é demora: fora da conta
                    por_jid.setdefault(canon, []).append(seg)
                    por_dia.setdefault(t.strftime("%Y-%m-%d"), []).append(seg)
            aberta = None
    todas = [s for v in por_jid.values() for s in v]
    ordenadas = sorted(todas)
    dia_ini = (agora - _td(days=dias - 1)).date()
    serie = []
    primeiro = min((str(l[1])[:10] for l in linhas), default="")  # 1ª mensagem guardada: antes disso não há o que medir
    for i in range(dias):
        d = (dia_ini + _td(days=i)).strftime("%Y-%m-%d")
        if primeiro and d < primeiro and i < dias - 1:
            continue
        v = por_dia.get(d, [])
        serie.append({"dia": d, "qtd": len(v), "mediana": _mediana(v)})
    hoje_ = agora.strftime("%Y-%m-%d")
    ranking = sorted(({"jid": j, "nome": info.get(j, j), "qtd": len(v), "mediana": _mediana(v), "pior": max(v)}
                      for j, v in por_jid.items() if len(v) >= 2), key=lambda x: -x["mediana"])
    return {"dias": dias, "atendimento": [ATEND_H0, ATEND_H1], "amostras": len(todas),
            "mediana": _mediana(todas), "media": int(sum(todas) / len(todas)) if todas else 0,
            "p90": ordenadas[min(len(ordenadas) - 1, int(len(ordenadas) * 0.9))] if ordenadas else 0,
            "rapidas": round(100 * sum(1 for s in todas if s <= 300) / len(todas)) if todas else 0,
            "hoje": {"qtd": len(por_dia.get(hoje_, [])), "mediana": _mediana(por_dia.get(hoje_, []))},
            "serie": serie, "conversas": ranking[:20], "conversas_total": len(ranking)}


def salvar_etiquetas(dados):
    jid = str(dados.get("jid") or "")
    if not jid or not jid_conhecido(jid):
        raise ErroEnvio("conversa desconhecida")
    tags = []
    for t in (dados.get("etiquetas") or [])[:10]:
        t = re.sub(r"\s+", " ", str(t)).strip()[:24]
        if t and t not in tags:
            tags.append(t)
    with _estado_lock:
        e = estado_ler()
        et = e.setdefault("etiquetas", {})
        if tags:
            et[jid] = tags
        else:
            et.pop(jid, None)
        au_ = e.get("etiquetas_auto") or {}
        if jid in au_:  # [autonomia] etiqueta automática que foi tirada na tela deixa de ser automática
            au_[jid] = [t for t in au_[jid] if t in tags]
            if not au_[jid]:
                au_.pop(jid)
        estado_gravar(e)
    return {"success": True, "etiquetas": tags}


QR_PNG = os.path.join(os.path.dirname(STORE), "qr.png")


# ---------- lembretes / adiar conversa ----------
def lembrete(dados):
    jid = str(dados.get("jid") or "")
    if not jid or not jid_conhecido(jid):
        raise ErroEnvio("conversa desconhecida")
    with _estado_lock:
        e = estado_ler()
        lista = [x for x in e.get("lembretes", []) if x["jid"] != jid]
        if not dados.get("apagar"):
            quando = str(dados.get("quando") or "")
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", quando):
                raise ErroEnvio("data/hora inválida")
            lista.append({"jid": jid, "quando": quando, "nota": str(dados.get("nota") or "").strip()[:200],
                          "criado": time.strftime("%Y-%m-%dT%H:%M")})
        e["lembretes"] = lista
        estado_gravar(e)
    return {"success": True}


def organizar(dados):
    """Fixar/arquivar conversas (só no painel)."""
    jid, acao = str(dados.get("jid") or ""), str(dados.get("acao") or "")
    if not jid or not jid_conhecido(jid):
        raise ErroEnvio("conversa desconhecida")
    campo, por = {"fixar": ("fixados", True), "desafixar": ("fixados", False),
                  "arquivar": ("arquivados", True), "desarquivar": ("arquivados", False)}.get(acao, (None, None))
    if not campo:
        raise ErroEnvio("ação inválida")
    with _estado_lock:
        e = estado_ler()
        lista = [j for j in e.get(campo, []) if j != jid]
        if por:
            if campo == "fixados" and len(lista) >= 5:
                raise ErroEnvio("dá para fixar no máximo 5 conversas")
            lista.insert(0, jid)
        e[campo] = lista
        if campo == "arquivados" and por:  # arquivar desafixa, como no WhatsApp
            e["fixados"] = [j for j in e.get("fixados", []) if j != jid]
        estado_gravar(e)
    return {"success": True}


# ---------- respostas rápidas e mensagens agendadas (o painel faz sozinho, sem o Claude) ----------
_CONH = {"mt": 0, "dados": {}}
def conhecimento_contato(jid):
    """Relação/empresa/projeto do contato vindos de conhecimento/contatos.json (só leitura, sem tom/evidência)."""
    p = os.path.join(BASE, "conhecimento", "contatos.json")
    try:
        mt = os.path.getmtime(p)
        if mt != _CONH["mt"]:
            with open(p, encoding="utf-8") as f:
                lista = json.load(f)
            d = {}
            for c in lista if isinstance(lista, list) else []:
                for j in [c.get("jid")] + list(c.get("alt_jids") or []):
                    if j:
                        d[j] = c
            _CONH["dados"], _CONH["mt"] = d, mt
    except Exception:
        return {}
    c = _CONH["dados"].get(jid)
    if not c:
        return {}
    return {k: str(c.get(k) or "")[:120] for k in ("categoria", "subtipo", "empresa", "projeto")}

def rapidas_salvar(dados):
    itens = []
    for it in (dados.get("rapidas") or [])[:200]:
        at = re.sub(r"[^\w\-]", "", str(it.get("atalho") or "").lower())[:30]
        tx = str(it.get("texto") or "").strip()[:4000]
        if at and tx:
            itens.append({"atalho": at, "texto": tx})
    with _estado_lock:
        e = estado_ler()
        e["rapidas"] = itens
        estado_gravar(e)
    return {"success": True, "rapidas": itens}


# ---------- [ficha] ficha do cliente (mini-CRM): empresa, valor, vencimento, plano, observações, situação ----------
FICHA_STATUS = ("Ativo", "Em negociação", "Inadimplente", "Cancelado")
FICHA_TAM = {"empresa": 80, "plano": 80, "obs": 2000}
FICHA_NOMES = {"empresa": "empresa", "plano": "plano/serviço", "obs": "observações"}


def ficha_jid(jid):
    """Mesma conversa da lista/etiquetas: o @lid duplicado vira o chat pelo número (canônico)."""
    return aliases()[1].get(jid, jid)


def _ficha_texto(v, campo):
    s = "" if v is None else str(v)
    s = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", s)  # tira caracteres de controle (mantém \t e \n)
    s = s.strip() if campo == "obs" else re.sub(r"\s+", " ", s).strip()
    if len(s) > FICHA_TAM[campo]:
        raise ErroEnvio(f"{FICHA_NOMES[campo]}: no máximo {FICHA_TAM[campo]} caracteres")
    return s


def _ficha_valor(v):
    """Aceita 859 / 859.5 / "859,00" / "R$ 1.234,56" / "1.234". Vazio = sem valor."""
    if v is None or (isinstance(v, str) and not v.strip()):
        return None
    if isinstance(v, bool):
        raise ErroEnvio("valor inválido")
    if isinstance(v, (int, float)):
        n = float(v)
    else:
        s = re.sub(r"[R$\s]", "", str(v))[:20]
        if "," in s:
            s = s.replace(".", "").replace(",", ".")
        elif re.fullmatch(r"\d{1,3}(\.\d{3})+", s):
            s = s.replace(".", "")
        if not re.fullmatch(r"\d+(\.\d{1,2})?", s):
            raise ErroEnvio("valor inválido (use, por exemplo, 859,00)")
        n = float(s)
    if not (0 <= n <= 10_000_000):  # também barra NaN/infinito
        raise ErroEnvio("valor fora do limite")
    return round(n, 2)


def _ficha_venc(v):
    if v is None or (isinstance(v, str) and not v.strip()):
        return None
    if isinstance(v, bool):
        raise ErroEnvio("vencimento inválido")
    s = str(v).strip()
    if isinstance(v, float):
        if not v.is_integer():
            raise ErroEnvio("vencimento: use um dia de 1 a 31")
        s = str(int(v))
    if not re.fullmatch(r"\d{1,2}", s) or not 1 <= int(s) <= 31:
        raise ErroEnvio("vencimento: use um dia de 1 a 31")
    return int(s)


def ficha_ler(jid):
    jid = str(jid or "")
    if not jid or not jid_conhecido(jid):
        return {"success": False, "erro": "conversa desconhecida"}
    canon = ficha_jid(jid)
    fs = estado_ler_cache().get("fichas", {})
    f = fs.get(canon) or next((fs[j] for j in jids_da_conversa(canon) if j in fs), None) or fs.get(jid) or {}
    return {"success": True, "jid": canon, "ficha": dict(f)}


def ficha_salvar(dados):
    """Salva só os campos que vieram (autosave campo a campo). Campo vazio apaga; ficha vazia some do estado."""
    jid = str(dados.get("jid") or "")
    if not jid or not jid_conhecido(jid):
        raise ErroEnvio("conversa desconhecida")
    jid = ficha_jid(jid)
    novos = {}
    for campo in ("empresa", "plano", "obs"):
        if campo in dados:
            novos[campo] = _ficha_texto(dados[campo], campo)
    if "valor" in dados:
        novos["valor"] = _ficha_valor(dados["valor"])
    if "vencimento" in dados:
        novos["vencimento"] = _ficha_venc(dados["vencimento"])
    if "status" in dados:
        stt = str(dados.get("status") or "").strip()
        if stt and stt not in FICHA_STATUS:
            raise ErroEnvio("situação inválida")
        novos["status"] = stt
    if not novos:
        raise ErroEnvio("nada para salvar")
    with _estado_lock:
        e = estado_ler()
        fs = e.setdefault("fichas", {})
        f = dict(fs.get(jid) or {})
        for k, v in novos.items():
            if v is None or v == "":
                f.pop(k, None)
            else:
                f[k] = v
        f.pop("atualizado", None)
        if f:
            f["atualizado"] = time.strftime("%Y-%m-%dT%H:%M")
            fs[jid] = f
        else:
            fs.pop(jid, None)
        estado_gravar(e)
    return {"success": True, "jid": jid, "ficha": f}


# ---------- [rascunhos] fila "Aprovar com 1 clique": rascunhos prontos (cobrança, modelo, Claude) ----------
# O servidor só GUARDA rascunhos. Nada aqui envia mensagem: quem envia é o operador, clicando "Enviar" no rascunho
# (o painel usa o mesmo caminho do compositor: /api/enviar). "enviado" só tira o rascunho da fila.
RASC_MAX = 300
RASC_COB_MODELO = ("Oi {nome}, tudo bem? Passando para lembrar que a mensalidade da {empresa} de {valor} vence "
                   "{vencimento}. Qualquer dúvida estou à disposição.")
RASC_COB_STATUS = ("Ativo", "Inadimplente")
RASC_COB_HORA = 9  # 09:00


def _rasc_origem(v):
    s = re.sub(r"[\x00-\x1f\x7f<>]", "", str(v or "")).strip()[:30]
    return s or "claude"


def rasc_cob_cfg(e=None):
    """Lembrete de cobrança (rascunho). Padrão: DESLIGADO até o operador ligar em Configurações → Automações."""
    c = ((e if e is not None else estado_ler_cache()).get("rasc_cobranca") or {})
    try:
        dias = int(c.get("dias_antes", 0))
    except (TypeError, ValueError):
        dias = 0
    modelo = str(c.get("modelo") or "").strip()[:2000] or RASC_COB_MODELO
    return {"ativo": c.get("ativo") is True, "dias_antes": max(0, min(5, dias)), "modelo": modelo}


def rascunhos_listar():
    e = estado_ler_cache()
    return {"success": True, "rascunhos": [dict(r) for r in e.get("rascunhos", [])], "cobranca": rasc_cob_cfg(e),
            "cobranca_ultima": e.get("rasc_cob_ultimo", "")}


def _rasc_criar(e, jid, texto, origem, chave=""):
    """Dentro do _estado_lock. Devolve o rascunho criado (ou o que já existia com o mesmo texto/chave)."""
    lista = e.setdefault("rascunhos", [])
    for r in lista:
        if r["jid"] == jid and ((chave and r.get("chave") == chave) or r["texto"] == texto):
            return r, False
    if len(lista) >= RASC_MAX:
        raise ErroEnvio(f"fila de rascunhos cheia ({RASC_MAX}); descarte alguns")
    r = {"id": secrets.token_hex(6), "jid": jid, "texto": texto, "origem": origem, "criado": time.strftime("%Y-%m-%dT%H:%M")}
    if chave:
        r["chave"] = chave
    lista.append(r)
    return r, True


def rascunhos_salvar(dados):
    acao = str(dados.get("acao") or "")
    if acao == "criar":
        jid = str(dados.get("jid") or "")
        if not jid or not jid_conhecido(jid):
            raise ErroEnvio("conversa desconhecida")
        jid = ficha_jid(jid)  # mesma conversa da lista (o @lid duplicado vira o chat pelo número)
        texto = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", str(dados.get("texto") or "")).strip()
        if not texto:
            raise ErroEnvio("rascunho vazio")
        if len(texto) > 4000:
            raise ErroEnvio("rascunho: no máximo 4000 caracteres")
        chave = re.sub(r"[^\w:\-@.]", "", str(dados.get("chave") or ""))[:80]
        with _estado_lock:
            e = estado_ler()
            r, novo = _rasc_criar(e, jid, texto, _rasc_origem(dados.get("origem")), chave)
            if novo:
                estado_gravar(e)
        return {"success": True, "rascunho": dict(r), "novo": novo}
    if acao in ("editar", "descartar", "enviado"):
        rid = str(dados.get("id") or "")
        with _estado_lock:
            e = estado_ler()
            lista = e.get("rascunhos", [])
            r = next((x for x in lista if x["id"] == rid), None)
            if not r:
                if acao == "editar":
                    raise ErroEnvio("rascunho não encontrado (já foi enviado ou descartado)")
                return {"success": True, "ja": True}  # descartar/enviado repetido: nada a fazer
            if acao == "editar":
                texto = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", str(dados.get("texto") or "")).strip()
                if not texto:
                    raise ErroEnvio("rascunho vazio (use Descartar)")
                r["texto"] = texto[:4000]
                r["editado"] = time.strftime("%Y-%m-%dT%H:%M")
            else:
                e["rascunhos"] = [x for x in lista if x["id"] != rid]
            estado_gravar(e)
        return {"success": True, "rascunho": dict(r)}
    if acao == "config":
        c = dados.get("cobranca") or {}
        try:
            dias = int(c.get("dias_antes", 0))
        except (TypeError, ValueError):
            raise ErroEnvio("dias antes: use de 0 a 5")
        if not 0 <= dias <= 5:
            raise ErroEnvio("dias antes: use de 0 a 5")
        modelo = str(c.get("modelo") or "").strip()
        if len(modelo) > 2000:
            raise ErroEnvio("modelo: no máximo 2000 caracteres")
        with _estado_lock:
            e = estado_ler()
            e["rasc_cobranca"] = {"ativo": c.get("ativo") is True, "dias_antes": dias, "modelo": modelo or RASC_COB_MODELO}
            estado_gravar(e)
        _rasc_cob_evento.set()  # ligou agora e já passou das 09:00: verifica sem esperar o próximo minuto
        return {"success": True, "cobranca": rasc_cob_cfg(e)}
    if acao == "gerar":  # "Verificar agora" (só cria rascunhos; continua sem enviar nada)
        if not rasc_cob_cfg()["ativo"]:
            raise ErroEnvio("ligue o lembrete de cobrança primeiro")
        return {"success": True, "criados": rasc_cobranca_gerar()}
    raise ErroEnvio("ação inválida")


def _rasc_fmt_valor(v):
    if v is None or v == "":
        return ""
    s = f"{float(v):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return "R$ " + s


def _rasc_primeiro_nome(jid):
    try:
        c = next((c for c in api_chats() if c.get("jid") == jid), None)
        n = (c or {}).get("nome") or ""
    except Exception:
        n = ""
    if not n:
        nomes, lid2pn = carregar_nomes()
        n = nome(jid, nomes, lid2pn)
    n = str(n or "").strip()
    return "" if n.startswith("+") or n.isdigit() else n.split()[0] if n else ""


def _rasc_cob_texto(modelo, jid, f, dias, alvo):
    venc = "dia %02d" % alvo.day
    venc = ("hoje (%s)" % venc) if dias == 0 else ("amanhã (%s)" % venc) if dias == 1 else ("no %s/%02d" % (venc, alvo.month))
    nome_ = _rasc_primeiro_nome(jid)
    vals = {"nome": nome_, "empresa": f.get("empresa") or "", "valor": _rasc_fmt_valor(f.get("valor")), "vencimento": venc}
    t = re.sub(r"\{(nome|empresa|valor|vencimento)\}", lambda m: vals[m.group(1).lower()], modelo, flags=re.I)
    t = re.sub(r"Oi ,", "Oi,", t)  # sem nome salvo: "Oi, tudo bem?"
    return re.sub(r"[ \t]{2,}", " ", t).strip()


def rasc_cobranca_gerar(hoje=None):
    """Cria UM rascunho de cobrança por ficha (Ativo/Inadimplente) cujo vencimento cai hoje + dias_antes.
    Nunca duplica para o mesmo jid no mesmo mês (mesmo que o rascunho tenha sido descartado). Não envia nada."""
    import calendar
    hoje = hoje or _dt_auto.now()
    est = estado_ler_cache()
    cfg = rasc_cob_cfg(est)
    if not cfg["ativo"]:
        return 0
    alvo = (hoje + _td_auto(days=cfg["dias_antes"])).date()
    ultimo_dia = calendar.monthrange(alvo.year, alvo.month)[1]
    mes = alvo.strftime("%Y-%m")
    candidatos = []
    for jid, f in (est.get("fichas") or {}).items():
        v = f.get("vencimento")
        if f.get("status") not in RASC_COB_STATUS or not isinstance(v, int):
            continue
        if min(v, ultimo_dia) != alvo.day:  # vencimento 31 em mês de 30 dias cai no último dia
            continue
        candidatos.append((jid, dict(f)))
    textos = {jid: _rasc_cob_texto(cfg["modelo"], jid, f, cfg["dias_antes"], alvo) for jid, f in candidatos}
    criados = 0
    with _estado_lock:
        e = estado_ler()
        feitos = e.setdefault("rasc_cob_feitos", {})
        for jid, _f in candidatos:
            if feitos.get(jid) == mes:
                continue
            _r, novo = _rasc_criar(e, jid, textos[jid], "cobrança", "cob:%s:%s" % (jid, mes))
            feitos[jid] = mes
            criados += int(novo)
        e["rasc_cob_ultimo"] = hoje.strftime("%Y-%m-%d")
        estado_gravar(e)
    return criados


_rasc_cob_evento = threading.Event()


def _rasc_cobranca():
    """Todo dia às 09:00 (e ao ligar o painel depois das 09:00) cria os rascunhos de cobrança. Só rascunho."""
    time.sleep(5)
    while True:
        try:
            agora = _dt_auto.now()
            e = estado_ler_cache()
            if rasc_cob_cfg(e)["ativo"] and agora.hour >= RASC_COB_HORA and e.get("rasc_cob_ultimo") != agora.strftime("%Y-%m-%d"):
                n = rasc_cobranca_gerar()
                if n:
                    print(f"rascunhos: {n} lembrete(s) de cobrança criados para aprovar")
        except Exception as ex:
            print("rascunhos:", type(ex).__name__, ex)
        _rasc_cob_evento.wait(60)
        _rasc_cob_evento.clear()


def agendar(dados):
    jid, texto, quando = str(dados.get("jid") or ""), str(dados.get("texto") or "").strip(), str(dados.get("quando") or "")
    # [agendar-numero-novo] número sem conversa: vale se a ponte confirmou há pouco (Conversar com +55...); no envio confere de novo
    if not jid or not (jid_conhecido(jid) or numero_liberado(jid)):
        raise ErroEnvio("conversa desconhecida")
    if not texto:
        raise ErroEnvio("escreva a mensagem")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", quando):
        raise ErroEnvio("data/hora inválida")
    if quando <= time.strftime("%Y-%m-%dT%H:%M"):
        raise ErroEnvio("escolha um horário no futuro")
    repetir = str(dados.get("repetir") or "")
    if repetir not in ("", "dia", "semana", "mes"):
        raise ErroEnvio("repetição inválida")
    item = {"id": secrets.token_hex(6), "jid": jid, "texto": texto[:4000], "quando": quando, "criado": time.strftime("%Y-%m-%dT%H:%M"),
            "status": "agendada", "repetir": repetir}
    with _estado_lock:
        e = estado_ler()
        e.setdefault("agendadas", []).append(item)
        estado_gravar(e)
    return {"success": True, "agendada": item}


def agendadas_cancelar(dados):
    aid = str(dados.get("id") or "")
    with _estado_lock:
        e = estado_ler()
        for it in e.get("agendadas", []):
            if it["id"] == aid and it["status"] in ("agendada", "erro"):
                it["status"] = "cancelada"
                estado_gravar(e)
                return {"success": True}
    raise ErroEnvio("agendamento não encontrado")


def proxima_vez(quando, repetir):
    from datetime import datetime as _dt, timedelta as _td
    d = _dt.strptime(quando, "%Y-%m-%dT%H:%M")
    agora = _dt.now()
    while d <= agora:
        if repetir == "dia":
            d += _td(days=1)
        elif repetir == "semana":
            d += _td(days=7)
        else:  # mês: mesmo dia (ou o último dia do mês, se não existir)
            import calendar
            ano, mes = (d.year + (d.month == 12), d.month % 12 + 1)
            dia = min(int(quando[8:10]), calendar.monthrange(ano, mes)[1])
            d = d.replace(year=ano, month=mes, day=dia)
    return d.strftime("%Y-%m-%dT%H:%M")


def _limpeza():
    """Apaga envios temporários (uploads) com mais de 1 dia — roda na partida e a cada 6 h."""
    while True:
        try:
            pasta = os.path.join(AQUI, "uploads")
            limite = time.time() - 86400
            for n in os.listdir(pasta):
                f = os.path.join(pasta, n)
                if os.path.isfile(f) and os.path.getmtime(f) < limite:
                    os.remove(f)
        except OSError:
            pass
        time.sleep(6 * 3600)


def config_painel(remoto):
    ips = []
    try:
        ips = [i for i in _socket.gethostbyname_ex(_socket.gethostname())[2] if ip_cliente_ok(i) and not i.startswith("127.")]
    except OSError:
        pass
    agora = time.time()
    return {"local": not remoto, "enderecos": [f"http://{i}:{PORT}" for i in ips],
            "aparelhos": sum(1 for v in _sessoes.values() if v[0] > agora)}


# ---------- [autonomia] etiquetas automáticas por palavra-chave e "Pago?" por comprovante (sem IA; NUNCA envia nada) ----------
# Só ACRESCENTA etiquetas (nunca tira as que o operador pôs); as que o painel pôs ficam em "etiquetas_auto" para a tela
# mostrar como automáticas. Tirar uma etiqueta automática na tela vale como "desfazer" (ela deixa de ser automática).
import unicodedata as _ud
from datetime import datetime as _dt_auto, timedelta as _td_auto

AUTO_PADRAO = {
    "ativo": True,
    "regras": [{"etiqueta": "Cobrança", "palavras": ["pix", "boleto", "comprovante", "paguei"]},
               {"etiqueta": "Lead", "palavras": ["orçamento", "preço", "valor", "quanto custa"]}],
    "comprovante": {"ativo": True, "palavras": ["comprovante", "pix", "paguei", "pagamento", "pago", "transferência", "transferi"]},
    "sugestoes": {},  # atalho da resposta rápida -> palavras que puxam a sugestão no compositor
}
ETIQ_PAGO = "Pago?"
APAGAR_LIMITE_S = 48 * 3600 + 600  # "apagar para todos": o WhatsApp recusa depois de ~2 dias (a tela esconde em 48 h)
_auto_mem = {"cursor": None, "ids": [], "gravado": 0.0}
_auto_lock = threading.Lock()


def _norm_auto(t):
    t = _ud.normalize("NFD", str(t or "")).lower()
    return "".join(c for c in t if _ud.category(c) != "Mn")


def _tem_palavra(txt_norm, palavras):
    for p in palavras or []:
        p = _norm_auto(p).strip()
        if p and re.search(r"(?<!\w)" + re.escape(p) + r"(?!\w)", txt_norm):
            return True
    return False


def _lista_palavras(v, maximo=40):
    if isinstance(v, str):
        v = re.split(r"[,;\n]", v)
    out = []
    for p in (v or [])[:maximo]:
        p = re.sub(r"\s+", " ", str(p)).strip()[:40]
        if p and p.lower() not in [x.lower() for x in out]:
            out.append(p)
    return out


def auto_cfg(e=None):
    """Configuração das regras (padrão + o que foi salvo em painel_estado.json -> "auto_config")."""
    salvo = ((e if e is not None else estado_ler_cache()).get("auto_config") or {})
    cfg = json.loads(json.dumps(AUTO_PADRAO))
    if isinstance(salvo.get("ativo"), bool):
        cfg["ativo"] = salvo["ativo"]
    if isinstance(salvo.get("regras"), list):
        cfg["regras"] = [{"etiqueta": str(r.get("etiqueta") or "").strip()[:24], "palavras": _lista_palavras(r.get("palavras"))}
                         for r in salvo["regras"][:10] if isinstance(r, dict) and str(r.get("etiqueta") or "").strip()]
    cp = salvo.get("comprovante")
    if isinstance(cp, dict):
        if isinstance(cp.get("ativo"), bool):
            cfg["comprovante"]["ativo"] = cp["ativo"]
        if "palavras" in cp:
            cfg["comprovante"]["palavras"] = _lista_palavras(cp.get("palavras"))
    if isinstance(salvo.get("sugestoes"), dict):
        cfg["sugestoes"] = {re.sub(r"[^\w\-]", "", str(k).lower())[:30]: _lista_palavras(v, 20)
                            for k, v in list(salvo["sugestoes"].items())[:200] if re.sub(r"[^\w\-]", "", str(k))}
    return cfg


def _auto_ts(ts):
    try:
        return _dt_auto.fromisoformat(str(ts))
    except ValueError:
        return None


def _eh_doc_pagamento(mt, fn):
    return mt == "image" or (mt == "document" and str(fn or "").lower().endswith(".pdf"))


def _auto_varrer():
    """Uma passada: lê só as mensagens RECEBIDAS depois do cursor e aplica as regras. Devolve quantas viu."""
    est = estado_ler_cache()
    cfg = auto_cfg(est)
    with _auto_lock:
        cursor = _auto_mem["cursor"] or est.get("auto_cursor")
        db = ro(MSG_DB)
        try:
            if not cursor:  # primeira vez: começa de agora (não reetiqueta o histórico)
                r = db.execute("select max(timestamp) from messages").fetchone()
                ids0 = [i for (i,) in db.execute("select id from messages where timestamp = ?", (r[0],))] if r[0] else []
                _auto_mem.update(cursor=str(r[0] or ""), ids=ids0[-200:])
                with _estado_lock:
                    e = estado_ler()
                    e["auto_cursor"] = _auto_mem["cursor"]
                    estado_gravar(e)
                _auto_mem["gravado"] = time.time()
                return 0
            rows = db.execute("""select id, chat_jid, content, media_type, filename, timestamp from messages
                                 where is_from_me = 0 and timestamp >= ? and coalesce(revoked, 0) = 0
                                 order by timestamp limit 500""", (cursor,)).fetchall()
            vistos = set(_auto_mem["ids"])
            rows = [r for r in rows if r[0] not in vistos]
            if not rows:
                return 0
            para = aliases()[1]
            cfg_v = config()
            etiq = est.get("etiquetas", {})
            add, pagos = {}, []
            for mid, cj, content, mt, fn, ts in rows:
                canon = para.get(cj, cj)
                if not cfg["ativo"] or tipo_chat(canon) != "individual" or oculto(canon, "", cfg_v):
                    continue
                if "Pessoal" in (etiq.get(canon) or []) or "Família" in (etiq.get(canon) or []):
                    continue
                txt = _norm_auto((content or "") + " " + (fn or "" if mt == "document" else ""))
                for rg in cfg["regras"]:
                    if rg["etiqueta"] and _tem_palavra(txt, rg["palavras"]):
                        add.setdefault(canon, []).append(rg["etiqueta"])
                cp = cfg["comprovante"]
                if cp["ativo"] and cp["palavras"]:
                    eh_doc, tem_pal = _eh_doc_pagamento(mt or "", fn), _tem_palavra(txt, cp["palavras"])
                    ok = eh_doc and tem_pal
                    if not ok and (eh_doc or tem_pal):  # foto/PDF e a palavra em mensagens separadas (até 10 min)
                        d = _auto_ts(ts)
                        if d:
                            ini = (d - _td_auto(minutes=10)).isoformat(sep=" ")
                            fim = (d + _td_auto(minutes=10)).isoformat(sep=" ")
                            jids = jids_da_conversa(canon)
                            viz = db.execute(f"""select content, media_type, filename from messages where chat_jid in ({','.join('?' * len(jids))})
                                                 and is_from_me = 0 and timestamp between ? and ? and id != ?""", (*jids, ini, fim, mid)).fetchall()
                            for c2, mt2, fn2 in viz:
                                t2 = _norm_auto((c2 or "") + " " + (fn2 or "" if mt2 == "document" else ""))
                                if (eh_doc and _tem_palavra(t2, cp["palavras"])) or (tem_pal and _eh_doc_pagamento(mt2 or "", fn2)):
                                    ok = True
                                    break
                    if ok:
                        add.setdefault(canon, []).append(ETIQ_PAGO)
                        item = {"jid": canon, "id": mid, "hora": str(ts or ""), "doc": eh_doc,
                                "texto": (content or (fn if mt == "document" else "") or ("📷 Foto" if mt == "image" else "📄 Documento"))[:140]}
                        ant = next((p for p in pagos if p["jid"] == canon), None)  # um aviso por conversa (de preferência o da foto/PDF)
                        if not ant:
                            pagos.append(item)
                        elif eh_doc or not ant["doc"]:
                            ant.update(item)
            novo_cursor = max(str(r[5] or "") for r in rows)
            ids_cursor = [r[0] for r in rows if str(r[5] or "") == novo_cursor] + \
                         ([i for i in _auto_mem["ids"]] if novo_cursor == cursor else [])
        finally:
            db.close()
        _auto_mem.update(cursor=novo_cursor, ids=ids_cursor[-200:])
        if not add and time.time() - _auto_mem["gravado"] < 600:
            return len(rows)  # nada novo para gravar: o cursor fica em memória (grava no máx. a cada 10 min)
        with _estado_lock:
            e = estado_ler()
            et, au = e.setdefault("etiquetas", {}), e.setdefault("etiquetas_auto", {})
            for jid, tags in add.items():
                atuais = list(et.get(jid) or [])
                for t in tags:
                    if t not in atuais and len(atuais) < 10:
                        atuais.append(t)
                        au.setdefault(jid, [])
                        if t not in au[jid]:
                            au[jid].append(t)
                if atuais:
                    et[jid] = atuais
            if pagos:
                lista = [p for p in e.get("pagos", []) if p["jid"] not in {x["jid"] for x in pagos}]
                e["pagos"] = (lista + pagos)[-60:]
            e["auto_cursor"] = _auto_mem["cursor"]
            estado_gravar(e)
        _auto_mem["gravado"] = time.time()
        return len(rows)


def _autonomia():
    """Vigia das regras automáticas (a cada 15 s). Só etiqueta e lista; não envia nada."""
    while True:
        time.sleep(15)
        try:
            _auto_varrer()
        except Exception as ex:
            print("autonomia:", type(ex).__name__, ex)


def api_autonomia():
    e = estado_ler_cache()
    limite = (_dt_auto.now() - _td_auto(days=7)).strftime("%Y-%m-%d")
    pagos = [dict(p) for p in e.get("pagos", []) if not p.get("conferido") and p["hora"][:10] >= limite]
    return {"config": auto_cfg(e), "auto": {k: list(v) for k, v in (e.get("etiquetas_auto") or {}).items()},
            "pagos": sorted(pagos, key=lambda p: p["hora"], reverse=True)[:20]}


def autonomia_salvar(dados):
    acao = str(dados.get("acao") or "")
    if acao == "config":
        c = dados.get("config") or {}
        novo = {"ativo": bool(c.get("ativo", True)),
                "regras": [{"etiqueta": re.sub(r"\s+", " ", str(r.get("etiqueta") or "")).strip()[:24], "palavras": _lista_palavras(r.get("palavras"))}
                           for r in (c.get("regras") or [])[:10] if isinstance(r, dict) and str(r.get("etiqueta") or "").strip()],
                "comprovante": {"ativo": bool((c.get("comprovante") or {}).get("ativo", True)),
                                "palavras": _lista_palavras((c.get("comprovante") or {}).get("palavras"))},
                "sugestoes": {re.sub(r"[^\w\-]", "", str(k).lower())[:30]: _lista_palavras(v, 20)
                              for k, v in list((c.get("sugestoes") or {}).items())[:200] if re.sub(r"[^\w\-]", "", str(k)) and _lista_palavras(v, 20)}}
        with _estado_lock:
            e = estado_ler()
            e["auto_config"] = novo
            estado_gravar(e)
        return {"success": True, "config": auto_cfg(novo and {"auto_config": novo})}
    if acao == "conferir":  # "comprovante conferido": sai do resumo e tira o "Pago?" que o painel pôs
        jid = str(dados.get("jid") or "")
        if not jid or not jid_conhecido(jid):
            raise ErroEnvio("conversa desconhecida")
        with _estado_lock:
            e = estado_ler()
            for p in e.get("pagos", []):
                if p["jid"] == jid:
                    p["conferido"] = True
            au = e.get("etiquetas_auto") or {}
            if ETIQ_PAGO in (au.get(jid) or []):
                au[jid] = [t for t in au[jid] if t != ETIQ_PAGO]
                if not au[jid]:
                    au.pop(jid)
                et = e.get("etiquetas") or {}
                et[jid] = [t for t in (et.get(jid) or []) if t != ETIQ_PAGO]
                if not et[jid]:
                    et.pop(jid)
            estado_gravar(e)
        return {"success": True}
    raise ErroEnvio("ação inválida")


def _agendador():
    """Envia as mensagens agendadas na hora certa (verifica a cada 20 s). Cada envio é marcado "enviando" ANTES de sair:
    se o painel cair no meio, a mensagem NÃO é reenviada sozinha (vira erro pedindo conferência)."""
    try:
        with _estado_lock:
            e0 = estado_ler()
            presas = [x for x in e0.get("agendadas", []) if x.get("status") == "enviando"]
            for x in presas:
                x.update(status="erro", erro="o painel parou durante o envio: confira na conversa se saiu antes de reenviar")
            if presas:
                estado_gravar(e0)
    except Exception as ex0:
        print("[agendador] limpeza inicial:", ex0, flush=True)
    while True:
        time.sleep(20)
        agora = time.strftime("%Y-%m-%dT%H:%M")
        with _estado_lock:
            pendentes = [dict(it) for it in estado_ler().get("agendadas", []) if it["status"] == "agendada" and it["quando"] <= agora]
        for it in pendentes:
            with _estado_lock:  # marca "enviando" e grava ANTES de enviar (quem cancelar nesse meio-tempo já não alcança)
                e1 = estado_ler()
                alvo = [x for x in e1.get("agendadas", []) if x["id"] == it["id"] and x["status"] == "agendada"]
                if not alvo:
                    continue
                alvo[0]["status"] = "enviando"
                estado_gravar(e1)
            try:
                from datetime import datetime as _dt
                atraso = (_dt.now() - _dt.strptime(it["quando"], "%Y-%m-%dT%H:%M")).total_seconds() / 60
                if atraso > 120:
                    raise ErroEnvio(f"não enviada: o painel estava desligado no horário ({int(atraso // 60)} h de atraso). Envie ou reagende")
                if not jid_conhecido(it["jid"]) and it["jid"].endswith("@s.whatsapp.net"):  # [agendar-numero-novo] 1ª mensagem: confere na ponte e libera
                    try:
                        _cad_consultar(it["jid"].split("@")[0])
                    except Exception as ex_n:
                        print("[agendador] conferir número novo:", ex_n, flush=True)
                r = enviar_mensagem({"jid": it["jid"], "texto": it["texto"], "sem_ler": True})
                novo, erro = ("enviada", "") if r.get("success") else ("erro", r.get("erro") or r.get("message") or "falhou")
            except Exception as ex:
                novo, erro = "erro", str(ex)
            with _estado_lock:
                e = estado_ler()
                for x in e.get("agendadas", []):
                    if x["id"] == it["id"] and x["status"] in ("agendada", "enviando"):
                        x.update(status=novo, enviado_em=time.strftime("%Y-%m-%dT%H:%M"), erro=erro)
                        if x.get("repetir"):  # cria a próxima vez (mesmo horário)
                            prox = proxima_vez(x["quando"], x["repetir"])
                            e["agendadas"].append({**{k: v for k, v in x.items() if k not in ("enviado_em", "erro")},
                                                   "id": secrets.token_hex(6), "quando": prox, "status": "agendada"})
                # guarda só os últimos 200 já resolvidos
                ativos = [x for x in e["agendadas"] if x["status"] == "agendada"]
                feitos = [x for x in e["agendadas"] if x["status"] != "agendada"][-200:]
                e["agendadas"] = ativos + feitos
                estado_gravar(e)


_chats_mem = {"chave": None, "t": 0.0, "v": None}
_chats_mem_lock = threading.Lock()


def api_chats():
    """[perf-patch v1] Mesmo resultado de _api_chats(), reaproveitado por até CACHE_TTL s enquanto o banco, o estado e a
    configuração não mudarem (vários aparelhos/abas pedindo ao mesmo tempo depois do mesmo aviso do /api/stream)."""
    chave = (_marca_db(), _marca_wa_db(), _marca_arq(ESTADO), _marca_arq(CONFIG), _nomes_cache["t"], _alias_cache["t"])
    with _chats_mem_lock:  # quem chega enquanto outro calcula espera e reaproveita
        if not (_chats_mem["chave"] == chave and time.monotonic() - _chats_mem["t"] < CACHE_TTL):
            _chats_mem.update(chave=chave, t=time.monotonic(), v=_api_chats())
        v = _chats_mem["v"]
    out = []
    for c in v:  # cópia rasa (e das listas/dicts internos) para ninguém alterar o cache sem querer
        d = dict(c)
        d["etiquetas"] = list(c["etiquetas"])
        if "lembrete" in c:
            d["lembrete"] = dict(c["lembrete"])
        if "ficha" in c:  # [ficha]
            d["ficha"] = dict(c["ficha"])
        out.append(d)
    return out


def _api_chats():
    nomes, lid2pn = carregar_nomes()
    cfg = config()
    db = ro(MSG_DB)
    chats = db.execute("select jid, name, last_message_time from chats").fetchall()
    ultimas = {}
    for cj, content, mt, me, sender, ts, rev in db.execute("""
            select m.chat_jid, m.content, m.media_type, m.is_from_me, m.sender, m.timestamp, coalesce(m.revoked, 0)
            from messages m join (select chat_jid, max(timestamp) t from messages group by chat_jid) x
              on m.chat_jid = x.chat_jid and m.timestamp = x.t"""):
        if rev:
            content, mt = "🚫 Mensagem apagada", ""
        ultimas[cj] = (content, mt, me, sender, ts)
    try:
        naolidas = contar_naolidas(db)
    except sqlite3.Error:
        naolidas = {}
    db.close()
    _est = estado_ler_cache()
    silenciados, fixados, arquivados = set(_est["silenciados"]), _est.get("fixados", []), set(_est.get("arquivados", []))
    etiquetas = _est.get("etiquetas", {})
    resolvidas = _est.get("resolvidas", {})
    lembretes = {x["jid"]: x for x in _est.get("lembretes", [])}
    fichas_ = _est.get("fichas", {})  # [ficha]
    _para_fav = aliases()[1]  # a favorita guarda o chat canonico; soma no canonico mesmo vindo do @lid
    favs_por_chat = {}
    for _f in _est.get("favoritas", []):
        _cj = str(_f.get("conversa") or _f.get("jid") or "")
        _cj = _para_fav.get(_cj, _cj)
        if _cj:
            favs_por_chat[_cj] = favs_por_chat.get(_cj, 0) + 1
    agora_min = time.strftime("%Y-%m-%dT%H:%M")
    out = []
    for jid, name, lmt in chats:
        titulo = nome_chat(jid, name, nomes, lid2pn)
        u = ultimas.get(jid)
        prev, ts = "", lmt
        if u:
            content, mt, me, sender, ts = u
            prev = content or ""
            if mt == "call":
                pass  # [chamadas] o texto já vem pronto da ponte ("Chamada de voz perdida")
            elif mt:
                prev = {"image": "📷 Imagem", "video": "🎥 Vídeo", "audio": "🎤 Áudio", "sticker": "🏷️ Figurinha",
                        "document": "📄 Documento"}.get(mt, mt) + ((": " + prev) if prev.strip() else "")
            if me:
                prev = "Você: " + prev
            elif jid.endswith("@g.us") and sender:
                prev = nome(sender, nomes, lid2pn) + ": " + prev
        espera = 0  # minutos desde a última mensagem recebida sem resposta do operador
        if u and not u[2] and ts and str(ts) > max(resolvidas.get(jid, ""), resolvidas.get(aliases()[1].get(jid, ""), "")):
            try:
                from datetime import datetime as _dt
                espera = max(0, int((time.time() - _dt.fromisoformat(str(ts)).timestamp()) // 60))
                if espera > 7 * 1440:  # mais de 7 dias: conversa fria, não conta como "esperando"
                    espera = 0
            except ValueError:
                espera = 0
        out.append({"jid": jid, "nome": titulo, "tipo": tipo_chat(jid), "oculto": oculto(jid, titulo, cfg),
                    "tel": (jid.split("@")[0] if jid.endswith("@s.whatsapp.net") else lid2pn.get(jid.split("@")[0], "")) if not jid.endswith("@g.us") else "",
                    "previa": prev[:120], "hora": str(ts or ""), "naolidas": naolidas.get(jid, 0), "mudo": jid in silenciados,
                    "fixado": (fixados.index(jid) + 1) if jid in fixados else 0, "arquivado": jid in arquivados,
                    "espera": espera, "etiquetas": etiquetas.get(jid, []), "favs": favs_por_chat.get(jid, 0)})
        c_ = out[-1]
        tags_ = set(c_["etiquetas"])
        fi_ = fichas_.get(jid)  # [ficha] resumo para o filtro e o cabeçalho
        if fi_:
            c_["ficha"] = {"status": fi_.get("status", ""), "venc": fi_.get("vencimento") or 0}
        lb = lembretes.get(jid)
        if lb:
            c_["lembrete"] = {"quando": lb["quando"], "nota": lb["nota"], "vencido": lb["quando"] <= agora_min}
        conta = (c_["tipo"] == "individual" or (c_["tipo"] == "grupo" and "Cliente" in tags_)) and "Pessoal" not in tags_ and "Família" not in tags_
        if not conta or (lb and lb["quando"] > agora_min):  # pessoal, grupo comum ou adiada: não é "esperando"
            c_["espera"] = 0
    de, para = aliases()
    if para:
        por = {c["jid"]: c for c in out}
        for extra, canon in para.items():
            c, x = por.get(canon), por.get(extra)
            if not c or not x:
                continue
            c["naolidas"] += x["naolidas"]
            if x["hora"] > c["hora"]:
                c["previa"], c["hora"], c["espera"] = x["previa"], x["hora"], x["espera"]
        out = [c for c in out if c["jid"] not in para]
    out.sort(key=lambda c: c["hora"], reverse=True)
    return out


# ---------- protobuf mínimo: dimensões e miniatura das mídias (para reservar o espaço da bolha) ----------
def _pb_campos(buf):
    """Percorre os campos de primeiro nível de uma mensagem protobuf: (numero, valor int | bytes)."""
    i, n = 0, len(buf)
    while i < n:
        chave, i = _pb_varint(buf, i)
        campo, tipo = chave >> 3, chave & 7
        if tipo == 0:
            v, i = _pb_varint(buf, i)
        elif tipo == 2:
            tam, i = _pb_varint(buf, i)
            v = buf[i:i + tam]
            i += tam
        elif tipo == 1:
            v, i = None, i + 8
        elif tipo == 5:
            v, i = None, i + 4
        else:
            return
        yield campo, v


def _pb_varint(buf, i):
    r = sh = 0
    while True:
        b = buf[i]
        i += 1
        r |= (b & 0x7F) << sh
        if b < 0x80:
            return r, i
        sh += 7


# campo da mensagem -> (campo altura, campo largura) ; miniatura JPEG é o campo 16 em imagem e vídeo
_PB_MIDIA = {3: (6, 7), 9: (9, 10), 26: (6, 7), 66: (9, 10)}


def info_midia_raw(raw):
    """(largura, altura, miniatura_jpeg|None) a partir do proto bruto guardado pela ponte."""
    try:
        for campo, v in _pb_campos(bytes(raw)):
            if campo in _PB_MIDIA and isinstance(v, (bytes, bytearray)):
                fh, fw = _PB_MIDIA[campo]
                w = h = 0
                mini = None
                for c2, v2 in _pb_campos(v):
                    if c2 == fh and isinstance(v2, int):
                        h = v2
                    elif c2 == fw and isinstance(v2, int):
                        w = v2
                    elif c2 == 16 and campo != 26 and isinstance(v2, (bytes, bytearray)) and v2:
                        mini = bytes(v2)
                return w, h, mini
    except (IndexError, ValueError):
        pass
    return 0, 0, None


def info_link_raw(raw):
    """Prévia de link que o próprio WhatsApp manda junto (ExtendedTextMessage): url, título, descrição, miniatura."""
    try:
        for campo, v in _pb_campos(bytes(raw)):
            if campo == 6 and isinstance(v, (bytes, bytearray)):
                d = {}
                for c2, v2 in _pb_campos(v):
                    if isinstance(v2, (bytes, bytearray)) and c2 in (2, 5, 6, 16):
                        d[c2] = bytes(v2)
                if 6 in d or 5 in d:
                    url = d.get(2, b"").decode("utf-8", "replace")
                    return {"url": url, "titulo": d.get(6, b"").decode("utf-8", "replace")[:200],
                            "desc": d.get(5, b"").decode("utf-8", "replace")[:300]}, d.get(16)
    except (IndexError, ValueError):
        pass
    return None, None


def miniatura(jid, mid):
    db = ro(MSG_DB)
    try:
        r = db.execute("select raw from messages where id=? and chat_jid=?", (mid, jid)).fetchone()
    except sqlite3.Error:
        r = None
    db.close()
    if not r or not r[0]:
        return None
    return info_midia_raw(r[0])[2] or info_link_raw(r[0])[1]


_msgs_mem = {}  # chave -> (t, resultado); poucas entradas
_msgs_mem_lock = threading.Lock()


def api_mensagens(jid, limite, incluir="", antes=""):
    """[perf-patch v1] Mesmo resultado de _api_mensagens(); reaproveita por até CACHE_TTL s se nada mudou (ex.: a pré-carga
    ao passar o mouse e a abertura logo depois, ou dois aparelhos na mesma conversa). Não alterar o objeto devolvido."""
    chave = (jid, limite, incluir, antes, _marca_db(), _marca_arq(TRANS_DB), _marca_arq(TRANS_DB + "-wal"), _marca_arq(ESTADO),
             _nomes_cache["t"], _alias_cache["t"], _eu["t"])
    agora = time.monotonic()
    with _msgs_mem_lock:
        c = _msgs_mem.get(chave)
        if c and agora - c[0] < CACHE_TTL:
            return c[1]
    v = _api_mensagens(jid, limite, incluir, antes)
    with _msgs_mem_lock:
        for k in [k for k, (t, _) in _msgs_mem.items() if agora - t >= CACHE_TTL]:
            _msgs_mem.pop(k, None)
        if len(_msgs_mem) < 16:
            _msgs_mem[chave] = (agora, v)
    return v


def _api_mensagens(jid, limite, incluir="", antes=""):
    nomes, lid2pn = carregar_nomes()
    db = ro(MSG_DB)
    r = db.execute("select name from chats where jid=?", (jid,)).fetchone()
    titulo = nome_chat(jid, r[0] if r else "", nomes, lid2pn)
    jids = jids_da_conversa(jid)
    marc = ",".join("?" * len(jids))
    if incluir:
        r_ = db.execute(f"select timestamp from messages where id=? and chat_jid in ({marc})", (incluir, *jids)).fetchone()
        if r_:
            n = db.execute(f"select count(*) from messages where chat_jid in ({marc}) and timestamp >= ?", (*jids, r_[0])).fetchone()[0]
            limite = max(limite, min(n + 30, 20000))
    if len(jids) == 1:  # [perf-patch v1] (id, chat_jid) é a chave primária: num chat só, count(id) == count(distinct id), sem B-tree temporária
        total = db.execute("select count(id) from messages where chat_jid = ?", jids).fetchone()[0]
    else:
        total = db.execute(f"select count(distinct id) from messages where chat_jid in ({marc})", jids).fetchone()[0]
    # [desempenho2] cursor: antes=<id da mensagem | timestamp> devolve so as `limite` anteriores a ele (o padrao continua sendo a janela final)
    _cond_antes, _par_antes = "", ()
    if antes:
        _r_a = db.execute(f"select timestamp from messages where id=? and chat_jid in ({marc})", (antes, *jids)).fetchone()
        if _r_a:
            _cond_antes, _par_antes = " and timestamp <= ? and id != ?", (_r_a[0], antes)
        else:
            _cond_antes, _par_antes = " and timestamp < ?", (antes,)
    novas = colunas_novas(db)
    extras = (", quoted_id, quoted_sender, quoted_text, mentions, forwarded, edited, revoked, status, extra,"
              " case when media_type in ('image','video','sticker') or (media_type = '' and content like '%http%') then raw end") if novas else ""
    rows = db.execute(f"""select id, sender, content, timestamp, is_from_me, media_type, filename{extras}, chat_jid
                         from messages where chat_jid in ({marc}){_cond_antes} order by timestamp desc limit ?""", (*jids, *_par_antes, limite)).fetchall()
    reacoes, versao = {}, 0
    try:
        versao = (db.execute("select seq from panel_changes where id=1").fetchone() or [0])[0]
    except sqlite3.Error:
        pass
    if novas and rows:
        try:
            for mid, snd, emo, me in db.execute(
                    f"select message_id, sender, emoji, from_me from reactions where chat_jid in ({marc}) order by timestamp", jids):
                reacoes.setdefault(mid, []).append({"emoji": emo, "eu": bool(me) or snd == "me",
                                                    "quem": "Você" if (me or snd == "me") else nome(snd, nomes, lid2pn)})
        except sqlite3.Error:
            pass
    db.close()
    trans = {}
    if os.path.exists(TRANS_DB):
        try:
            t = ro(TRANS_DB)
            trans = {i: tx for i, tx in t.execute(f"select id, texto from transcricoes where chat_jid in ({marc})", jids)}
            t.close()
        except Exception:
            pass
    favs = {f["id"] for f in estado_ler_cache().get("favoritas", [])}
    msgs, ja = [], set()
    for r in reversed(rows):
        if r[0] in ja:  # duplicada entre os dois chats da mesma conversa
            continue
        ja.add(r[0])
        mid, sender, content, ts, me, mt, fn = r[:7]
        m = {"id": mid, "eu": bool(me), "remetente": "" if me else nome(sender, nomes, lid2pn),
             "remetente_jid": "" if me else (sender or ""),
             "texto": (content or "") if (content or "").strip() else "",
             "hora": str(ts or ""), "midia": mt or "", "arquivo": fn or "", "transcricao": limpar_transcricao(trans.get(mid)) or None}
        if mid in favs:
            m["favorita"] = True
        if r[-1] != jid:
            m["chat"] = r[-1]  # mensagem guardada no outro chat da mesma conversa (@lid / número)
        if novas:
            qid, qsnd, qtxt, mencoes, fwd, edt, rev, status, extra, raw = r[7:-1]
            if raw and not mt:
                lk, lmini = info_link_raw(raw)
                if lk and lk["url"].startswith(("http://", "https://")):
                    lk["mini"] = bool(lmini)
                    m["link"] = lk
            elif raw:
                w, h, mini = info_midia_raw(raw)
                if w and h:
                    m["dim"] = [w, h]
                if mini:
                    m["mini"] = True
            if qid:
                eu_q = bool(qsnd) and qsnd.split("@")[0].split(":")[0] in meus_ids()
                m["citacao"] = {"id": qid, "texto": qtxt or "", "eu": eu_q,
                                "quem": "Você" if eu_q else (nome(qsnd, nomes, lid2pn) if qsnd else "")}
            if mencoes:
                try:
                    m["mencoes"] = {j.split("@")[0]: nome(j, nomes, lid2pn) for j in json.loads(mencoes)}
                except (ValueError, TypeError, AttributeError):
                    pass
            if fwd:
                m["encaminhada"] = True
            if edt:
                m["editada"] = True
            if rev:
                m["apagada"] = True
                m["texto"] = ""
            if me:
                m["status"] = status or 0
            if extra:
                try:
                    m["extra"] = json.loads(extra)
                except ValueError:
                    pass
            if mid in reacoes:
                m["reacoes"] = reacoes[mid]
        msgs.append(m)
    _res = {"jid": jid, "nome": titulo, "tipo": tipo_chat(jid), "total": total, "versao": versao, "mensagens": msgs}
    if antes:
        _res["antes"] = antes
        _res["mais"] = len(rows) >= limite
    return _res


_colunas = {"ok": None, "t": 0}


def colunas_novas(db):
    """True quando a ponte já criou as colunas extras (citação, reações, status...)."""
    if _colunas["ok"] is None or (not _colunas["ok"] and time.time() - _colunas["t"] > 30):
        cols = {r[1] for r in db.execute("pragma table_info(messages)")}
        _colunas.update(ok={"quoted_id", "status", "extra", "revoked"} <= cols, t=time.time())
    return _colunas["ok"]


_eu = {"ids": set(), "t": 0}


def meus_ids():
    """Número e LID da própria conta (para saber quais citações/reações são minhas)."""
    if not _eu["ids"] or time.time() - _eu["t"] > 600:
        try:
            with urllib.request.urlopen(PONTE + "/api/me", timeout=3) as r:
                d = json.load(r)
            _eu["ids"] = {j.split("@")[0] for j in (d.get("jid"), d.get("lid")) if j}
        except Exception:
            pass
        _eu["t"] = time.time()
    return _eu["ids"]


def baixar_midia(mid, jid):
    db = ro(MSG_DB)
    r = db.execute("select media_type, filename from messages where id=? and chat_jid=?", (mid, jid)).fetchone()
    db.close()
    if not r or r[0] not in ("image", "video", "audio", "document", "sticker"):
        return None, None, None
    chave = (mid, jid)
    with _lock:
        p = _midia_cache.get(chave)
    if p and os.path.isfile(p):
        return p, r[0], r[1]
    req = urllib.request.Request(BRIDGE, data=json.dumps({"message_id": mid, "chat_jid": jid}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            path = json.load(resp).get("path")
    except Exception as e:  # ponte fora do ar / reiniciando
        raise PonteIndisponivel(str(e))
    if path and os.path.isfile(path):
        with _lock:
            _midia_cache[chave] = path
        return path, r[0], r[1]
    return None, r[0], r[1]


class PonteIndisponivel(Exception):
    pass


_assin_mem = {"chave": None, "t": 0.0, "v": None}
_assin_lock = threading.Lock()


def assinatura():
    """[perf-patch v1] Mesmo valor de _assinatura_bruta(), mas: (a) vários /api/stream abertos dividem a mesma consulta
    (no máx. 1 por ~0,9 s) e (b) com os arquivos do banco e das transcrições parados (mtime/tamanho iguais), só reconsulta
    a cada 5 s. Uma gravação da ponte muda o WAL e força a consulta na hora."""
    chave = (_marca_db(), _marca_arq(TRANS_DB), _marca_arq(TRANS_DB + "-wal"))
    with _assin_lock:
        idade = time.monotonic() - _assin_mem["t"]
        if _assin_mem["v"] is None or not (idade < 0.9 or (_assin_mem["chave"] == chave and idade < 5)):
            _assin_mem.update(chave=chave, t=time.monotonic(), v=_assinatura_bruta()[0])
        msg = _assin_mem["v"]
    try:
        dem = str(os.path.getmtime(DEMANDAS))
    except OSError:
        dem = ""
    return msg, dem


def _assinatura_bruta():
    """Assinatura barata do estado: muda quando chega mensagem, transcrição ou demandas.md é alterado."""
    partes = []
    try:
        db = ro(MSG_DB)
        partes.append(db.execute("select max(rowid), max(timestamp), count(*) from messages").fetchone())
        partes.append(db.execute("select max(last_message_time), count(*) from chats").fetchone())
        try:  # edições, reações, apagadas e confirmações de leitura
            partes.append(db.execute("select seq from panel_changes where id=1").fetchone())
        except sqlite3.Error:
            pass
        db.close()
    except Exception:
        partes.append("msgdb?")
    try:
        if os.path.exists(TRANS_DB):
            t = ro(TRANS_DB)
            partes.append(t.execute("select count(*), max(rowid) from transcricoes").fetchone())
            t.close()
    except Exception:
        partes.append("trans?")
    msg = json.dumps(partes, default=str)
    try:
        dem = str(os.path.getmtime(DEMANDAS))
    except OSError:
        dem = ""
    return msg, dem


_midia_cache = {}
TIPOS = {".ogg": "audio/ogg", ".oga": "audio/ogg", ".opus": "audio/ogg", ".mp3": "audio/mpeg", ".m4a": "audio/mp4",
         ".aac": "audio/aac", ".wav": "audio/wav", ".amr": "audio/amr", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
         ".png": "image/png", ".webp": "image/webp", ".gif": "image/gif", ".mp4": "video/mp4", ".3gp": "video/3gpp",
         ".webm": "video/webm", ".mov": "video/quicktime", ".pdf": "application/pdf"}
PADRAO = {"image": "image/jpeg", "audio": "audio/ogg", "video": "video/mp4", "document": "application/octet-stream",
          "sticker": "image/webp"}


def tipo_midia(path, mt):
    if mt == "sticker":
        return "image/webp"
    t = TIPOS.get(os.path.splitext(path)[1].lower()) or mimetypes.guess_type(path)[0] or PADRAO[mt]
    # Imagem/áudio/vídeo sempre com tipo da própria família (nunca HTML/script servido no domínio do painel).
    if mt in ("image", "audio", "video") and not t.startswith(mt + "/"):
        t = PADRAO[mt]
    return t


# ---- envio ----
class ErroEnvio(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


EXT_BLOQUEADAS = {"exe", "bat", "cmd", "com", "scr", "msi", "ps1", "vbs", "vbe", "wsf", "wsh", "lnk",
                  "dll", "hta", "cpl", "reg", "jar", "pif", "msp", "gadget"}


def nome_seguro(nome, ext_padrao=""):
    base, ext = os.path.splitext(os.path.basename(nome or "arquivo"))
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._")[:60] or "arquivo"
    ext = re.sub(r"[^A-Za-z0-9.]", "", ext.lower())[:10] or ext_padrao
    return f"{time.strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(3)}_{base}{ext}"


def converter_voz(origem):
    """webm/ogg (Opus) gravado no navegador -> .ogg Opus mono 48 kHz (nota de voz do WhatsApp)."""
    try:
        import av
    except ImportError:
        raise ErroEnvio("PyAV não está instalado; inicie o painel pelo iniciar-painel.cmd", 500)
    destino = os.path.splitext(origem)[0] + ".ogg"
    if os.path.abspath(destino) == os.path.abspath(origem):  # gravado já em .ogg (Firefox): não sobrescrever a origem
        destino = os.path.splitext(origem)[0] + "-voz.ogg"
    ent = av.open(origem)
    try:
        a = next(s for s in ent.streams if s.type == "audio")
        # 1) remux direto: DESLIGADO — o .webm do navegador reembalado em .ogg dava "erro" no celular de alguns
        #    contatos (19/11). Sempre recodifica com libopus, que gera o Ogg/Opus padrão das notas de voz.
        if False and a.codec_context.name == "opus" and a.codec_context.channels == 1:
            try:
                with av.open(destino, "w", format="ogg") as sai:
                    if hasattr(sai, "add_stream_from_template"):
                        o = sai.add_stream_from_template(a)
                    else:
                        o = sai.add_stream(template=a)
                    for pk in ent.demux(a):
                        if pk.dts is None:
                            continue
                        pk.stream = o
                        sai.mux(pk)
                if os.path.getsize(destino) > 200:
                    return destino
            except Exception:
                pass
            ent.close()
            ent = av.open(origem)
            a = next(s for s in ent.streams if s.type == "audio")
        # 2) transcodifica com libopus
        with av.open(destino, "w", format="ogg") as sai:
            o = sai.add_stream("libopus", rate=48000)
            try:
                o.layout = "mono"
            except Exception:
                o.codec_context.layout = "mono"
            o.bit_rate = 32000
            rs = av.AudioResampler(format="s16", layout="mono", rate=48000)
            for fr in ent.decode(a):
                fr.pts = None
                for f2 in rs.resample(fr):
                    for pk in o.encode(f2):
                        sai.mux(pk)
            for f2 in rs.resample(None):
                for pk in o.encode(f2):
                    sai.mux(pk)
            for pk in o.encode(None):
                sai.mux(pk)
    finally:
        ent.close()
    return destino


def converter_figurinha(origem):
    """Imagem qualquer -> figurinha 512x512 WebP (fundo transparente), arquivo *.sticker.webp."""
    try:
        from PIL import Image, ImageOps
    except ImportError:
        raise ErroEnvio("Pillow não está instalado; inicie o painel pelo iniciar-painel.cmd", 500)
    with Image.open(origem) as im:
        im = ImageOps.exif_transpose(im).convert("RGBA")
        im.thumbnail((512, 512), Image.LANCZOS)
        tela = Image.new("RGBA", (512, 512), (0, 0, 0, 0))
        tela.paste(im, ((512 - im.width) // 2, (512 - im.height) // 2), im)
    destino = os.path.splitext(origem)[0] + ".sticker.webp"
    for q in (85, 70, 55, 40):
        tela.save(destino, "WEBP", quality=q, method=4)  # method=6 levava ~4s por figurinha
        if os.path.getsize(destino) <= 100 * 1024:
            break
    return destino


def _miniatura_jpeg(im, lado=100):
    from PIL import Image
    import base64, io
    im = im.convert("RGB")
    im.thumbnail((lado, lado), Image.LANCZOS)
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=60)
    return base64.b64encode(buf.getvalue()).decode()


def metadados_midia(path):
    """Duração, dimensões, miniatura e forma de onda do arquivo (o WhatsApp mostra isso antes de baixar)."""
    import base64
    ext = os.path.splitext(path)[1].lower()
    meta = {}
    if path.lower().endswith(".sticker.webp"):
        return meta
    try:
        if ext in (".jpg", ".jpeg", ".png", ".gif", ".webp"):
            from PIL import Image, ImageOps
            with Image.open(path) as im:
                im = ImageOps.exif_transpose(im)
                meta["width"], meta["height"] = im.size
                meta["thumbnail"] = _miniatura_jpeg(im)
        elif ext in (".mp4", ".mov", ".webm", ".3gp", ".avi"):
            import av
            with av.open(path) as c:
                v = next((s for s in c.streams if s.type == "video"), None)
                if c.duration:
                    meta["seconds"] = max(1, round(c.duration / 1_000_000))
                if v is not None:
                    meta["width"], meta["height"] = v.codec_context.width, v.codec_context.height
                    for fr in c.decode(v):
                        meta["thumbnail"] = _miniatura_jpeg(fr.to_image())
                        break
        elif ext in (".ogg", ".opus", ".mp3", ".m4a", ".aac", ".wav"):
            import av
            with av.open(path) as c:
                a = next(s for s in c.streams if s.type == "audio")
                amostras = []
                for fr in c.decode(a):
                    arr = fr.to_ndarray()
                    if arr.ndim > 1:
                        arr = abs(arr.astype("float32")).mean(axis=0)
                    else:
                        arr = abs(arr.astype("float32"))
                    amostras.append(arr)
                dur = None
                if c.duration:
                    dur = c.duration / 1_000_000
            if amostras:
                import numpy as np
                tudo = np.concatenate(amostras)
                if dur is None:
                    dur = len(tudo) / (a.codec_context.sample_rate or 48000)
                if ext in (".ogg", ".opus"):  # forma de onda da nota de voz (64 barras, 0-100)
                    blocos = np.array_split(tudo, 64)
                    niveis = np.array([float(np.sqrt((b ** 2).mean())) if len(b) else 0.0 for b in blocos])
                    topo = niveis.max() or 1.0
                    meta["waveform"] = base64.b64encode(bytes(int(round(x / topo * 100)) for x in niveis)).decode()
            if dur:
                meta["seconds"] = max(1, round(dur))
    except Exception as e:  # metadados são opcionais; o envio segue sem eles
        print("aviso: metadados de mídia indisponíveis:", type(e).__name__, e)
    return meta


def jid_conhecido(jid):
    db = ro(MSG_DB)
    ok = db.execute("select 1 from chats where jid=?", (jid,)).fetchone()
    db.close()
    return bool(ok)


def caminho_upload(path):
    if not path:
        return ""
    real = os.path.realpath(path)
    raiz = os.path.realpath(UPLOADS) + os.sep
    if not real.startswith(raiz) or not os.path.isfile(real):
        raise ErroEnvio("arquivo de envio inválido")
    return real


def chamar_ponte(rota, corpo, timeout=180):
    req = urllib.request.Request(PONTE + rota, data=json.dumps(corpo).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            txt = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        txt = e.read().decode("utf-8", "replace")
        try:
            return json.loads(txt)
        except Exception:
            raise ErroEnvio(f"ponte respondeu {e.code}: {txt[:200]}", 502)
    except Exception as e:
        raise ErroEnvio(f"ponte do WhatsApp indisponível: {e}", 503)
    try:
        return json.loads(txt)
    except Exception:
        return {"success": True, "message": txt[:200]}


def enviar_mensagem(dados):
    jid = str(dados.get("jid") or "")
    texto = str(dados.get("texto") or "")
    path = caminho_upload(dados.get("path") or "")
    if not jid or not (jid_conhecido(jid) or numero_liberado(jid)):  # [numeros] 1ª mensagem para número confirmado
        raise ErroEnvio("conversa desconhecida")
    local, contato = dados.get("local"), dados.get("contato")
    if not texto.strip() and not path and not local and not contato:
        raise ErroEnvio("nada para enviar")
    corpo = {"recipient": jid, "message": texto}
    if path:
        corpo["media_path"] = path
        corpo.update(metadados_midia(path))
        nome_orig = os.path.basename(str(dados.get("nome") or ""))
        # nome original só quando a extensão bate (voz gravada em .webm vira .ogg; figurinha vira .sticker.webp)
        if nome_orig and not path.lower().endswith(".sticker.webp") \
                and os.path.splitext(nome_orig)[1].lower() == os.path.splitext(path)[1].lower():
            corpo["filename"] = nome_orig[:120]
        if dados.get("tipo") == "voz":
            corpo["ptt"] = True
    if dados.get("responder"):
        corpo["reply_to"] = str(dados["responder"])
    if isinstance(dados.get("mencoes"), list):
        corpo["mentions"] = [str(m) for m in dados["mencoes"] if "@" in str(m)][:50]
    if isinstance(local, dict):
        try:
            corpo["location"] = {"lat": float(local["lat"]), "lng": float(local["lng"]),
                                 "name": str(local.get("nome") or "")[:200], "address": str(local.get("endereco") or "")[:300]}
        except (KeyError, TypeError, ValueError):
            raise ErroEnvio("localização inválida")
    if isinstance(contato, dict):
        nomec = str(contato.get("nome") or "").strip()[:100]
        tel = re.sub(r"\D", "", str(contato.get("telefone") or ""))[:20]
        if not nomec or not tel:
            raise ErroEnvio("contato precisa de nome e telefone")
        corpo["contact"] = {"name": nomec, "vcard": "BEGIN:VCARD\nVERSION:3.0\nN:;%s;;;\nFN:%s\nTEL;type=CELL;waid=%s:+%s\nEND:VCARD"
                            % (nomec.replace(";", " "), nomec, tel, tel)}
    if DRYRUN or dados.get("dry_run"):
        return {"success": True, "dry_run": True, "enviaria": {"/api/send": corpo, "/api/read": {"chat_jid": jid}}}
    r = chamar_ponte("/api/send", corpo)
    if not r.get("success"):
        raise ErroEnvio(r.get("message") or "falha no envio", 502)
    if path:  # a ponte guarda a própria cópia em store\; apaga o upload (e o original antes da conversão)
        prefixo = "_".join(os.path.basename(path).split("_")[:3]) + "_"
        for f in os.listdir(UPLOADS):
            if f.startswith(prefixo):
                try:
                    os.remove(os.path.join(UPLOADS, f))
                except OSError:
                    pass
    if dados.get("sem_ler"):  # envio automático (agendado): o operador não viu as mensagens, não marca como lidas
        return r
    try:  # marca a conversa como lida (best effort)
        r["lida"] = chamar_ponte("/api/read", {"chat_jid": jid}, timeout=30)
    except ErroEnvio as e:
        r["lida"] = {"success": False, "message": str(e)}
    return r


def apagar_para_todos(dados):
    jid, mid = str(dados.get("jid") or ""), str(dados.get("id") or "")
    if not jid or not mid or not jid_conhecido(jid):
        raise ErroEnvio("mensagem desconhecida")
    db = ro(MSG_DB)
    r = db.execute("select is_from_me, timestamp from messages where id=? and chat_jid=?", (mid, jid)).fetchone()
    db.close()
    if not r:
        raise ErroEnvio("mensagem não encontrada")
    if not r[0]:
        raise ErroEnvio("só é possível apagar para todos as suas próprias mensagens")
    _d_ap = _auto_ts(r[1])  # [autonomia] o WhatsApp recusa depois de ~2 dias
    if _d_ap and time.time() - _d_ap.timestamp() > APAGAR_LIMITE_S:
        raise ErroEnvio("passou do prazo do WhatsApp para apagar para todos (cerca de 2 dias)")
    if DRYRUN or dados.get("dry_run"):
        return {"success": True, "dry_run": True, "enviaria": {"/api/revoke": {"chat_jid": jid, "message_id": mid}}}
    r = chamar_ponte("/api/revoke", {"chat_jid": jid, "message_id": mid}, timeout=30)
    if not r.get("success"):
        raise ErroEnvio(r.get("message") or "falha ao apagar", 502)
    return r


def _msg_existe(jid, mid):
    if not jid or not mid or not jid_conhecido(jid):
        raise ErroEnvio("mensagem desconhecida")
    db = ro(MSG_DB)
    r = db.execute("select is_from_me, media_type from messages where id=? and chat_jid=?", (mid, jid)).fetchone()
    db.close()
    if not r:
        raise ErroEnvio("mensagem não encontrada")
    return bool(r[0]), r[1] or ""


def _ponte_ok(rota, corpo, dados, erro):
    if DRYRUN or dados.get("dry_run"):
        return {"success": True, "dry_run": True, "enviaria": {rota: corpo}}
    r = chamar_ponte(rota, corpo, timeout=60)
    if not r.get("success"):
        raise ErroEnvio(r.get("message") or erro, 502)
    return r


def reagir(dados):
    jid, mid = str(dados.get("jid") or ""), str(dados.get("id") or "")
    emoji = str(dados.get("emoji") or "")[:16]
    _msg_existe(jid, mid)
    return _ponte_ok("/api/react", {"chat_jid": jid, "message_id": mid, "emoji": emoji}, dados, "falha ao reagir")


def editar(dados):
    jid, mid, texto = str(dados.get("jid") or ""), str(dados.get("id") or ""), str(dados.get("texto") or "")
    eu, _ = _msg_existe(jid, mid)
    if not eu:
        raise ErroEnvio("só é possível editar as suas próprias mensagens")
    if not texto.strip():
        raise ErroEnvio("o texto não pode ficar vazio")
    # a ponte só aceita edição de teste (chat próprio / Arquivos) até a edição ser verificada
    return _ponte_ok("/api/edit", {"chat_jid": jid, "message_id": mid, "message": texto, "test": True}, dados, "falha ao editar")


def encaminhar(dados):
    jid, mid, destino = str(dados.get("jid") or ""), str(dados.get("id") or ""), str(dados.get("destino") or "")
    _msg_existe(jid, mid)
    if not destino or not jid_conhecido(destino):
        raise ErroEnvio("conversa de destino desconhecida")
    return _ponte_ok("/api/forward", {"chat_jid": jid, "message_id": mid, "recipient": destino}, dados, "falha ao encaminhar")


def marcar_lida(dados):
    jid = str(dados.get("jid") or "")
    if not jid or not jid_conhecido(jid):
        raise ErroEnvio("conversa desconhecida")
    if DRYRUN or dados.get("dry_run"):
        return {"success": True, "dry_run": True, "enviaria": {"/api/read": {"chat_jid": jid}}}
    marcar_visto(jid)
    return chamar_ponte("/api/read", {"chat_jid": jid}, timeout=30)


def meu_jid_teste():
    jid = ponte_get("/api/me", timeout=5).get("jid", "")
    if not jid.endswith("@s.whatsapp.net"):
        raise ErroEnvio("Conecte seu WhatsApp antes de enviar um teste")
    return jid

# ==================== [campanhas] Programação em grupos ====================
# Anúncio recorrente nos grupos que o operador escolher (ex.: venda de itens de produtos). Só envia campanhas que ELE
# criou e deixou ligadas. Regras de segurança:
#   - no máx. 20 grupos por campanha, só jids @g.us que existem no banco; mínimo de 20 s entre QUAISQUER dois envios
#     de campanha e intervalo sorteado (padrão 25-75 s) entre um grupo e o próximo;
#   - cada envio tem uma chave campanha|dia|horário|grupo gravada ANTES de enviar e marcada depois: nunca sai duas vezes;
#   - horário com mais de 30 min de atraso (PC desligado, painel fechado) vira "pulado", não sai atrasado;
#   - falha temporária da ponte (503/tempo esgotado) tenta de novo 1 vez após 2 min, conferindo antes no banco se a
#     mensagem já saiu; "enviando" encontrado na partida (painel fechou no meio) nunca é reenviado sozinho;
#   - envia com sem_ler=True (não marca o grupo como lido). O teste vai SÓ para o chat do próprio operador.
import random as _camp_random
import shutil as _camp_shutil
from datetime import datetime as _cdt, timedelta as _ctd, time as _ctime

CAMP_MIDIA = os.path.join(AQUI, "campanhas_midia")

CAMP_MAX_GRUPOS = 20
CAMP_MAX_CAMPANHAS = 50
CAMP_MAX_VARIACOES = 10
CAMP_MAX_HORARIOS = 24
CAMP_GAP_GLOBAL = 20          # s entre dois envios quaisquer de campanha
CAMP_ATRASO_MAX = 30 * 60     # s; mais atrasado que isso vira "pulado"
CAMP_RETRY_SEG = 120          # nova tentativa após falha temporária
CAMP_HIST_DIAS = 7
CAMP_MIDIA_MAX = 64 * 1024 * 1024
CAMP_EXT = {".jpg": "image", ".jpeg": "image", ".png": "image", ".mp4": "video", ".3gp": "video", ".mov": "video"}
CAMP_DIAS_NOME = ["domingo", "segunda-feira", "terça-feira", "quarta-feira", "quinta-feira", "sexta-feira", "sábado"]
_RE_CAMP_HM = re.compile(r"([01]\d|2[0-3]):[0-5]\d")
_RE_CAMP_GRUPO = re.compile(r"[0-9]{5,25}(-[0-9]{5,15})?@g\.us")
_RE_CAMP_ARQ = re.compile(r"[0-9a-f]{12}_[0-9a-f]{8}\.[a-z0-9]{2,4}")
_camp_rng = _camp_random.SystemRandom()
_camp_teste = {"t": 0.0}
_camp_envio_lock = threading.Lock()   # um envio de campanha por vez (loop e "reenviar" nunca em paralelo)


def _camp_agora():
    return _cdt.now()


def _camp_iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%S")


def _camp_dt(s):
    try:
        return _cdt.strptime(str(s or "")[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def _camp_dow(d):
    return (d.weekday() + 1) % 7  # 0 = domingo, igual ao getDay() do navegador


def _camp_estado(e):
    """Seção "campanhas" do painel_estado.json (cria o que faltar). Usar só dentro do _estado_lock."""
    c = e.get("campanhas")
    if not isinstance(c, dict):
        c = e["campanhas"] = {}
    c.setdefault("lista", [])
    c.setdefault("execucoes", {})
    c.setdefault("fila", [])
    c.setdefault("pausado_tudo", False)
    c.setdefault("ultimo_envio", "")
    return c


def _camp_ro():
    c = estado_ler_cache().get("campanhas")
    c = c if isinstance(c, dict) else {}
    return {"lista": c.get("lista") or [], "execucoes": c.get("execucoes") or {}, "fila": c.get("fila") or [],
            "pausado_tudo": bool(c.get("pausado_tudo")), "ultimo_envio": c.get("ultimo_envio") or ""}


# ---------- validação ----------
def _camp_horarios(v, vazio_ok=False):
    if isinstance(v, str):
        v = re.split(r"[,;\s]+", v)
    if not isinstance(v, list):
        raise ErroEnvio("horários inválidos")
    hs = sorted({str(h).strip() for h in v if str(h or "").strip()})
    for h in hs:
        if not _RE_CAMP_HM.fullmatch(h):
            raise ErroEnvio(f"horário inválido: {h[:10]} (use HH:MM)")
    if not hs and not vazio_ok:
        raise ErroEnvio("adicione pelo menos um horário")
    if len(hs) > CAMP_MAX_HORARIOS:
        raise ErroEnvio(f"no máximo {CAMP_MAX_HORARIOS} horários")
    return hs


def _camp_data(v, campo):
    v = str(v or "").strip()
    if not v:
        return ""
    try:
        _cdt.strptime(v, "%Y-%m-%d")
    except ValueError:
        raise ErroEnvio(f"data de {campo} inválida")
    return v


def _camp_no_silencio(h, sil):
    if not sil:
        return False
    ini, fim = sil["ini"], sil["fim"]
    return ini <= h < fim if ini < fim else (h >= ini or h < fim)


def _camp_validar(d, atual=None):
    a = atual or {}

    def g(k, padrao=None):
        return d[k] if k in d else a.get(k, padrao)

    nome_ = re.sub(r"\s+", " ", str(g("nome", "") or "")).strip()[:60]
    if not nome_:
        raise ErroEnvio("dê um nome à campanha")
    vs = g("variacoes", None)
    if vs is None:
        vs = [g("texto", "")]
    if isinstance(vs, str):
        vs = [vs]
    if not isinstance(vs, list):
        raise ErroEnvio("variações inválidas")
    vs = [str(x).strip()[:4000] for x in vs if str(x or "").strip()]
    if len(vs) > CAMP_MAX_VARIACOES:
        raise ErroEnvio(f"no máximo {CAMP_MAX_VARIACOES} variações")
    modo = str(g("modo_variacao", "rodizio") or "rodizio")
    if modo not in ("rodizio", "aleatorio"):
        raise ErroEnvio("ordem das variações inválida")
    grupos = g("grupos", [])
    if not isinstance(grupos, list):
        raise ErroEnvio("grupos inválidos")
    vistos, gs = set(), []
    for j in grupos:
        j = str(j or "")
        if j and j not in vistos:
            vistos.add(j)
            gs.append(j)
    if not gs:
        raise ErroEnvio("escolha pelo menos um grupo")
    if len(gs) > CAMP_MAX_GRUPOS:
        raise ErroEnvio(f"no máximo {CAMP_MAX_GRUPOS} grupos por campanha")
    for j in gs:
        if not _RE_CAMP_GRUPO.fullmatch(j) or not jid_conhecido(j):
            raise ErroEnvio(f"grupo desconhecido: {j[:40]}")
    horarios = _camp_horarios(g("horarios", []))
    hg_in = g("horarios_grupo", {}) or {}
    if not isinstance(hg_in, dict):
        raise ErroEnvio("horários por grupo inválidos")
    hg = {}
    for j, hs in hg_in.items():
        if j in vistos:
            hs = _camp_horarios(hs, vazio_ok=True)
            if hs:
                hg[j] = hs
    dias = g("dias", list(range(7)))
    if not isinstance(dias, list):
        raise ErroEnvio("dias inválidos")
    try:
        dias = sorted({int(x) for x in dias})
    except (TypeError, ValueError):
        raise ErroEnvio("dias inválidos")
    if not dias or any(x < 0 or x > 6 for x in dias):
        raise ErroEnvio("escolha pelo menos um dia da semana")
    try:
        imin, imax = int(g("intervalo_min", 25)), int(g("intervalo_max", 75))
    except (TypeError, ValueError):
        raise ErroEnvio("intervalo inválido")
    if not (CAMP_GAP_GLOBAL <= imin <= imax <= 900):
        raise ErroEnvio(f"intervalo entre grupos: mínimo {CAMP_GAP_GLOBAL} s, máximo 900 s (e o mínimo não pode passar do máximo)")
    inicio, fim = _camp_data(g("inicio", ""), "início"), _camp_data(g("fim", ""), "fim")
    if inicio and fim and fim < inicio:
        raise ErroEnvio("a data final é antes da inicial")
    sil = g("silencio", None)
    if sil:
        if not isinstance(sil, dict):
            raise ErroEnvio("janela de silêncio inválida")
        sil = {"ini": str(sil.get("ini") or ""), "fim": str(sil.get("fim") or "")}
        if not _RE_CAMP_HM.fullmatch(sil["ini"]) or not _RE_CAMP_HM.fullmatch(sil["fim"]) or sil["ini"] == sil["fim"]:
            raise ErroEnvio("janela de silêncio inválida (use HH:MM, início diferente do fim)")
        for h in horarios + [x for hs in hg.values() for x in hs]:
            if _camp_no_silencio(h, sil):
                raise ErroEnvio(f"o horário {h} cai na janela de silêncio ({sil['ini']}–{sil['fim']})")
    else:
        sil = None
    return {"nome": nome_, "variacoes": vs, "texto": vs[0] if vs else "", "modo_variacao": modo, "grupos": gs,
            "horarios": horarios, "horarios_grupo": hg, "dias": dias, "intervalo_min": imin, "intervalo_max": imax,
            "inicio": inicio, "fim": fim, "silencio": sil, "ativo": bool(g("ativo", True))}


# ---------- mídia (cópia própria em painel\campanhas_midia; uploads somem em 1 dia e após cada envio) ----------
def _camp_midia_origem(d):
    """(arquivo de origem, nome, tipo sugerido) da mídia nova pedida, ou None."""
    acao = str(d.get("midia_acao") or "manter")
    if acao == "upload":
        p = caminho_upload(str(d.get("midia_path") or ""))
        if not p:
            raise ErroEnvio("arquivo de envio inválido")
        return p, os.path.basename(str(d.get("midia_nome") or p)), ""
    if acao == "mensagem":
        mm = d.get("midia_msg") if isinstance(d.get("midia_msg"), dict) else {}
        jid, mid = str(mm.get("jid") or ""), str(mm.get("id") or "")
        eu, mt = _msg_existe(jid, mid)
        if not eu:
            raise ErroEnvio("só dá para usar a mídia de uma mensagem sua")
        if mt not in ("image", "video"):
            raise ErroEnvio("essa mensagem não tem foto nem vídeo")
        try:
            p, _, fn = baixar_midia(mid, jid)
        except PonteIndisponivel:
            raise ErroEnvio("ponte do WhatsApp indisponível; tente de novo", 503)
        if not p or not os.path.isfile(p):
            raise ErroEnvio("não encontrei o arquivo dessa mídia")
        return p, os.path.basename(fn or p), mt
    if acao not in ("manter", "remover", "nenhuma", ""):
        raise ErroEnvio("mídia inválida")
    return None


def _camp_tipo_arquivo(path, dica=""):
    ext = os.path.splitext(path)[1].lower()
    t = CAMP_EXT.get(ext)
    if not t and dica in ("image", "video"):  # arquivo da ponte sem extensão conhecida
        t, ext = dica, (".jpg" if dica == "image" else ".mp4")
    if not t:
        raise ErroEnvio("a mídia precisa ser foto (JPG/PNG) ou vídeo (MP4/MOV/3GP)")
    if os.path.getsize(path) > CAMP_MIDIA_MAX:
        raise ErroEnvio("mídia maior que 64 MB")
    return t, ext


def _camp_guardar_midia(cid, origem, nome_, dica=""):
    t, ext = _camp_tipo_arquivo(origem, dica)
    os.makedirs(CAMP_MIDIA, exist_ok=True)
    arq = f"{cid}_{secrets.token_hex(4)}{ext}"
    _camp_shutil.copyfile(origem, os.path.join(CAMP_MIDIA, arq))
    base = os.path.splitext(os.path.basename(nome_ or "midia"))[0][:100] or "midia"
    return {"arquivo": arq, "nome": base + ext, "tipo": t, "bytes": os.path.getsize(os.path.join(CAMP_MIDIA, arq))}


def _camp_midia_path(m):
    arq = str((m or {}).get("arquivo") or "")
    if not _RE_CAMP_ARQ.fullmatch(arq):
        return ""
    p = os.path.join(CAMP_MIDIA, arq)
    return p if os.path.isfile(p) else ""


def _camp_apagar_midia(m):
    p = _camp_midia_path(m)
    if p:
        try:
            os.remove(p)
        except OSError:
            pass


def _camp_copia_envio(origem, dica=""):
    """Cópia descartável em uploads\\ (o enviar_mensagem apaga o upload depois de enviar)."""
    os.makedirs(UPLOADS, exist_ok=True)
    _, ext = _camp_tipo_arquivo(origem, dica)
    dest = os.path.join(UPLOADS, nome_seguro("campanha" + ext, ext))
    _camp_shutil.copyfile(origem, dest)
    return dest


# ---------- texto ----------
def _camp_texto(c, idx, quando):
    vs = c.get("variacoes") or ([c["texto"]] if c.get("texto") else [])
    if not vs:
        return ""
    t = vs[idx % len(vs)]
    return (t.replace("{data}", quando.strftime("%d/%m/%Y")).replace("{hora}", quando.strftime("%H:%M"))
             .replace("{dia_semana}", CAMP_DIAS_NOME[_camp_dow(quando)]))


def _camp_escolher_var(c):
    """Índice da variação deste envio (rodízio ou sorteio sem repetir a anterior). Altera c (idx_var/ult_var)."""
    n = len(c.get("variacoes") or []) or 1
    if c.get("modo_variacao") == "aleatorio" and n > 1:
        ult = c.get("ult_var", -1)
        i = _camp_rng.choice([k for k in range(n) if k != ult])
    else:
        i = int(c.get("idx_var", 0) or 0) % n
        c["idx_var"] = (i + 1) % n
    c["ult_var"] = i
    return i


def _camp_hash(t):
    return hashlib.sha1(str(t or "").encode("utf-8")).hexdigest()[:16]


# ---------- agenda ----------
def _camp_vale_no_dia(c, dia):
    s = dia.strftime("%Y-%m-%d")
    if c.get("inicio") and s < c["inicio"]:
        return False
    if c.get("fim") and s > c["fim"]:
        return False
    return _camp_dow(dia) in (c.get("dias") or [])


def _camp_slots_dia(c, dia):
    """[(hora, [jids])] da campanha nesse dia (cada grupo usa os horários próprios, se tiver)."""
    if not _camp_vale_no_dia(c, dia):
        return []
    por, hg = {}, c.get("horarios_grupo") or {}
    for j in c.get("grupos") or []:
        for h in hg.get(j) or c.get("horarios") or []:
            por.setdefault(h, []).append(j)
    return sorted(por.items())


def _camp_chave(cid, dia_s, h, jid):
    return f"{cid}|{dia_s}|{h}|{jid}"


def _camp_quando(dia, h):
    return _cdt.combine(dia, _ctime(int(h[:2]), int(h[3:5])))


def _camp_fmt_atraso(seg):
    m = int(seg // 60)
    return f"{m} min" if m < 120 else f"{m // 60} h"


def _camp_podar(ce, agora):
    corte = (agora.date() - _ctd(days=CAMP_HIST_DIAS)).strftime("%Y-%m-%d")
    ex = ce["execucoes"]
    for k in [k for k, v in ex.items() if str(v.get("dia", "")) < corte and v.get("status") not in ("fila", "enviando")]:
        del ex[k]
    if len(ex) > 6000:
        for k, _ in sorted(ex.items(), key=lambda kv: (kv[1].get("dia", ""), kv[1].get("hora", "")))[:len(ex) - 6000]:
            if ex[k].get("status") not in ("fila", "enviando"):
                del ex[k]


def campanhas_tick(agora=None):
    """Põe na fila os horários que venceram (hoje e ontem). Cada grupo só uma vez por campanha+dia+horário.
    Devolve quantos envios entraram na fila."""
    agora = agora or _camp_agora()
    if not _camp_ro()["lista"]:
        return 0
    novos = 0
    with _estado_lock:
        e = estado_ler()
        ce = _camp_estado(e)
        execs, fila, mudou = ce["execucoes"], ce["fila"], False
        for c in ce["lista"]:
            if not c.get("ativo"):
                continue
            desde = _camp_dt(c.get("vale_desde")) or agora
            for dia in (agora.date() - _ctd(days=1), agora.date()):
                ds = dia.strftime("%Y-%m-%d")
                for h, jids in _camp_slots_dia(c, dia):
                    quando = _camp_quando(dia, h)
                    if quando > agora or quando < desde:
                        continue
                    pend = [j for j in jids if _camp_chave(c["id"], ds, h, j) not in execs]
                    if not pend:
                        continue
                    mudou = True
                    atraso = (agora - quando).total_seconds()
                    motivo = ""
                    if ce["pausado_tudo"]:
                        motivo = "Pausado (Pausar tudo estava ligado no horário)"
                    elif atraso > CAMP_ATRASO_MAX:
                        motivo = f"Não enviado: o painel estava desligado no horário ({_camp_fmt_atraso(atraso)} de atraso)"
                    elif _camp_no_silencio(h, c.get("silencio")):
                        motivo = "Dentro da janela de silêncio"
                    if motivo:
                        for j in pend:
                            execs[_camp_chave(c["id"], ds, h, j)] = {"cid": c["id"], "jid": j, "dia": ds, "hora": h,
                                                                     "status": "pulado", "motivo": motivo, "em": _camp_iso(agora)}
                        continue
                    base = agora
                    ult = _camp_dt(ce.get("ultimo_envio"))
                    if ult:
                        base = max(base, ult + _ctd(seconds=CAMP_GAP_GLOBAL))
                    if fila:
                        base = max(base, max(_camp_dt(x["quando"]) or agora for x in fila) + _ctd(seconds=CAMP_GAP_GLOBAL))
                    t = base
                    for i, j in enumerate(pend):
                        if i:
                            t += _ctd(seconds=_camp_rng.uniform(c.get("intervalo_min", 25), c.get("intervalo_max", 75)))
                        k = _camp_chave(c["id"], ds, h, j)
                        execs[k] = {"cid": c["id"], "jid": j, "dia": ds, "hora": h, "status": "fila", "motivo": "",
                                    "criado": _camp_iso(agora), "quando": _camp_iso(t)}
                        fila.append({"chave": k, "quando": _camp_iso(t), "tentativa": 1})
                        novos += 1
        if mudou:
            _camp_podar(ce, agora)
            estado_gravar(e)
    return novos


def _camp_transitorio(err):
    if isinstance(err, PonteIndisponivel):
        return True
    if isinstance(err, ErroEnvio):
        return err.code in (503, 504) or "timed out" in str(err).lower() or "tempo" in str(err).lower()
    return isinstance(err, (TimeoutError, ConnectionError, urllib.error.URLError))


def _camp_ja_saiu(jid, texto_hash, tipo_midia, desde_epoch):
    """Depois de uma falha ambígua (tempo esgotado): a mensagem chegou a sair? Olha as últimas mensagens minhas no grupo."""
    try:
        db = ro(MSG_DB)
        rows = db.execute("select content, media_type, timestamp from messages where chat_jid=? and is_from_me=1 "
                          "order by timestamp desc limit 8", (jid,)).fetchall()
        db.close()
    except Exception:
        return False
    for content, mt, ts in rows:
        try:
            d = _cdt.fromisoformat(str(ts))
            ep = d.timestamp()
        except (ValueError, OverflowError, OSError):
            continue
        if ep < desde_epoch - 5:
            continue
        if _camp_hash((content or "").strip()) == texto_hash or (tipo_midia and (mt or "") == tipo_midia and texto_hash == _camp_hash("")):
            return True
    return False


def campanhas_enviar_proximo(agora=None):
    """Trata no máximo 1 item vencido da fila (envia, pula ou reagenda). Devolve a chave tratada ou None."""
    agora = agora or _camp_agora()
    if not _camp_ro()["fila"]:
        return None
    with _camp_envio_lock:
        with _estado_lock:
            e = estado_ler()
            ce = _camp_estado(e)
            if not ce["fila"]:
                return None
            ult = _camp_dt(ce.get("ultimo_envio"))
            if ult and 0 <= (agora - ult).total_seconds() < CAMP_GAP_GLOBAL:
                return None
            ce["fila"].sort(key=lambda x: x.get("quando", ""))
            job = ce["fila"][0]
            if job.get("quando", "") > _camp_iso(agora):
                return None
            ce["fila"].pop(0)
            k = job.get("chave", "")
            rx = ce["execucoes"].get(k)
            if not rx or rx.get("status") != "fila":  # já tratado (ex.: enviado): nunca duplica
                estado_gravar(e)
                return k or None
            c = next((x for x in ce["lista"] if x.get("id") == rx.get("cid")), None)
            manual = bool(rx.get("manual"))
            planejado = _camp_dt(job.get("quando")) or agora
            motivo = ""
            if ce["pausado_tudo"]:
                motivo = "Pausado (Pausar tudo)"
            elif not c:
                motivo = "Campanha apagada"
            elif not c.get("ativo") and not manual:
                motivo = "Campanha pausada"
            elif rx.get("jid") not in (c.get("grupos") or []):
                motivo = "Grupo tirado da campanha"
            elif (agora - planejado).total_seconds() > CAMP_ATRASO_MAX:
                motivo = f"Não enviado: atrasou {_camp_fmt_atraso((agora - planejado).total_seconds())} (painel desligado ou ponte fora do ar)"
            elif not manual and _camp_no_silencio(agora.strftime("%H:%M"), c.get("silencio")):
                motivo = "Dentro da janela de silêncio"
            if motivo:
                rx.update(status="pulado", motivo=motivo, em=_camp_iso(agora))
                estado_gravar(e)
                return k
            tentativa = int(job.get("tentativa", 1) or 1)
            if tentativa >= 2 and rx.get("t_envio") and rx.get("texto_hash") is not None:
                texto, idx = None, rx.get("variacao", 0)   # nova tentativa: mesmo texto da primeira
            else:
                idx = _camp_escolher_var(c)
                texto = _camp_texto(c, idx, agora)
            midia = dict(c.get("midia") or {}) or None
            if texto is None:
                texto = rx.get("_texto", "") or _camp_texto(c, idx, _camp_dt(rx.get("em")) or agora)
            ja_saiu = tentativa >= 2 and rx.get("t_envio") and _camp_ja_saiu(
                rx["jid"], rx.get("texto_hash", ""), (midia or {}).get("tipo", ""), float(rx["t_envio"]))
            if ja_saiu:
                rx.update(status="enviado", motivo="Confirmado: tinha saído na 1ª tentativa", em=_camp_iso(agora))
                estado_gravar(e)
                return k
            rx.update(status="enviando", em=_camp_iso(agora), variacao=idx, tentativas=tentativa,
                      texto_hash=_camp_hash(texto.strip()), t_envio=time.time(), previa=texto[:140])
            ce["ultimo_envio"] = _camp_iso(agora)
            estado_gravar(e)  # a chave fica "enviando" ANTES de enviar: se o painel cair agora, não reenvia sozinho
        status, motivo, retry, copia = "enviado", "", False, ""
        try:
            if not jid_conhecido(rx["jid"]):
                raise ErroEnvio("grupo não encontrado no WhatsApp")
            path = ""
            if midia:
                orig = _camp_midia_path(midia)
                if not orig:
                    raise ErroEnvio("a mídia da campanha sumiu; edite a campanha e escolha de novo")
                copia = path = _camp_copia_envio(orig, midia.get("tipo", ""))
            r = enviar_mensagem({"jid": rx["jid"], "texto": texto, "path": path, "nome": (midia or {}).get("nome", ""),
                                 "sem_ler": True})
            if not r or not r.get("success"):
                raise ErroEnvio((r or {}).get("message") or "falha no envio", 502)
            if r.get("dry_run"):
                motivo = "Simulação (PAINEL_DRYRUN): nada saiu"
        except Exception as err:
            status, motivo = "erro", (str(err) or type(err).__name__)[:300]
            retry = _camp_transitorio(err) and tentativa < 2
        finally:
            if copia and os.path.exists(copia):
                try:
                    os.remove(copia)
                except OSError:
                    pass
        with _estado_lock:
            e = estado_ler()
            ce = _camp_estado(e)
            x = ce["execucoes"].get(k)
            if x is not None and x.get("status") == "enviando":
                if retry:
                    q = _camp_iso(agora + _ctd(seconds=CAMP_RETRY_SEG))
                    x.update(status="fila", motivo=f"Falha temporária ({motivo}); nova tentativa às {q[11:16]}", quando=q,
                             _texto=texto)
                    ce["fila"].append({"chave": k, "quando": q, "tentativa": tentativa + 1})
                else:
                    x.pop("_texto", None)
                    x.update(status=status, motivo=motivo, em=_camp_iso(agora))
                estado_gravar(e)
        return k


def campanhas_recuperar(agora=None):
    """Na partida: envio que ficou "enviando" (painel fechou no meio) é conferido no banco; se não achou, vira erro
    (nunca reenvia sozinho)."""
    agora = agora or _camp_agora()
    with _estado_lock:
        e = estado_ler()
        if not isinstance(e.get("campanhas"), dict):
            return 0
        ce = _camp_estado(e)
        n = 0
        for x in ce["execucoes"].values():
            if x.get("status") == "enviando":
                n += 1
                if x.get("t_envio") and _camp_ja_saiu(x.get("jid", ""), x.get("texto_hash", ""), "", float(x["t_envio"])):
                    x.update(status="enviado", motivo="Confirmado após reiniciar o painel", em=_camp_iso(agora))
                else:
                    x.update(status="erro", em=_camp_iso(agora),
                             motivo="O painel foi fechado durante o envio; confira o grupo antes de reenviar")
        if n:
            estado_gravar(e)
        return n


def _campanhas_loop():
    time.sleep(5)
    try:
        campanhas_recuperar()
    except Exception as ex:
        print("campanhas (recuperar):", type(ex).__name__, ex)
    ultimo_tick = 0.0
    while True:
        try:
            if time.time() - ultimo_tick >= 15:
                ultimo_tick = time.time()
                campanhas_tick()
            for _ in range(20):
                if not campanhas_enviar_proximo():
                    break
        except Exception as ex:
            print("campanhas:", type(ex).__name__, ex)
        time.sleep(2)


# ---------- API ----------
def _camp_nomes_grupos(jids):
    out = {}
    jids = [j for j in set(jids) if _RE_CAMP_GRUPO.fullmatch(j or "")]
    if not jids:
        return out
    try:
        db = ro(MSG_DB)
        for i in range(0, len(jids), 200):
            parte = jids[i:i + 200]
            for j, n in db.execute("select jid, name from chats where jid in (%s)" % ",".join("?" * len(parte)), parte):
                out[j] = n or ""
        db.close()
    except Exception:
        pass
    return out


def _camp_publica(c):
    m = c.get("midia") or None
    return {**{k: v for k, v in c.items() if k not in ("midia", "ult_var")},
            "midia": {"nome": m.get("nome", ""), "tipo": m.get("tipo", ""), "bytes": m.get("bytes", 0),
                      "ok": bool(_camp_midia_path(m))} if m else None}


def _camp_proximo(c, execs, pausado, agora):
    if not c.get("ativo") or pausado:
        return ""
    desde = _camp_dt(c.get("vale_desde")) or agora
    for n in range(0, 9):
        dia = agora.date() + _ctd(days=n)
        for h, jids in _camp_slots_dia(c, dia):
            q = _camp_quando(dia, h)
            if q < desde or q <= agora:
                continue
            return _camp_iso(q)
    return ""


def campanhas_api(agora=None):
    agora = agora or _camp_agora()
    ce = _camp_ro()
    lista, execs, pausado = ce["lista"], ce["execucoes"], ce["pausado_tudo"]
    hoje_s = agora.strftime("%Y-%m-%d")
    corte = (agora.date() - _ctd(days=CAMP_HIST_DIAS)).strftime("%Y-%m-%d")
    nomes = _camp_nomes_grupos([j for c in lista for j in c.get("grupos") or []] + [x.get("jid", "") for x in execs.values()])
    por_cid = {c["id"]: c for c in lista}
    camps = []
    for c in lista:
        p = _camp_publica(c)
        p["proximo"] = _camp_proximo(c, execs, pausado, agora)
        meus = [x for x in execs.values() if x.get("cid") == c["id"] and x.get("status") not in ("fila",)]
        if meus:
            ult = max(meus, key=lambda x: (x.get("dia", ""), x.get("hora", "")))
            rodada = [x for x in meus if x.get("dia") == ult.get("dia") and x.get("hora") == ult.get("hora")]
            p["ultimo"] = {"dia": ult.get("dia"), "hora": ult.get("hora"),
                           "enviados": sum(x.get("status") == "enviado" for x in rodada),
                           "erros": sum(x.get("status") == "erro" for x in rodada),
                           "pulados": sum(x.get("status") == "pulado" for x in rodada),
                           "enviando": sum(x.get("status") == "enviando" for x in rodada)}
        else:
            p["ultimo"] = None
        camps.append(p)
    planejados = []
    for c in lista:
        desde = _camp_dt(c.get("vale_desde")) or agora
        for h, jids in _camp_slots_dia(c, agora.date()):
            q = _camp_quando(agora.date(), h)
            for j in jids:
                x = execs.get(_camp_chave(c["id"], hoje_s, h, j))
                if x:
                    stt = x.get("status")
                elif not c.get("ativo") or pausado:
                    stt = "pausado"
                elif q < desde:
                    stt = "fora"   # criada/ligada depois desse horário
                elif q <= agora:
                    stt = "fila"
                else:
                    stt = "previsto"
                planejados.append({"hora": h, "cid": c["id"], "campanha": c.get("nome", ""), "jid": j,
                                   "status": stt, "motivo": (x or {}).get("motivo", ""), "em": (x or {}).get("em", ""),
                                   "quando": (x or {}).get("quando", "")})
    planejados.sort(key=lambda p: (p["hora"], p["campanha"]))
    hist = []
    for k, x in execs.items():
        if str(x.get("dia", "")) < corte:
            continue
        c = por_cid.get(x.get("cid"))
        hist.append({"chave": k, "cid": x.get("cid"), "campanha": (c or {}).get("nome", "(apagada)"), "jid": x.get("jid"),
                     "dia": x.get("dia"), "hora": x.get("hora"), "status": x.get("status"), "motivo": x.get("motivo", ""),
                     "em": x.get("em", ""), "quando": x.get("quando", ""), "manual": bool(x.get("manual")),
                     "variacao": x.get("variacao"), "tentativas": x.get("tentativas", 0)})
    hist.sort(key=lambda h: (h["dia"] or "", h["hora"] or "", h.get("em") or ""), reverse=True)
    hoje_ex = [x for x in execs.values() if x.get("dia") == hoje_s]
    resumo = {"ativas": sum(1 for c in lista if c.get("ativo")), "total": len(lista),
              "enviados_hoje": sum(x.get("status") == "enviado" for x in hoje_ex),
              "erros_hoje": sum(x.get("status") == "erro" for x in hoje_ex),
              "pulados_hoje": sum(x.get("status") == "pulado" for x in hoje_ex),
              "proximos_hoje": sum(p["status"] in ("previsto", "fila") for p in planejados),
              "fila": len(ce["fila"])}
    return {"success": True, "agora": _camp_iso(agora), "pausado_tudo": pausado, "resumo": resumo, "campanhas": camps,
            "hoje": planejados, "historico": hist[:1500], "nomes": nomes,
            "limites": {"grupos": CAMP_MAX_GRUPOS, "variacoes": CAMP_MAX_VARIACOES, "horarios": CAMP_MAX_HORARIOS,
                        "gap": CAMP_GAP_GLOBAL, "atraso_min": CAMP_ATRASO_MAX // 60, "campanhas": CAMP_MAX_CAMPANHAS}}


def campanhas_midia_arquivo(cid):
    c = next((x for x in _camp_ro()["lista"] if x.get("id") == str(cid or "")), None)
    p = _camp_midia_path((c or {}).get("midia"))
    if not p:
        return None, None, None
    return p, c["midia"].get("tipo", "image"), c["midia"].get("nome", "")


def _camp_tirar_da_fila(ce, filtro, motivo, agora):
    resto = []
    for job in ce["fila"]:
        x = ce["execucoes"].get(job.get("chave", ""))
        if x and filtro(x) and x.get("status") == "fila":
            x.update(status="pulado", motivo=motivo, em=_camp_iso(agora))
        else:
            resto.append(job)
    ce["fila"] = resto


def campanhas_post(d):
    acao = str(d.get("acao") or "")
    agora = _camp_agora()
    vale = _camp_iso(agora - _ctd(seconds=60))  # horário de agora há pouco ainda vale; os já passados, não
    if acao in ("criar", "editar"):
        cid = secrets.token_hex(6) if acao == "criar" else str(d.get("id") or "")
        atual = None
        if acao == "editar":
            atual = next((x for x in _camp_ro()["lista"] if x.get("id") == cid), None)
            if not atual:
                raise ErroEnvio("campanha não encontrada")
        c = _camp_validar(d, atual)  # o painel manda a campanha inteira; o que faltar fica como estava
        origem = _camp_midia_origem(d)
        nova_midia = _camp_guardar_midia(cid, *origem) if origem else None
        try:
            with _estado_lock:
                e = estado_ler()
                ce = _camp_estado(e)
                if acao == "criar":
                    if len(ce["lista"]) >= CAMP_MAX_CAMPANHAS:
                        raise ErroEnvio(f"no máximo {CAMP_MAX_CAMPANHAS} campanhas")
                    midia = nova_midia
                    if not c["variacoes"] and not midia:
                        raise ErroEnvio("escreva a mensagem ou escolha uma foto/vídeo")
                    c.update(id=cid, midia=midia, criado=_camp_iso(agora), atualizado=_camp_iso(agora), vale_desde=vale, idx_var=0)
                    ce["lista"].append(c)
                    velha = None
                else:
                    alvo = next((x for x in ce["lista"] if x.get("id") == cid), None)
                    if not alvo:
                        raise ErroEnvio("campanha não encontrada")
                    acao_m = str(d.get("midia_acao") or "manter")
                    velha = alvo.get("midia")
                    midia = nova_midia if nova_midia else (None if acao_m in ("remover", "nenhuma") else velha)
                    if not c["variacoes"] and not midia:
                        raise ErroEnvio("escreva a mensagem ou escolha uma foto/vídeo")
                    if midia is velha:
                        velha = None
                    n_var = max(1, len(c["variacoes"]))
                    alvo.update(c, midia=midia, atualizado=_camp_iso(agora), vale_desde=vale,
                                idx_var=int(alvo.get("idx_var", 0) or 0) % n_var)
                    c = alvo
                estado_gravar(e)
        except Exception:
            if nova_midia:
                _camp_apagar_midia(nova_midia)
            raise
        if velha:
            _camp_apagar_midia(velha)
        return {"success": True, "campanha": _camp_publica(c)}
    if acao in ("pausar", "ativar", "apagar", "duplicar"):
        cid = str(d.get("id") or "")
        apagar_midia, copia_de = None, None
        with _estado_lock:
            e = estado_ler()
            ce = _camp_estado(e)
            c = next((x for x in ce["lista"] if x.get("id") == cid), None)
            if not c:
                raise ErroEnvio("campanha não encontrada")
            if acao == "pausar":
                c["ativo"] = False
                _camp_tirar_da_fila(ce, lambda x: x.get("cid") == cid and not x.get("manual"), "Campanha pausada", agora)
            elif acao == "ativar":
                c.update(ativo=True, vale_desde=vale)
            elif acao == "apagar":
                ce["lista"] = [x for x in ce["lista"] if x.get("id") != cid]
                ce["fila"] = [j for j in ce["fila"] if (ce["execucoes"].get(j.get("chave", "")) or {}).get("cid") != cid]
                for k in [k for k, x in ce["execucoes"].items() if x.get("cid") == cid and x.get("status") != "enviando"]:
                    del ce["execucoes"][k]
                apagar_midia = c.get("midia")
            else:
                if len(ce["lista"]) >= CAMP_MAX_CAMPANHAS:
                    raise ErroEnvio(f"no máximo {CAMP_MAX_CAMPANHAS} campanhas")
                novo = json.loads(json.dumps(c))
                nid = secrets.token_hex(6)
                novo.update(id=nid, nome=(c.get("nome", "") + " (cópia)")[:60], ativo=False, criado=_camp_iso(agora),
                            atualizado=_camp_iso(agora), vale_desde=vale, idx_var=0, midia=None)
                novo.pop("ult_var", None)
                orig = _camp_midia_path(c.get("midia"))
                if orig:
                    try:
                        novo["midia"] = _camp_guardar_midia(nid, orig, c["midia"].get("nome", ""), c["midia"].get("tipo", ""))
                    except (ErroEnvio, OSError):
                        novo["midia"] = None
                ce["lista"].append(novo)
                copia_de = novo
            estado_gravar(e)
        if apagar_midia:
            _camp_apagar_midia(apagar_midia)
        return {"success": True, **({"campanha": _camp_publica(copia_de)} if copia_de else {})}
    if acao == "pausar_tudo":
        sim = bool(d.get("sim"))
        with _estado_lock:
            e = estado_ler()
            ce = _camp_estado(e)
            ce["pausado_tudo"] = sim
            if sim:
                _camp_tirar_da_fila(ce, lambda x: True, "Pausado (Pausar tudo)", agora)
            else:  # ao retomar, horários que passaram durante a pausa não saem atrasados
                for c in ce["lista"]:
                    if c.get("ativo"):
                        c["vale_desde"] = max(str(c.get("vale_desde") or ""), vale)
            estado_gravar(e)
        return {"success": True, "pausado_tudo": sim}
    if acao == "reenviar":
        k = str(d.get("chave") or "")
        with _estado_lock:
            e = estado_ler()
            ce = _camp_estado(e)
            x = ce["execucoes"].get(k)
            if not x:
                raise ErroEnvio("envio não encontrado")
            if x.get("status") != "erro":
                raise ErroEnvio("só dá para reenviar um envio que deu erro")
            if ce["pausado_tudo"]:
                raise ErroEnvio("a programação está pausada (Pausar tudo)")
            c = next((y for y in ce["lista"] if y.get("id") == x.get("cid")), None)
            if not c or x.get("jid") not in (c.get("grupos") or []):
                raise ErroEnvio("esse grupo não está mais na campanha")
            if not jid_conhecido(x.get("jid", "")):
                raise ErroEnvio("grupo desconhecido")
            if any(j.get("chave") == k for j in ce["fila"]):
                raise ErroEnvio("esse envio já está na fila")
            x.update(status="fila", manual=True, motivo="Reenvio manual", quando=_camp_iso(agora))
            for campo in ("t_envio", "texto_hash", "_texto"):
                x.pop(campo, None)
            ce["fila"].append({"chave": k, "quando": _camp_iso(agora), "tentativa": 1})
            estado_gravar(e)
        return {"success": True}
    if acao == "enviar_agora_teste":
        if time.time() - _camp_teste["t"] < 5:
            raise ErroEnvio("aguarde alguns segundos entre um teste e outro", 429)
        cid = str(d.get("id") or "")
        c = next((x for x in _camp_ro()["lista"] if x.get("id") == cid), None) if cid else None
        if cid and not c:
            raise ErroEnvio("campanha não encontrada")
        vs = d.get("variacoes", None)
        if vs is not None:  # rascunho do editor (ainda não salvo)
            if not isinstance(vs, list):
                raise ErroEnvio("variações inválidas")
            vs = [str(x).strip()[:4000] for x in vs if str(x or "").strip()]
        else:
            vs = list((c or {}).get("variacoes") or [])
        try:
            idx = int(d.get("variacao") or 0)
        except (TypeError, ValueError):
            idx = 0
        texto = _camp_texto({"variacoes": vs}, max(0, idx), agora)
        origem, dica, nome_m, copia = None, "", "", ""
        o = _camp_midia_origem(d)
        if o:
            origem, nome_m, dica = o
        elif c and str(d.get("midia_acao") or "manter") == "manter" and c.get("midia"):
            origem, nome_m, dica = _camp_midia_path(c["midia"]), c["midia"].get("nome", ""), c["midia"].get("tipo", "")
            if not origem:
                raise ErroEnvio("a mídia da campanha sumiu; escolha de novo")
        if not texto.strip() and not origem:
            raise ErroEnvio("escreva a mensagem ou escolha uma foto/vídeo")
        _camp_teste["t"] = time.time()
        try:
            if origem:
                copia = _camp_copia_envio(origem, dica)
            r = enviar_mensagem({"jid": meu_jid_teste(), "texto": texto, "path": copia, "nome": nome_m, "sem_ler": True})
        finally:
            if copia and os.path.exists(copia):
                try:
                    os.remove(copia)
                except OSError:
                    pass
        return {"success": True, "para": meu_jid_teste(), "dry_run": bool((r or {}).get("dry_run"))}
    if acao == "importar":
        itens = d.get("campanhas")
        if not isinstance(itens, list) or not itens:
            raise ErroEnvio("arquivo sem campanhas")
        ok, erros = [], []
        for i, it in enumerate(itens[:CAMP_MAX_CAMPANHAS]):
            if not isinstance(it, dict):
                erros.append(f"item {i + 1}: inválido")
                continue
            try:
                c = _camp_validar({**it, "ativo": False})
                if not c["variacoes"]:
                    raise ErroEnvio("sem texto (a mídia não vem no arquivo)")
                ok.append(c)
            except ErroEnvio as ex:
                erros.append(f"{str(it.get('nome') or 'item ' + str(i + 1))[:40]}: {ex}")
        with _estado_lock:
            e = estado_ler()
            ce = _camp_estado(e)
            cabem = max(0, CAMP_MAX_CAMPANHAS - len(ce["lista"]))
            if len(ok) > cabem:
                erros.append(f"{len(ok) - cabem} não couberam (limite de {CAMP_MAX_CAMPANHAS})")
                ok = ok[:cabem]
            for c in ok:
                c.update(id=secrets.token_hex(6), midia=None, criado=_camp_iso(agora), atualizado=_camp_iso(agora),
                         vale_desde=vale, idx_var=0)
                ce["lista"].append(c)
            if ok:
                estado_gravar(e)
        return {"success": True, "importadas": len(ok), "erros": erros}
    raise ErroEnvio("ação inválida")
# ==================== [campanhas] fim ====================


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # mantém a conexão aberta: avatares e miniaturas chegam sem abrir TCP novo

    def log_message(self, *a):
        pass

    def _token(self):
        for parte in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = parte.strip().partition("=")
            if k == "painel_sessao":
                return v
        return ""

    def portaria(self, post):
        """Retorna True se pode seguir. IP privado, Host válido, login (fora deste PC) e, em POST, mesma origem."""
        if not hasattr(self, "_peer"):  # conexão keep-alive: o client_address pode já ter sido trocado pelo IP real
            self._peer = self.client_address[0]
        ip = self._peer
        self.via_proxy = False
        if PROXY and ip_cliente_ok(ip) and not ip_local(ip) and self.headers.get("X-Forwarded-For"):
            real = self.headers["X-Forwarded-For"].split(",")[-1].strip()
            try:
                ipaddress.ip_address(real)
                self.client_address = (real, self.client_address[1])  # limites e registros por cliente, não pelo proxy
                self.via_proxy = True
                ip = real
            except ValueError:
                pass
        if not self.via_proxy and not ip_cliente_ok(ip):
            self.close_connection = True
            registrar("recusado_ip_externo", ip, repetir=60)
            self.enviar(403, "acesso permitido só pela rede local", "text/plain; charset=utf-8")
            return False
        host = self.headers.get("Host", "")
        if not host_ok(host):
            self.close_connection = True
            registrar("recusado_host", ip, repetir=60, host=host)
            self.enviar(403, "proibido", "text/plain; charset=utf-8")
            return False
        esquema = "https" if (self.connection.__class__.__name__ == "SSLSocket" or
                              (self.via_proxy and self.headers.get("X-Forwarded-Proto") == "https")) else "http"
        self.https = esquema == "https"
        if post and (self.headers.get("Origin") != esquema + "://" + host or self.headers.get("X-Painel") != "1"):
            self.close_connection = True
            registrar("recusado_origem", ip, repetir=60, origem=self.headers.get("Origin") or "-",
                      rota=urlparse(self.path).path)
            self.enviar(403, "origem não permitida", "text/plain; charset=utf-8")
            return False
        self.remoto = not ip_local(ip)
        caminho = urlparse(self.path).path
        # pela rede, sempre https (o navegador só libera microfone/câmera/avisos em site seguro)
        if self.remoto and not self.https and not post and HTTPS_ATIVO:
            self.enviar(302, "", "text/plain; charset=utf-8", {"Location": "https://" + host + self.path})
            return False
        if self.remoto and caminho not in ("/login", "/api/login") and not sessao_valida(self._token()):
            if post:
                self.close_connection = True  # corpo não lido: não dá para reaproveitar a conexão
            registrar("sessao_vencida" if self._token() else "sem_login", ip, repetir=600, rota=caminho)
            if not post and caminho in ("/", "/index.html"):
                self.enviar(302, "", "text/plain; charset=utf-8", {"Location": "/login"})
            else:
                self.json({"success": False, "erro": "faça login", "login": True}, 401)
            return False
        return True

    def do_POST(self):
        # Só aceita POST vindo do próprio painel (mesma origem + cabeçalho X-Painel) e, fora deste PC, com login.
        if not self.portaria(post=True):
            return
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            tam = int(self.headers.get("Content-Length") or 0)
            if u.path != "/api/login":  # [limite] o login tem o freio próprio (5 erros / 15 min)
                espera = ritmo_espera(self.client_address[0], u.path)
                if espera:
                    if 0 <= tam <= 1024 * 1024:
                        self.rfile.read(tam)  # corpo pequeno: lê e descarta, a conexão continua boa
                    else:
                        self.close_connection = True
                    registrar("limite", self.client_address[0], repetir=60, classe=classe_rota(u.path),
                              rota=u.path, espera=espera)
                    return self.enviar(429, json.dumps({"success": False, "limite": True, "espera": espera,
                                       "erro": f"Muitas ações em pouco tempo. Tente de novo em {espera} s."}, ensure_ascii=False),
                                       extra={"Retry-After": str(espera)})
            if u.path == "/api/upload":
                return self.json(self.receber_upload(q, tam))
            if tam > 1024 * 1024:
                raise ErroEnvio("requisição grande demais", 413)
            dados = json.loads(self.rfile.read(tam) or b"{}")
            if u.path == "/api/login":
                ok, r_ = tentar_login(self.client_address[0], str(dados.get("senha") or "")[:200])
                if not ok:
                    return self.json({"success": False, "erro": r_}, 401)
                return self.enviar(200, json.dumps({"success": True}), "application/json; charset=utf-8",
                                   {"Set-Cookie": f"painel_sessao={r_}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSAO_SEG}" + ("; Secure" if self.https else "")})
            if u.path == "/api/csp-violacao":
                registrar("csp_violacao", self.client_address[0], repetir=300,
                          classe=str(dados.get("diretiva") or "")[:30], diretiva=str(dados.get("diretiva") or "")[:30],
                          alvo=str(dados.get("alvo") or "")[:80])
                return self.json({"success": True})
            if u.path == "/api/sair":
                with _acesso_lock:
                    _sessoes.pop(_chave(self._token()), None)
                    _sessoes_gravar()
                registrar("saiu", self.client_address[0])
                return self.enviar(200, json.dumps({"success": True}), "application/json; charset=utf-8",
                                   {"Set-Cookie": "painel_sessao=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
            if u.path == "/api/enviar":
                resp_ = enviar_mensagem(dados)
                rid_ = re.sub(r"[^0-9a-f]", "", str(dados.get("rascunho") or ""))[:16]
                if rid_ and isinstance(resp_, dict) and resp_.get("success") and not resp_.get("dry_run"):
                    try:  # o rascunho sai da fila NO MESMO pedido do envio: se o navegador falhar depois, não volta para ser enviado de novo
                        with _estado_lock:
                            e_ = estado_ler()
                            ant_ = len(e_.get("rascunhos") or [])
                            e_["rascunhos"] = [r_ for r_ in (e_.get("rascunhos") or []) if r_.get("id") != rid_]
                            if len(e_["rascunhos"]) != ant_:
                                estado_gravar(e_)
                    except Exception as ex_:
                        print("[rascunho] não consegui tirar da fila:", ex_, flush=True)
                return self.json(resp_)
            if u.path == "/api/lida":
                return self.json(marcar_lida(dados))
            if u.path == "/api/visto":
                jid = str(dados.get("jid") or "")
                if not jid or not jid_conhecido(jid):
                    raise ErroEnvio("conversa desconhecida")
                return self.json(marcar_visto(jid))
            if u.path == "/api/autonomia":
                return self.json(autonomia_salvar(dados))
            if u.path == "/api/rapidas":
                return self.json(rapidas_salvar(dados))
            if u.path == "/api/rascunhos":  # [rascunhos] só guarda; nunca envia
                return self.json(rascunhos_salvar(dados))
            if u.path == "/api/campanhas":  # [campanhas] Programação em grupos
                return self.json(campanhas_post(dados))
            if u.path == "/api/agendar":
                return self.json(agendar(dados))
            if u.path == "/api/agendar-cancelar":
                return self.json(agendadas_cancelar(dados))
            if u.path in ("/api/nova-senha", "/api/sair-todos"):
                if self.remoto:
                    raise ErroEnvio("só pode ser feito no próprio computador", 403)
                if u.path == "/api/sair-todos":
                    with _acesso_lock:
                        _sessoes.clear()
                        _sessoes_gravar()
                    registrar("saiu_todos", self.client_address[0])
                    return self.json({"success": True})
                nova = str(dados.get("senha") or "") or gerar_senha()
                if len(nova) < 8:
                    raise ErroEnvio("a senha precisa ter pelo menos 8 caracteres")
                definir_senha(nova)
                registrar("senha_trocada", self.client_address[0])
                return self.json({"success": True, "senha": nova})
            if u.path == "/api/ia/salvar":
                return self.json(ia_salvar(dados))
            if u.path == "/api/ia/testar":
                return self.json({"success": True, "texto": ia_chamar("Responda apenas: Conexão funcionando ✅", "Teste de conexão do painel.", 200)})
            if u.path == "/api/ia/corrigir":  # [corrigir]
                return self.json(ia_corrigir(dados))
            if u.path in ("/api/ia/sugerir", "/api/ia/resumir"):
                return self.json(ia_acao(dados, u.path.rsplit("/", 1)[1]))
            if u.path == "/api/favoritar":
                return self.json(favoritar(dados))
            if u.path == "/api/rascunho-chat":
                return self.json(rascunho_chat_salvar(dados))
            if u.path == "/api/seg-visto":  # [segvisto]
                return self.json(seg_visto_salvar(dados))
            if u.path == "/api/historico":
                return self.json(pedir_historico(dados))
            if u.path == "/api/reenviar-audio":
                return self.json(reenviar_audio(dados))
            if u.path == "/api/resolver":
                return self.json(resolver(dados))
            if u.path == "/api/etiquetas":
                return self.json(salvar_etiquetas(dados))
            if u.path == "/api/ficha":  # [ficha]
                return self.json(ficha_salvar(dados))
            if u.path == "/api/followup":  # [followup] só guarda/cancela o lembrete; não envia nada
                return self.json(followup(dados))
            if u.path == "/api/lembrete":
                return self.json(lembrete(dados))
            if u.path == "/api/organizar":
                return self.json(organizar(dados))
            if u.path == "/api/presenca":
                return self.json(presenca(dados))
            if u.path == "/api/silenciar":
                return self.json(silenciar(dados))
            if u.path == "/api/apagar":
                return self.json(apagar_para_todos(dados))
            if u.path == "/api/reagir":
                return self.json(reagir(dados))
            if u.path == "/api/editar":
                return self.json(editar(dados))
            if u.path == "/api/encaminhar":
                return self.json(encaminhar(dados))
            self.enviar(404, "não encontrado", "text/plain; charset=utf-8")
        except ErroEnvio as e:
            self.close_connection = True  # o corpo pode não ter sido lido até o fim
            try:
                rota_ = self.path.split("?")[0]
                if e.code == 413 or rota_ == "/api/upload":
                    registrar("upload_recusado" if rota_ == "/api/upload" else "corpo_grande",
                              self.client_address[0], repetir=60, classe=rota_, rota=rota_, codigo=e.code,
                              motivo=str(e)[:80])
            except Exception:
                pass
            self.json({"success": False, "erro": str(e)}, e.code)
        except Exception as e:
            self.close_connection = True
            self.json({"success": False, "erro": f"{type(e).__name__}: {e}"}, 500)

    def receber_upload(self, q, tam):
        if tam <= 0:
            raise ErroEnvio("arquivo vazio")
        if tam > MAX_UPLOAD:
            raise ErroEnvio("arquivo maior que 200 MB", 413)
        tipo = q.get("tipo", ["arquivo"])[0]
        nome = q.get("nome", ["arquivo"])[0]
        # extensão executável/atalho nunca entra (checa as duas últimas extensões: "a.exe.pdf" e "a.pdf.exe" são recusados)
        _partes = [p.lower() for p in os.path.basename(nome or "").split(".")[1:]]
        if any(re.sub(r"[^a-z0-9]", "", p) in EXT_BLOQUEADAS for p in _partes[-2:]):
            raise ErroEnvio("tipo de arquivo não permitido (executável ou script)", 415)
        os.makedirs(UPLOADS, exist_ok=True)
        padrao ={"voz": ".webm", "foto": ".jpg", "figurinha": ".png"}.get(tipo, "")
        destino = os.path.join(UPLOADS, nome_seguro(nome, padrao))
        restante = tam
        with open(destino, "wb") as f:
            while restante > 0:
                bloco = self.rfile.read(min(1 << 20, restante))
                if not bloco:
                    break
                f.write(bloco)
                restante -= len(bloco)
        if restante:
            os.remove(destino)
            raise ErroEnvio("upload incompleto")
        final = destino
        if tipo == "voz":
            final = converter_voz(destino)
        elif tipo == "figurinha":
            final = converter_figurinha(destino)
        return {"success": True, "path": final, "nome": os.path.basename(final), "bytes": os.path.getsize(final)}

    def enviar(self, code, corpo, tipo="application/json; charset=utf-8", extra=None, gz=None):
        if isinstance(corpo, str):
            corpo = corpo.encode("utf-8")
        cab = dict(extra or {})
        if code != 304 and (gz is not None or (len(corpo) >= GZIP_MIN and tipo.startswith(GZIP_TIPOS))):
            cab["Vary"] = "Accept-Encoding"
            if "gzip" in (self.headers.get("Accept-Encoding") or ""):
                corpo = gz if gz is not None else comprimir(corpo)
                cab["Content-Encoding"] = "gzip"
        self.send_response(code)
        self.send_header("Content-Type", tipo)
        if code == 304:
            corpo = b""  # 304 nunca tem corpo
        else:
            self.send_header("Content-Length", str(len(corpo)))
        for k, v in (("Cache-Control", "no-store"),
                     ("X-Content-Type-Options", "nosniff"),
                     ("Referrer-Policy", "no-referrer"),
                     ("X-Frame-Options", "DENY"),
                     ("Permissions-Policy", POLITICA_PERMISSOES),
                     ("Content-Security-Policy", CSP_API)):
            cab.setdefault(k, v)  # quem chamou manda mais que o padrão
        for k, v in cab.items():
            self.send_header(k, v)
        self.end_headers()
        if corpo and not self._head:  # [head] HEAD: cabeçalhos iguais ao GET, sem corpo
            try:
                self.wfile.write(corpo)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                self.close_connection = True

    def servir_arquivo(self, path, mt, fn):
        tipo = tipo_midia(path, mt)
        tam = os.path.getsize(path)
        ini, fim, code = 0, tam - 1, 200
        rng = self.headers.get("Range", "")
        if rng.startswith("bytes=") and tam:
            try:
                a, b = rng[6:].split(",")[0].split("-")
                if a:
                    ini, fim = int(a), (int(b) if b else tam - 1)
                else:
                    ini = max(0, tam - int(b))
                fim = min(fim, tam - 1)
                if ini > fim:
                    raise ValueError
                code = 206
            except ValueError:
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{tam}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
        self.send_response(code)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(fim - ini + 1 if tam else 0))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Cache-Control", "private, max-age=86400")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        if code == 206:
            self.send_header("Content-Range", f"bytes {ini}-{fim}/{tam}")
        if mt == "document":
            nomearq = os.path.basename(fn or path)
            from urllib.parse import quote
            disp = "inline" if tipo == "application/pdf" else "attachment"
            self.send_header("Content-Disposition", f"{disp}; filename*=UTF-8''{quote(nomearq)}")
            self.send_header("Content-Security-Policy", "sandbox; frame-ancestors 'none'")
        self.end_headers()
        if self.command == "HEAD" or not tam:
            return
        with open(path, "rb") as f:
            f.seek(ini)
            restante = fim - ini + 1
            while restante > 0:
                bloco = f.read(min(65536, restante))
                if not bloco:
                    break
                try:
                    self.wfile.write(bloco)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    self.close_connection = True
                    return
                restante -= len(bloco)

    def stream(self):
        """Server-Sent Events: verifica o banco a cada 1s e avisa o navegador quando algo muda."""
        import time
        self.close_connection = True  # fluxo sem tamanho definido: fecha ao terminar, não reaproveita
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self.end_headers()
        ultimo, ultimo_dem, ultimo_ping = None, None, time.time()
        ultimo_est = None
        try:
            self.wfile.write(b"retry: 2000\n\n")
            self.wfile.flush()
            while True:
                msg, dem = assinatura()
                eventos = []
                if msg != ultimo:
                    eventos.append(("mensagens", msg))
                    ultimo = msg
                if dem != ultimo_dem:
                    eventos.append(("demandas", dem))
                    ultimo_dem = dem
                try:  # favoritas/estado alterados por outro aparelho
                    est = str(os.path.getmtime(ESTADO))
                except OSError:
                    est = ""
                if est != ultimo_est:
                    if ultimo_est is not None:  # na abertura o cliente já carrega tudo
                        eventos.append(("estado", est))
                    ultimo_est = est
                for nomeev, dado in eventos:
                    self.wfile.write(f"event: {nomeev}\ndata: {json.dumps(dado)}\n\n".encode("utf-8"))
                if not eventos and time.time() - ultimo_ping > 15:
                    self.wfile.write(b": ping\n\n")
                    eventos = True
                if eventos:
                    self.wfile.flush()
                    ultimo_ping = time.time()
                time.sleep(1)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            return

    # [desempenho2] GET de JSON com ETag (hash do corpo): quem revalida (cache no-cache) recebe 304 sem corpo
    _JSON_ETAG = ("/api/mensagens", "/api/pendentes", "/api/chats", "/api/campanhas", "/api/resumo", "/api/tempos")

    def json(self, obj, code=200):
        corpo = json.dumps(obj, ensure_ascii=False)
        if code == 200 and getattr(self, "command", "") == "GET" and urlparse(self.path).path in self._JSON_ETAG:
            etag = '"j%s"' % hashlib.sha1(corpo.encode("utf-8")).hexdigest()[:20]
            cab = {"ETag": etag, "Cache-Control": "no-cache, private"}
            if etag in (self.headers.get("If-None-Match") or ""):
                return self.enviar(304, b"", "application/json; charset=utf-8", cab)
            return self.enviar(code, corpo, "application/json; charset=utf-8", cab)
        self.enviar(code, corpo)

    # [metodos] Erros do próprio http.server (método que o painel não usa, pedido malformado, linha ou cabeçalho grande
    # demais) saíam como página HTML do Python, sem CSP/X-Frame-Options e ecoando o método. Agora: texto curto em
    # português, cabeçalhos de segurança do painel, conexão fechada (o corpo não foi lido) e 405 + Allow para
    # OPTIONS/PUT/DELETE/PATCH/TRACE etc. Sem CORS: OPTIONS não libera nada para outra origem.
    METODOS_ACEITOS = "GET, POST, HEAD"

    def send_error(self, code, message=None, explain=None):
        code = int(code)
        self.close_connection = True
        cab = {"Connection": "close"}
        metodo = "".join(c for c in str(getattr(self, "command", "") or "")[:16] if c.isalnum()) or "-"
        if code == 501 and metodo != "-" and not hasattr(self, "do_" + str(self.command)):
            code, texto = 405, "método não permitido"
            cab["Allow"] = self.METODOS_ACEITOS
        else:
            texto = {400: "pedido inválido", 408: "tempo esgotado", 414: "endereço grande demais",
                     431: "cabeçalhos grandes demais", 505: "versão HTTP não suportada"}.get(code, "erro")
        # versão inválida/estranha: o http.server ainda considera HTTP/0.9 e mandaria só o corpo, sem cabeçalho nenhum
        if getattr(self, "request_version", "") == "HTTP/0.9" and "HTTP/" in (getattr(self, "requestline", "") or ""):
            self.request_version = "HTTP/1.1"
        if getattr(self, "headers", None) is None:
            import http.client
            self.headers = http.client.HTTPMessage()  # erro antes de ler os cabeçalhos: enviar() consulta Accept-Encoding
        try:
            ip = self.client_address[0]
            xff = (self.headers.get("X-Forwarded-For") or "").split(",")[-1].strip()
            if PROXY and xff and ip_cliente_ok(ip) and not ip_local(ip):  # mesmo critério da portaria
                ipaddress.ip_address(xff)
                ip = xff
            registrar("metodo_recusado" if code == 405 else "pedido_invalido", ip, repetir=600, metodo=metodo, codigo=code)
        except Exception:
            pass
        corpo = b"" if self.command == "HEAD" else texto.encode("utf-8")
        try:
            self.enviar(code, corpo, "text/plain; charset=utf-8", cab)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            pass

    # [head] HEAD = GET sem corpo, só nas rotas baratas (monitor de disponibilidade, checagem de link).
    # Antes respondia 501 e um monitor acusaria queda. Rotas caras (SSE, mídia, buscas) respondem 405.
    _head = False
    HEAD_ROTAS = ("/", "/index.html", "/login", "/api/sessao")

    def do_HEAD(self):
        self._head = True
        try:
            if urlparse(self.path).path in self.HEAD_ROTAS:
                return self.do_GET()
            if not self.portaria(post=False):
                return
            self.enviar(405, b"", "text/plain; charset=utf-8", {"Allow": "GET, POST"})
        finally:
            self._head = False

    def do_GET(self):
        # IP da rede local, Host válido (contra DNS rebinding) e login quando o acesso vem de outro aparelho.
        if not self.portaria(post=False):
            return
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            if self.remoto and u.path in ("/api/buscar", "/api/midia"):  # [limite] leitura cara pela rede
                espera = ritmo_espera(self.client_address[0], u.path)
                if espera:
                    registrar("limite", self.client_address[0], repetir=60, classe=classe_rota(u.path),
                              rota=u.path, espera=espera)
                    return self.enviar(429, json.dumps({"success": False, "limite": True, "espera": espera,
                                       "erro": f"Muitos pedidos em pouco tempo. Tente de novo em {espera} s."}, ensure_ascii=False),
                                       extra={"Retry-After": str(espera)})
            if u.path == "/login":
                if self.remoto and sessao_valida(self._token()):
                    return self.enviar(302, "", "text/plain; charset=utf-8", {"Location": "/"})
                return self.enviar(200, PAGINA_LOGIN, "text/html; charset=utf-8",
                                   {"Content-Security-Policy": CSP_LOGIN})
            m_fonte = re.fullmatch(r"/fontes/emoji/(\d{1,2})\.woff2", u.path)
            if m_fonte:  # fonte de emojis (Noto Color Emoji, Google Fonts) servida localmente: 🩷 e emojis novos no Windows 10
                arq = os.path.join(AQUI, "fontes", "emoji", m_fonte.group(1) + ".woff2")
                if not os.path.isfile(arq):
                    return self.enviar(404, "não encontrado", "text/plain; charset=utf-8")
                with open(arq, "rb") as f:
                    return self.enviar(200, f.read(), "font/woff2", {"Cache-Control": "public, max-age=31536000, immutable"})
            if u.path == "/api/eu":
                try:
                    d = ponte_get("/api/me", timeout=5)
                    return self.json({"jid": d.get("jid") or "", "lid": d.get("lid") or ""})
                except Exception:
                    return self.json({"jid": "", "lid": ""})
            if u.path == "/api/sessao":
                return self.json({"remoto": self.remoto})
            if u.path in ("/", "/index.html"):
                corpo, gz, etag, csp = index_html()
                extra = {"ETag": etag, "Cache-Control": "no-cache, private",
                         "Content-Security-Policy": csp}  # revalida sempre; 304 evita baixar de novo
                if self.remoto:  # renova o cookie do aparelho (continua conectado enquanto usar)
                    extra["Set-Cookie"] = f"painel_sessao={self._token()}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSAO_SEG}" + ("; Secure" if self.https else "")
                if etag in (self.headers.get("If-None-Match") or ""):
                    return self.enviar(304, b"", "text/html; charset=utf-8", extra)
                return self.enviar(200, corpo, "text/html; charset=utf-8", extra, gz=gz)
            if u.path == "/api/chats":
                return self.json(api_chats())
            if u.path == "/api/mensagens":
                jid = q.get("jid", [""])[0]
                lim = max(1, min(int(q.get("limite", ["200"])[0]), 5000))
                return self.json(api_mensagens(jid, lim, q.get("incluir", [""])[0], q.get("antes", [""])[0][:80]))
            if u.path == "/api/demandas":
                txt = ""
                etag_d = '"dem-0"'
                if os.path.exists(DEMANDAS):
                    st_d = os.stat(DEMANDAS)
                    etag_d = '"dem-%x-%x"' % (st_d.st_mtime_ns, st_d.st_size)
                    cab_d = {"ETag": etag_d, "Cache-Control": "no-cache, private"}
                    if etag_d in (self.headers.get("If-None-Match") or ""):
                        return self.enviar(304, b"", "application/json; charset=utf-8", cab_d)  # arquivo igual: não manda 150 KB de novo
                    with open(DEMANDAS, encoding="utf-8") as f:
                        txt = f.read()
                else:
                    cab_d = {"ETag": etag_d, "Cache-Control": "no-cache, private"}
                # gzip guardado por ETag: o arquivo só é recomprimido quando muda (160 KB -> 36 KB)
                corpo_d = json.dumps({"markdown": txt}, ensure_ascii=False)
                gz_d = _DEM_GZ.get(etag_d)
                if gz_d is None:
                    gz_d = comprimir(corpo_d.encode("utf-8"))
                    _DEM_GZ.clear()
                    _DEM_GZ[etag_d] = gz_d
                return self.enviar(200, corpo_d, "application/json; charset=utf-8", cab_d, gz=gz_d)
            if u.path == "/api/pendentes":
                # chats de trabalho sem resposta, mantidos pelo notificador.py (caixa_entrada.json)
                try:
                    with open(os.path.join(BASE, "caixa_entrada.json"), encoding="utf-8") as f:
                        caixa = json.load(f)
                except Exception:
                    caixa = []
                pend = sorted(pendentes_vivas(caixa), key=lambda e: (e.get("prioridade") == "baixa", e.get("desde_ts", "")))
                return self.json(pend)
            if u.path == "/api/autonomia":
                return self.json(api_autonomia())
            if u.path == "/api/rapidas":
                return self.json(estado_ler_cache().get("rapidas", []))
            if u.path == "/api/rascunhos":  # [rascunhos]
                return self.json(rascunhos_listar())
            if u.path == "/api/config-painel":
                return self.json(config_painel(self.remoto))
            if u.path == "/api/midias":
                return self.json(api_midias(q.get("jid", [""])[0], q.get("tipo", ["midia"])[0]))
            if u.path == "/api/ia":
                return self.json(ia_config_publica())
            if u.path == "/api/resumo":
                return self.json(api_resumo())
            if u.path == "/api/relatorio":  # [followup] relatório do dia + ranking de espera (só leitura)
                return self.json(api_relatorio())
            if u.path == "/api/ranking-espera":  # [rank-periodo] ranking de espera no período escolhido (só leitura)
                return self.json(api_ranking_espera(q.get("dias", ["7"])[0]))
            if u.path == "/api/tempo-resposta":  # [followup] tempo de resposta de uma conversa (7/30 dias)
                return self.json(api_tempo_resposta(q.get("jid", [""])[0]))
            if u.path == "/api/tempos":
                return self.json(api_tempos(q.get("dias", ["7"])[0] if str(q.get("dias", ["7"])[0]).isdigit() else 7))
            if u.path == "/api/favoritas":
                return self.json(api_favoritas())
            if u.path == "/api/exportar":
                jid = q.get("jid", [""])[0]
                if not jid_conhecido(jid):
                    return self.enviar(404, "conversa desconhecida", "text/plain; charset=utf-8")
                titulo, txt = exportar_conversa(jid)
                arq = re.sub(r"[^\w\- ]", "", titulo).strip()[:60] or "conversa"
                return self.enviar(200, txt, "text/plain; charset=utf-8",
                                   {"Content-Disposition": f"attachment; filename*=UTF-8''{quote('Conversa WhatsApp - ' + arq + '.txt')}"})
            if u.path == "/api/campanhas":  # [campanhas] Programação em grupos
                return self.json(campanhas_api())
            if u.path == "/api/campanhas/midia":  # [campanhas]
                p_c, mt_c, fn_c = campanhas_midia_arquivo(q.get("id", [""])[0])
                if not p_c:
                    return self.enviar(404, "mídia indisponível", "text/plain; charset=utf-8")
                return self.servir_arquivo(p_c, mt_c, fn_c)
            if u.path == "/api/agendadas":
                return self.json([x for x in estado_ler_cache().get("agendadas", []) if x["status"] in ("agendada", "erro")])
            if u.path == "/api/qr":
                if not os.path.exists(QR_PNG):
                    return self.enviar(404, "sem QR no momento", "text/plain; charset=utf-8")
                with open(QR_PNG, "rb") as f:
                    return self.enviar(200, f.read(), "image/png")
            if u.path == "/api/saude":
                sg = seg_resumo()  # [segaviso]
                return self.json(dict(saude, seg=sg) if sg else saude)
            if u.path == "/api/vivo":
                return self.json(api_vivo())
            if u.path == "/api/rascunho-chat":
                return self.json({"rascunhos": estado_ler_cache().get("rascunhos_chat") or {}})
            if u.path == "/api/conhecimento":
                return self.json(conhecimento_contato(q.get("jid", [""])[0]))
            if u.path == "/api/ficha":  # [ficha]
                return self.json(ficha_ler(q.get("jid", [""])[0]))
            if u.path == "/api/numero":  # [numeros] número digitado/clicado: conversa existente ou número no WhatsApp
                return self.json(api_numero(q.get("n", [""])[0]))
            if u.path == "/api/info":
                return self.json(api_info(q.get("jid", [""])[0]))
            if u.path == "/api/buscar":
                return self.json(api_buscar(q.get("q", [""])[0], ocultos=q.get("ocultos", [""])[0] == "1"))
            if u.path == "/api/miniatura":
                jpg = miniatura(q.get("jid", [""])[0], q.get("id", [""])[0])
                if not jpg:
                    return self.enviar(404, "sem miniatura", "text/plain; charset=utf-8", {"Cache-Control": "private, max-age=600"})
                return self.enviar(200, jpg, "image/jpeg", {"Cache-Control": "private, max-age=604800, immutable"})
            if u.path == "/api/avatar":
                jid = q.get("jid", [""])[0]
                if not re.fullmatch(r"[0-9A-Za-z.\-_:]+@[a-z.]+", jid or ""):
                    return self.enviar(400, "jid inválido", "text/plain; charset=utf-8")
                try:
                    dados, etag, _fonte = avatar_completo(jid) if q.get("full", [""])[0] == "1" else avatar(jid)
                except AvatarErro as e:
                    return self.enviar(e.code, e.texto, "text/plain; charset=utf-8")
                # stale-while-revalidate: passado o max-age o navegador mostra a foto que tem na hora
                # e revalida por trás — nada de buraco na lista enquanto o 304 volta.
                cab = {"Cache-Control": "private, max-age=21600, stale-while-revalidate=86400"}
                if q.get("full", [""])[0] == "1" and _fonte == "miniatura":
                    cab["Cache-Control"] = "private, max-age=600"
                if not dados:
                    return self.enviar(204, b"", "image/jpeg", cab)  # 204: sem foto não vira erro no console
                cab["ETag"] = etag
                if etag in (self.headers.get("If-None-Match") or ""):
                    return self.enviar(304, b"", "image/jpeg", cab)  # mesma foto: o navegador reusa a dele
                return self.enviar(200, dados, "image/jpeg", cab)
            if u.path == "/api/stream":
                return self.stream()
            if u.path == "/api/midia":
                try:
                    path, mt, fn = baixar_midia(q.get("id", [""])[0], q.get("jid", [""])[0])
                except PonteIndisponivel:
                    return self.enviar(503, "ponte do WhatsApp indisponível no momento; tente de novo",
                                       "text/plain; charset=utf-8", {"Retry-After": "5"})
                if not path:
                    return self.enviar(404, "mídia indisponível", "text/plain; charset=utf-8")
                return self.servir_arquivo(path, mt, fn)
            self.enviar(404, "não encontrado", "text/plain; charset=utf-8")
        except Exception as e:
            self.json({"erro": str(e)}, 500)


# ---------- [followup] "lembrar se não responder", relatório do dia (18h) e tempo de resposta por cliente ----------
# Só LÊ o messages.db (modo somente leitura) e guarda os lembretes no painel_estado.json. Nunca envia nada.
from datetime import datetime as _fu_dt, timedelta as _fu_td
import calendar as _fu_cal

FU_DIAS = (1, 2, 7)          # opções do menu: 1 dia, 2 dias, 1 semana
FU_TTL = 60.0                # segundos de cache do relatório / tempo por conversa
FU_HORA_RELATORIO = 18       # o relatório do dia "fica pronto" a partir desta hora
FU_PESSOAL = {"Pessoal", "Família"}
_fu_mem = {}
_fu_mem_lock = threading.Lock()


def _fu_cache(chave, fn, ttl=FU_TTL):
    """Guarda o resultado por até `ttl` s. Cada chamada recebe uma cópia (ninguém altera o cache sem querer)."""
    agora = time.monotonic()
    with _fu_mem_lock:
        c = _fu_mem.get(chave)
        if c and agora - c[0] < ttl:
            return json.loads(c[1])
    v = fn()
    with _fu_mem_lock:
        if len(_fu_mem) > 200:
            for k in sorted(_fu_mem, key=lambda k: _fu_mem[k][0])[:100]:
                _fu_mem.pop(k, None)
        _fu_mem[chave] = (agora, json.dumps(v, ensure_ascii=False))
    return json.loads(_fu_mem[chave][1])


def _fu_limpar_cache():
    with _fu_mem_lock:
        _fu_mem.clear()


def _fu_ts(ts):
    try:
        d = _fu_dt.fromisoformat(str(ts))
    except ValueError:
        return None
    return d if d.tzinfo else d.astimezone()


def _fu_dur(s):
    s = int(s or 0)
    if s < 60:
        return f"{max(1, s)} s"
    if s < 3600:
        return f"{round(s / 60)} min"
    if s < 86400:
        h = round(s / 360) / 10
        return (f"{h:.1f}".replace(".", ",") if h % 1 else str(int(h))) + " h"
    return f"{round(s / 86400)} d"


def _fu_trabalho(so_individuais=False):
    """{jid canônico: conversa} das conversas de trabalho: contatos (e grupos "Cliente"), fora ocultas e Pessoal/Família."""
    out = {}
    for c in api_chats_cache():
        tags = set(c.get("etiquetas") or [])
        if c.get("oculto") or tags & FU_PESSOAL:
            continue
        if c["tipo"] == "individual" or (not so_individuais and c["tipo"] == "grupo" and "Cliente" in tags):
            out[c["jid"]] = c
    return out


def _fu_linhas(desde, jids=None):
    """(chat_jid, timestamp, is_from_me) desde `desde`, sem chamadas, canais e status. Só leitura."""
    sql = """select chat_jid, timestamp, is_from_me from messages
             where timestamp >= ? and coalesce(media_type, '') <> 'call'
               and chat_jid not like '%@broadcast' and chat_jid not like '%@newsletter'"""
    args = [desde]
    if jids is not None:
        jids = list(jids)
        if not jids:
            return []
        sql += f" and chat_jid in ({','.join('?' * len(jids))})"
        args += jids
    db = ro(MSG_DB)
    try:
        return db.execute(sql, args).fetchall()
    except sqlite3.Error:
        return []
    finally:
        db.close()


def _fu_blocos(linhas, para, agora):
    """Junta @lid + número (para) e separa em blocos: da 1ª mensagem recebida sem resposta até a 1ª resposta do operador.
    Devolve ({canon: [(hora_da_resposta, segundos)]}, {canon: início_da_espera_aberta}, {canon: [recebidas, enviadas]}).
    Mesma regra do /api/tempos: só conta das 8h às 20h e blocos de até 7 dias."""
    por = {}
    for cj, ts, me in linhas:
        por.setdefault(para.get(cj, cj), []).append((str(ts or ""), bool(me)))
    blocos, abertas, cont = {}, {}, {}
    for canon, msgs in por.items():
        msgs.sort(key=lambda x: x[0])
        k = cont.setdefault(canon, [0, 0])
        aberta = None
        for ts, me in msgs:
            t = _fu_ts(ts)
            if t is None:
                continue
            k[1 if me else 0] += 1
            if not me:
                if aberta is None:
                    aberta = t
            elif aberta is not None:
                if (t - aberta).total_seconds() <= 7 * 86400:
                    blocos.setdefault(canon, []).append((t, _seg_atendimento(aberta, t)))
                aberta = None
        if aberta is not None and (agora - aberta).total_seconds() <= 7 * 86400:
            abertas[canon] = aberta
    return blocos, abertas, cont


def _fu_stats(segs):
    if not segs:
        return {"respostas": 0, "media": 0, "mediana": 0, "pior": 0}
    return {"respostas": len(segs), "media": int(sum(segs) / len(segs)), "mediana": _mediana(segs), "pior": max(segs)}


# ---- 1) lembrete "se não responder" ----
def _fu_previa(content, mt, fn):
    if content:
        return str(content)
    return {"image": "Foto", "video": "Vídeo", "audio": "Áudio", "document": fn or "Documento",
            "sticker": "Figurinha"}.get(mt or "", "Mensagem")


def _fu_respondeu(db, jid, ts):
    jids = jids_da_conversa(jid)
    return db.execute(f"""select 1 from messages where chat_jid in ({','.join('?' * len(jids))}) and is_from_me = 0
                          and timestamp > ? and coalesce(revoked, 0) = 0 limit 1""", (*jids, str(ts))).fetchone() is not None


def followup(dados):
    """POST /api/followup {jid, id, dias: 1|2|7} cria; {jid, cancelar: true[, id]} cancela. Um lembrete por conversa."""
    jid = str(dados.get("jid") or "")
    if not jid or not jid_conhecido(jid):
        raise ErroEnvio("conversa desconhecida")
    canon = aliases()[1].get(jid, jid)
    mid = str(dados.get("id") or "")[:128]
    if dados.get("cancelar"):
        with _estado_lock:
            e = estado_ler()
            antes = e.get("followups") or []
            depois = [f for f in antes if not (f.get("jid") == canon and (not mid or f.get("id") == mid))]
            if len(depois) != len(antes):
                e["followups"] = depois
                estado_gravar(e)
        _fu_limpar_cache()
        return {"success": True, "cancelado": len(depois) != len(antes)}
    try:
        dias = int(dados.get("dias"))
    except (TypeError, ValueError):
        dias = 0
    if dias not in FU_DIAS:
        raise ErroEnvio("prazo inválido (1 dia, 2 dias ou 1 semana)")
    if not mid:
        raise ErroEnvio("mensagem inválida")
    jids = jids_da_conversa(canon)
    db = ro(MSG_DB)
    try:
        m = db.execute(f"""select chat_jid, timestamp, is_from_me, content, media_type, filename from messages
                           where id = ? and chat_jid in ({','.join('?' * len(jids))})""", (mid, *jids)).fetchone()
        if not m:
            raise ErroEnvio("mensagem não encontrada")
        if not m[2]:
            raise ErroEnvio("só dá para lembrar de mensagens que você enviou")
        if _fu_respondeu(db, canon, m[1]):
            raise ErroEnvio("o contato já respondeu depois desta mensagem")
    finally:
        db.close()
    item = {"jid": canon, "id": mid, "chat": m[0], "ts": str(m[1]), "dias": dias,
            "quando": (_fu_dt.now() + _fu_td(days=dias)).strftime("%Y-%m-%dT%H:%M"),
            "texto": re.sub(r"\s+", " ", _fu_previa(m[3], m[4], m[5])).strip()[:120],
            "criado": time.strftime("%Y-%m-%dT%H:%M")}
    with _estado_lock:
        e = estado_ler()
        e["followups"] = ([f for f in e.get("followups") or [] if f.get("jid") != canon] + [item])[-200:]
        estado_gravar(e)
    _fu_limpar_cache()
    return {"success": True, "followup": item}


def _fu_lista(fus):
    agora_min = time.strftime("%Y-%m-%dT%H:%M")
    vivos, resp = [], set()
    db = ro(MSG_DB)
    try:
        for f in fus:
            if _fu_respondeu(db, f["jid"], f["ts"]):
                resp.add(f["id"])
            else:
                vivos.append({**f, "vencido": f["quando"] <= agora_min})
    except sqlite3.Error:
        return [{**f, "vencido": f["quando"] <= agora_min} for f in fus]
    finally:
        db.close()
    if resp:  # o contato respondeu: o lembrete some sozinho
        with _estado_lock:
            e = estado_ler()
            e["followups"] = [f for f in e.get("followups") or [] if f.get("id") not in resp]
            estado_gravar(e)
    return vivos


def fu_lista():
    """Lembretes ativos (com "vencido"). Recalcula quando o banco/estado muda ou a cada minuto."""
    fus = [dict(f) for f in estado_ler_cache().get("followups") or [] if f.get("jid") and f.get("ts")]
    if not fus:
        return []
    chave = ("fu", _marca_db(), _marca_arq(ESTADO), time.strftime("%Y-%m-%dT%H:%M"))
    return _fu_cache(chave, lambda: _fu_lista(fus))


_fu_api_chats0 = api_chats


def api_chats():
    """[followup] /api/chats + "followup" ({id, quando, vencido, texto, dias, ts}) nas conversas com lembrete ativo."""
    out = _fu_api_chats0()
    try:
        fus = {f["jid"]: f for f in fu_lista()}
    except Exception as ex:
        print("followup:", type(ex).__name__, ex)
        fus = {}
    if fus:
        for c in out:
            f = fus.get(c["jid"])
            if f:
                c["followup"] = {k: f[k] for k in ("id", "quando", "vencido", "texto", "dias", "ts")}
    return out


# ---- 3) tempo de resposta por conversa (painel de dados) ----
def api_tempo_resposta(jid):
    jid = str(jid or "")
    if not jid or not jid_conhecido(jid):
        return {"success": False, "erro": "conversa desconhecida"}
    canon = aliases()[1].get(jid, jid)
    return _fu_cache(("tempo", canon, time.strftime("%Y-%m-%d")), lambda: _api_tempo_resposta(canon))


def _api_tempo_resposta(canon):
    agora = _fu_dt.now().astimezone()
    jids = jids_da_conversa(canon)
    para = {j: canon for j in jids}
    # 37 dias: uma espera que começou até 7 dias antes da janela e foi respondida dentro dela conta inteira (igual ao ranking)
    linhas = _fu_linhas((agora - _fu_td(days=37)).isoformat(" ", "seconds"), jids)
    bl = _fu_blocos(linhas, para, agora)[0].get(canon, [])
    out = {"success": True, "jid": canon, "atendimento": [ATEND_H0, ATEND_H1]}
    for dias in (7, 30):
        corte = agora - _fu_td(days=dias)
        cs = corte.isoformat(" ", "seconds")
        rec = sum(1 for x in linhas if str(x[1]) >= cs and not x[2])
        env = sum(1 for x in linhas if str(x[1]) >= cs and x[2])
        out[f"d{dias}"] = {**_fu_stats([s for t, s in bl if t >= corte]), "recebidas": rec, "enviadas": env}
    return out


# ---- 2) relatório do dia + ranking "quem mais esperou (7 dias)" ----
def _fu_ranking(blocos, trab, agora, dias):
    """Contatos de trabalho (sem grupos) com a maior média de espera nos últimos `dias` dias."""
    corte = agora - _fu_td(days=dias)
    rk = []
    for j, bl in blocos.items():
        c = trab.get(j)
        v = [s for t, s in bl if t >= corte]
        if c and c["tipo"] == "individual" and v:
            rk.append({"jid": j, "nome": c["nome"], **_fu_stats(v)})
    rk.sort(key=lambda x: (-x["media"], -x["respostas"]))
    return rk


def api_ranking_espera(dias=7):
    """[rank-periodo] GET /api/ranking-espera?dias=N: o ranking da tela inicial no período escolhido (1 a 30 dias).
    Mesma regra do `ranking_7d` do /api/relatorio (com dias=7 o resultado é igual). Só leitura."""
    try:
        dias = max(1, min(30, int(dias or 7)))
    except (TypeError, ValueError):
        dias = 7
    return _fu_cache(("ranking", dias, time.strftime("%Y-%m-%d")), lambda: _api_ranking_espera(dias))


def _api_ranking_espera(dias):
    agora = _fu_dt.now().astimezone()
    # +8 dias: uma espera que começou até 7 dias antes da janela e foi respondida dentro dela conta inteira
    blocos = _fu_blocos(_fu_linhas((agora - _fu_td(days=dias + 8)).strftime("%Y-%m-%d")), aliases()[1], agora)[0]
    rk = _fu_ranking(blocos, _fu_trabalho(), agora, dias)
    return {"success": True, "dias": dias, "atendimento": [ATEND_H0, ATEND_H1], "total": len(rk), "ranking": rk[:20]}


def api_relatorio():
    pronto = int(time.strftime("%H")) >= FU_HORA_RELATORIO
    return _fu_cache(("relatorio", time.strftime("%Y-%m-%d"), pronto), _api_relatorio)


def _api_relatorio():
    agora = _fu_dt.now().astimezone()
    hoje = agora.strftime("%Y-%m-%d")
    para = aliases()[1]
    todos = {c["jid"]: c for c in api_chats_cache()}
    trab = _fu_trabalho()
    nome_de = lambda j: (todos.get(j) or {}).get("nome") or j
    # 15 dias (7 + 8), igual ao /api/ranking-espera: com 8 a espera que começou antes da janela ficava fora do ranking
    blocos, abertas, _ = _fu_blocos(_fu_linhas((agora - _fu_td(days=15)).strftime("%Y-%m-%d")), para, agora)

    # respondidas hoje (blocos fechados hoje) e tempo médio da 1ª resposta
    hoje_bl = {}
    for j, bl in blocos.items():
        if j in trab:
            v = [s for t, s in bl if t.strftime("%Y-%m-%d") == hoje]
            if v:
                hoje_bl[j] = v
    segs = [s for v in hoje_bl.values() for s in v]
    maior = None
    for j, v in hoje_bl.items():
        if not maior or max(v) > maior["seg"]:
            maior = {"jid": j, "nome": nome_de(j), "seg": max(v), "aberta": False}

    # ainda esperando (mesma regra do card "esperando resposta" da tela inicial)
    esp = sorted((c for c in trab.values() if not c.get("mudo") and not c.get("arquivado") and (c.get("espera") or 0) >= 60),
                 key=lambda c: -(c.get("espera") or 0))
    esperando = []
    for c in esp:
        ini = abertas.get(c["jid"])
        seg = _seg_atendimento(ini, agora) if ini else 0
        esperando.append({"jid": c["jid"], "nome": c["nome"], "seg": seg})
        if ini and (not maior or seg > maior["seg"]):
            maior = {"jid": c["jid"], "nome": c["nome"], "seg": seg, "aberta": True}

    # contatos novos: primeira mensagem da conversa (somando @lid + número) foi hoje
    db = ro(MSG_DB)
    try:
        prim = db.execute("select chat_jid, min(timestamp) from messages group by chat_jid").fetchall()
    except sqlite3.Error:
        prim = []
    finally:
        db.close()
    pri = {}
    for cj, ts in prim:
        cn, ts = para.get(cj, cj), str(ts or "")
        if ts and (cn not in pri or ts < pri[cn]):
            pri[cn] = ts
    novos = [{"jid": j, "nome": c["nome"]} for j, c in trab.items() if c["tipo"] == "individual" and pri.get(j, "")[:10] == hoje]

    est = estado_ler_cache()
    pagos = [p for p in est.get("pagos", []) if str(p.get("hora", ""))[:10] == hoje]
    ult = _fu_cal.monthrange(agora.year, agora.month)[1]
    fichas = []
    for j, f in (est.get("fichas") or {}).items():
        stt, venc = f.get("status") or "", f.get("vencimento") or 0
        if stt == "Inadimplente":
            motivo = "Inadimplente"
        elif stt != "Cancelado" and venc and (venc == agora.day or (venc > ult and agora.day == ult)):
            motivo = "Vence hoje"
        else:
            continue
        cj = para.get(j, j)
        fichas.append({"jid": cj, "nome": (todos.get(cj) or {}).get("nome") or f.get("empresa") or cj,
                       "motivo": motivo, "valor": f.get("valor")})
    fichas.sort(key=lambda x: (x["motivo"] != "Inadimplente", x["nome"].lower()))
    try:
        fl = fu_lista()
    except Exception:
        fl = []
    fu = {"ativos": len(fl), "vencidos": sum(1 for f in fl if f["vencido"])}

    # ranking: contatos (sem grupos) com a maior média de espera nos últimos 7 dias
    rk = _fu_ranking(blocos, trab, agora, 7)

    r = {"success": True, "data": hoje, "data_br": agora.strftime("%d/%m/%Y"), "hora": agora.strftime("%H:%M"),
         "pronto": agora.hour >= FU_HORA_RELATORIO, "hora_relatorio": FU_HORA_RELATORIO, "atendimento": [ATEND_H0, ATEND_H1],
         "respondidas": len(hoje_bl), "respostas": len(segs), "tempo_medio": int(sum(segs) / len(segs)) if segs else 0,
         "maior_espera": maior, "esperando": len(esperando), "esperando_lista": esperando[:12],
         "novos": len(novos), "novos_lista": novos[:12], "pagos": len(pagos),
         "pagos_conferir": sum(1 for p in pagos if not p.get("conferido")), "fichas": fichas[:20], "followups": fu,
         "ranking_7d": rk[:20]}
    nomes_ = lambda l: ", ".join(x["nome"] for x in l[:8]) + (f" e mais {len(l) - 8}" if len(l) > 8 else "")
    linhas = [f"Relatório do dia - {r['data_br']} (às {r['hora']})",
              f"- Conversas respondidas: {r['respondidas']}",
              f"- Ainda esperando resposta: {r['esperando']}" + (f" ({nomes_(esperando)})" if esperando else ""),
              "- Tempo médio da 1ª resposta: " + (f"{_fu_dur(r['tempo_medio'])} ({r['respostas']} respostas, contando das {ATEND_H0}h às {ATEND_H1}h)" if segs else "sem respostas hoje"),
              "- Maior espera: " + (f"{_fu_dur(maior['seg'])} - {maior['nome']}" + (" (ainda esperando)" if maior["aberta"] else "") if maior else "nenhuma"),
              f"- Contatos novos: {r['novos']}" + (f" ({nomes_(novos)})" if novos else ""),
              f"- Comprovantes \"Pago?\": {r['pagos']}" + (f" ({r['pagos_conferir']} para conferir)" if r["pagos_conferir"] else ""),
              f"- Fichas em atraso ou vencendo hoje: {len(fichas)}" + (" (" + ", ".join(f"{x['nome']} - {x['motivo']}" for x in fichas[:8]) + ")" if fichas else ""),
              f"- Lembretes \"sem resposta\": {fu['vencidos']} vencidos, {fu['ativos'] - fu['vencidos']} aguardando"]
    r["texto"] = "\n".join(linhas)
    return r


# ---------- [figurinhas] figurinhas salvas: coleção local, envio pelo caminho normal, criar a partir de imagem ----------
# Arquivos em painel\figurinhas\<sha1>.webp (o nome é o hash do conteúdo: a mesma figurinha nunca entra duas vezes)
# e os dados em painel\figurinhas\indice.json. Remover move para figurinhas\lixeira\ (dá para desfazer; some em 7 dias).
# Enviar = copiar para uploads\ como *.sticker.webp e seguir pelo /api/enviar de sempre (pendente, ✓✓, apagar o upload).
import shutil as _fig_shutil
FIG_DIR = os.path.join(AQUI, "figurinhas")
FIG_MAX_ESTATICA = 1024 * 1024          # arquivo guardado: 1 MB (parada) / 1,5 MB (animada)
FIG_MAX_ANIMADA = 1536 * 1024
FIG_MAX_ENTRADA = 10 * 1024 * 1024      # "Criar figurinha": foto do celular (png/jpg/webp) até 10 MB
FIG_MAX_PIXELS = 40_000_000             # contra imagem-bomba
FIG_LIXEIRA_DIAS = 7
FIG_MAX_ITENS = 2000
_fig_lock = threading.RLock()
_fig_ponte = {"t": 0.0, "ok": False}
_FIG_HASH = re.compile(r"[0-9a-f]{40}")


def _fig_hash_ok(h):
    h = str(h or "")
    if not _FIG_HASH.fullmatch(h):
        raise ErroEnvio("figurinha inválida")
    return h


def _fig_indice():
    try:
        with open(os.path.join(FIG_DIR, "indice.json"), encoding="utf-8") as f:
            d = json.load(f)
        if not isinstance(d, dict):
            raise ValueError
    except (OSError, ValueError):
        d = {}
    itens = [x for x in d.get("itens", []) if isinstance(x, dict) and _FIG_HASH.fullmatch(str(x.get("hash", "")))]
    lixo = [x for x in d.get("lixeira", []) if isinstance(x, dict) and _FIG_HASH.fullmatch(str(x.get("hash", "")))]
    return {"versao": 1, "itens": itens, "lixeira": lixo}


def _fig_gravar(d):
    os.makedirs(FIG_DIR, exist_ok=True)
    destino = os.path.join(FIG_DIR, "indice.json")
    tmp = destino + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    os.replace(tmp, destino)


def _fig_formato(b):
    if len(b) >= 12 and b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return "webp"
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if b[:3] == b"\xff\xd8\xff":
        return "jpg"
    return ""


def fig_webp_info(b):
    """(animada, largura, altura) lendo os blocos RIFF do WebP — sem depender do Pillow."""
    anim, w, h = False, 0, 0
    if _fig_formato(b) != "webp":
        return anim, w, h
    p = 12
    while p + 8 <= len(b):
        cid, tam = b[p:p + 4], int.from_bytes(b[p + 4:p + 8], "little")
        dado = b[p + 8:p + 8 + tam]
        if cid in (b"ANIM", b"ANMF"):
            anim = True
        elif cid == b"VP8X" and len(dado) >= 10:
            anim = anim or bool(dado[0] & 0x02)
            w = int.from_bytes(dado[4:7], "little") + 1
            h = int.from_bytes(dado[7:10], "little") + 1
        elif cid == b"VP8 " and not w and len(dado) >= 10 and dado[3:6] == b"\x9d\x01\x2a":
            w = int.from_bytes(dado[6:8], "little") & 0x3FFF
            h = int.from_bytes(dado[8:10], "little") & 0x3FFF
        elif cid == b"VP8L" and not w and len(dado) >= 5 and dado[0] == 0x2F:
            v = int.from_bytes(dado[1:5], "little")
            w, h = (v & 0x3FFF) + 1, ((v >> 14) & 0x3FFF) + 1
        if tam > len(b):
            break
        p += 8 + tam + (tam & 1)
    return anim, w, h


def fig_ponte_animada():
    """A ponte atualizada responde /api/recursos com sticker_animado=true (ela marca IsAnimated no envio)."""
    agora = time.time()
    if agora - _fig_ponte["t"] < (300 if _fig_ponte["ok"] else 60):
        return _fig_ponte["ok"]
    ok = False
    try:
        with urllib.request.urlopen(PONTE + "/api/recursos", timeout=2) as r:
            ok = bool(json.load(r).get("sticker_animado"))
    except Exception:
        ok = False
    _fig_ponte.update(t=agora, ok=ok)
    return ok


def _fig_info_msg(jid, mid):
    """(media_type, filename, data, nome da conversa) da mensagem — só leitura do messages.db."""
    db = ro(MSG_DB)
    try:
        r = db.execute("select media_type, filename, timestamp from messages where id=? and chat_jid=?", (mid, jid)).fetchone()
        c = db.execute("select name from chats where jid=?", (jid,)).fetchone()
    finally:
        db.close()
    if not r:
        raise ErroEnvio("mensagem não encontrada")
    try:
        nomes, lid2pn = carregar_nomes()
        nc = nome_chat(jid, c[0] if c else "", nomes, lid2pn)
    except Exception:
        nc = jid
    return r[0] or "", r[1] or "", str(r[2] or ""), nc


def _fig_publico(x):
    return {k: x.get(k) for k in ("hash", "arquivo", "animada", "largura", "altura", "origem", "salva_em",
                                  "usos", "ultimo_uso", "favorita")}


def _fig_guardar(dados_webp, origem):
    """Guarda o WebP na coleção (dedupe por sha1). Retorna (item, ja_existia)."""
    if _fig_formato(dados_webp) != "webp":
        raise ErroEnvio("a figurinha precisa ser WebP")
    anim, w, h = fig_webp_info(dados_webp)
    limite = FIG_MAX_ANIMADA if anim else FIG_MAX_ESTATICA
    if len(dados_webp) > limite:
        raise ErroEnvio("figurinha grande demais (%d KB; máx. %d KB)" % (len(dados_webp) // 1024, limite // 1024), 413)
    hx = hashlib.sha1(dados_webp).hexdigest()
    with _fig_lock:
        d = _fig_indice()
        for x in d["itens"]:
            if x["hash"] == hx:
                return x, True
        volta = next((x for x in d["lixeira"] if x["hash"] == hx), None)
        if len(d["itens"]) >= FIG_MAX_ITENS:
            raise ErroEnvio("coleção cheia (%d figurinhas); remova algumas" % FIG_MAX_ITENS)
        os.makedirs(FIG_DIR, exist_ok=True)
        arq = hx + ".webp"
        tmp = os.path.join(FIG_DIR, arq + ".tmp")
        with open(tmp, "wb") as f:
            f.write(dados_webp)
        os.replace(tmp, os.path.join(FIG_DIR, arq))
        try:
            os.remove(os.path.join(FIG_DIR, "lixeira", arq))
        except OSError:
            pass
        agora = time.strftime("%Y-%m-%dT%H:%M:%S")
        if volta:
            d["lixeira"].remove(volta)
            volta.pop("removida_em", None)
            item = volta
        else:
            item = {"hash": hx, "arquivo": arq, "animada": anim, "largura": w, "altura": h, "origem": origem,
                    "salva_em": agora, "usos": 0, "ultimo_uso": "", "favorita": False}
        d["itens"].append(item)
        _fig_gravar(d)
        return item, False


def fig_salvar(dados):
    jid, mid = str(dados.get("jid") or "")[:120], str(dados.get("id") or "")[:120]
    if not jid or not mid or not jid_conhecido(jid):
        raise ErroEnvio("mensagem desconhecida")
    mt, fn, data, nc = _fig_info_msg(jid, mid)
    if mt != "sticker" and not fn.lower().endswith(".sticker.webp"):
        raise ErroEnvio("esta mensagem não é uma figurinha")
    try:
        path, _mt, _fn = baixar_midia(mid, jid)
    except PonteIndisponivel:
        raise ErroEnvio("ponte do WhatsApp indisponível no momento; tente de novo", 503)
    if not path:
        raise ErroEnvio("não foi possível baixar a figurinha", 404)
    if os.path.getsize(path) > FIG_MAX_ANIMADA:
        raise ErroEnvio("figurinha grande demais", 413)
    with open(path, "rb") as f:
        b = f.read()
    item, ja = _fig_guardar(b, {"jid": jid, "id": mid, "nome_conversa": nc, "data": data})
    return {"success": True, "item": _fig_publico(item), "ja_existia": ja}


def _fig_lixeira_limpar(d):
    """Apaga de vez o que está na lixeira há mais de FIG_LIXEIRA_DIAS. Retorna True se mudou algo."""
    limite = time.time() - FIG_LIXEIRA_DIAS * 86400
    fica, mudou = [], False
    for x in d["lixeira"]:
        try:
            t = time.mktime(time.strptime(x.get("removida_em", ""), "%Y-%m-%dT%H:%M:%S"))
        except (ValueError, OverflowError):
            t = 0
        if t < limite:
            mudou = True
            try:
                os.remove(os.path.join(FIG_DIR, "lixeira", x["hash"] + ".webp"))
            except OSError:
                pass
        else:
            fica.append(x)
    d["lixeira"] = fica
    return mudou


def fig_listar():
    with _fig_lock:
        d = _fig_indice()
        if d["lixeira"] and _fig_lixeira_limpar(d):
            _fig_gravar(d)
        itens = [_fig_publico(x) for x in d["itens"] if os.path.isfile(os.path.join(FIG_DIR, x["hash"] + ".webp"))]
    itens.sort(key=lambda x: x.get("salva_em") or "", reverse=True)
    return {"success": True, "itens": itens, "animadas_ok": fig_ponte_animada(),
            "limites": {"estatica": FIG_MAX_ESTATICA, "animada": FIG_MAX_ANIMADA, "entrada": FIG_MAX_ENTRADA}}


def fig_arquivo(h):
    h = _fig_hash_ok(h)
    p = os.path.join(FIG_DIR, h + ".webp")
    if not os.path.isfile(p):
        return None
    with open(p, "rb") as f:
        return f.read()


def _fig_primeiro_quadro(origem, destino):
    from PIL import Image
    with Image.open(origem) as im:
        im.seek(0)
        q = im.convert("RGBA")
    q.save(destino, "WEBP", quality=80, method=4)


def fig_preparar(dados):
    """Copia a figurinha para uploads\\ como *.sticker.webp (o /api/enviar normal manda como figurinha)."""
    h = _fig_hash_ok(dados.get("h"))
    with _fig_lock:
        d = _fig_indice()
        item = next((x for x in d["itens"] if x["hash"] == h), None)
        if not item:
            raise ErroEnvio("figurinha não encontrada", 404)
        origem = os.path.join(FIG_DIR, h + ".webp")
        if not os.path.isfile(origem):
            raise ErroEnvio("arquivo da figurinha sumiu", 404)
        os.makedirs(UPLOADS, exist_ok=True)
        destino = os.path.join(UPLOADS, nome_seguro("figurinha.sticker.webp", ".webp"))
        aviso = ""
        if item.get("animada") and not fig_ponte_animada():
            try:
                _fig_primeiro_quadro(origem, destino)
                aviso = "A ponte ainda não envia figurinha animada: foi só o 1º quadro (parada)."
            except Exception:
                raise ErroEnvio("a ponte ainda não envia figurinha animada (atualize a ponte)")
        else:
            _fig_shutil.copyfile(origem, destino)
        item["usos"] = int(item.get("usos") or 0) + 1
        item["ultimo_uso"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        _fig_gravar(d)
    r = {"success": True, "path": destino, "nome": os.path.basename(destino), "bytes": os.path.getsize(destino)}
    if aviso:
        r["aviso"] = aviso
    return r


def fig_favoritar(dados):
    h = _fig_hash_ok(dados.get("h"))
    with _fig_lock:
        d = _fig_indice()
        item = next((x for x in d["itens"] if x["hash"] == h), None)
        if not item:
            raise ErroEnvio("figurinha não encontrada", 404)
        item["favorita"] = bool(dados.get("sim"))
        _fig_gravar(d)
    return {"success": True, "item": _fig_publico(item)}


def fig_remover(dados):
    h = _fig_hash_ok(dados.get("h"))
    with _fig_lock:
        d = _fig_indice()
        item = next((x for x in d["itens"] if x["hash"] == h), None)
        if not item:
            raise ErroEnvio("figurinha não encontrada", 404)
        os.makedirs(os.path.join(FIG_DIR, "lixeira"), exist_ok=True)
        try:
            os.replace(os.path.join(FIG_DIR, h + ".webp"), os.path.join(FIG_DIR, "lixeira", h + ".webp"))
        except OSError:
            pass
        d["itens"].remove(item)
        item["removida_em"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        d["lixeira"] = [x for x in d["lixeira"] if x["hash"] != h] + [item]
        _fig_gravar(d)
    return {"success": True}


def fig_restaurar(dados):
    h = _fig_hash_ok(dados.get("h"))
    with _fig_lock:
        d = _fig_indice()
        item = next((x for x in d["lixeira"] if x["hash"] == h), None)
        if not item:
            raise ErroEnvio("não dá mais para desfazer", 404)
        try:
            os.replace(os.path.join(FIG_DIR, "lixeira", h + ".webp"), os.path.join(FIG_DIR, h + ".webp"))
        except OSError:
            raise ErroEnvio("arquivo da figurinha não está mais na lixeira", 404)
        d["lixeira"].remove(item)
        item.pop("removida_em", None)
        d["itens"].append(item)
        _fig_gravar(d)
    return {"success": True, "item": _fig_publico(item)}


def _fig_webp_ate(salvar, alvo, minimo_q=30):
    """Salva com qualidade decrescente até caber em `alvo` bytes; retorna os bytes da última tentativa."""
    import io
    b = b""
    for q in (85, 75, 60, 45, minimo_q):
        buf = io.BytesIO()
        salvar(buf, q)
        b = buf.getvalue()
        if len(b) <= alvo:
            break
    return b


def fig_criar(q, corpo):
    """Imagem (png/jpg/webp, até 10 MB) -> figurinha 512x512 WebP. modo=cortar (x, y, lado em pixels da imagem
    já girada pelo EXIF) ou modo=inteira (encaixa sem cortar, sobra transparente). WebP animado continua animado."""
    try:
        from PIL import Image, ImageOps, ImageSequence
    except ImportError:
        raise ErroEnvio("Pillow não está instalado; inicie o painel pelo iniciar-painel.cmd", 500)
    import io
    fmt = _fig_formato(corpo)
    if fmt not in ("png", "jpg", "webp"):
        raise ErroEnvio("use uma imagem PNG, JPG ou WebP")
    modo = q.get("modo", ["cortar"])[0]
    if modo not in ("cortar", "inteira"):
        raise ErroEnvio("modo inválido")

    def num(k):
        v = q.get(k, ["0"])[0]
        if not re.fullmatch(r"\d{1,6}", v or ""):
            raise ErroEnvio("recorte inválido")
        return int(v)
    cx, cy, lado = num("x"), num("y"), num("lado")
    try:
        im = Image.open(io.BytesIO(corpo))
        if im.width * im.height > FIG_MAX_PIXELS:
            raise ErroEnvio("imagem grande demais (máx. 40 megapixels)")
        im.load()
    except ErroEnvio:
        raise
    except Exception:
        raise ErroEnvio("não foi possível ler a imagem")

    def ajustar(fr):
        fr = fr.convert("RGBA")
        if modo == "inteira":
            fr.thumbnail((512, 512), Image.LANCZOS)
            tela = Image.new("RGBA", (512, 512), (0, 0, 0, 0))
            tela.paste(fr, ((512 - fr.width) // 2, (512 - fr.height) // 2), fr)
            return tela
        L = min(lado or min(fr.size), fr.width, fr.height)
        x0, y0 = max(0, min(cx, fr.width - L)), max(0, min(cy, fr.height - L))
        return fr.crop((x0, y0, x0 + L, y0 + L)).resize((512, 512), Image.LANCZOS)

    animada = fmt == "webp" and getattr(im, "is_animated", False)
    if animada:
        if getattr(im, "n_frames", 1) > 300:
            raise ErroEnvio("animação longa demais (máx. 300 quadros)")
        quadros, tempos = [], []
        for fr in ImageSequence.Iterator(im):
            tempos.append(int(fr.info.get("duration") or 80))
            quadros.append(ajustar(fr))

        def salvar(buf, qual):
            quadros[0].save(buf, "WEBP", save_all=True, append_images=quadros[1:], duration=tempos, loop=0,
                            quality=qual, method=4)
        b = _fig_webp_ate(salvar, 500 * 1024)
    else:
        im = ImageOps.exif_transpose(im)  # o navegador mostra já girada (JPG e também PNG/WebP com EXIF)
        quadro = ajustar(im)

        def salvar(buf, qual):
            quadro.save(buf, "WEBP", quality=qual, method=4)
        b = _fig_webp_ate(salvar, 100 * 1024)
    nome_orig = os.path.basename(q.get("nome", [""])[0])[:80]
    item, ja = _fig_guardar(b, {"jid": "", "id": "", "nome_conversa": "Criada no painel",
                                "data": time.strftime("%Y-%m-%dT%H:%M:%S"), "arquivo_original": nome_orig})
    return {"success": True, "item": _fig_publico(item), "ja_existia": ja}


_fig_get0 = Handler.do_GET
_fig_post0 = Handler.do_POST


def _fig_do_GET(self):
    u = urlparse(self.path)
    if u.path not in ("/api/figurinhas", "/api/figurinhas/arquivo"):
        return _fig_get0(self)
    if not self.portaria(post=False):
        return
    try:
        if u.path == "/api/figurinhas":
            return self.json(fig_listar())
        b = fig_arquivo(parse_qs(u.query).get("h", [""])[0])
        if b is None:
            return self.enviar(404, "figurinha não encontrada", "text/plain; charset=utf-8")
        # o nome é o hash do conteúdo: o arquivo nunca muda, então pode ficar no cache para sempre
        return self.enviar(200, b, "image/webp", {"Cache-Control": "private, max-age=31536000, immutable"})
    except ErroEnvio as e:
        self.json({"success": False, "erro": str(e)}, e.code)
    except Exception as e:
        self.json({"success": False, "erro": f"{type(e).__name__}: {e}"}, 500)


def _fig_do_POST(self):
    u = urlparse(self.path)
    if u.path not in ("/api/figurinhas", "/api/figurinhas/criar"):
        return _fig_post0(self)
    if not self.portaria(post=True):
        return
    try:
        tam = int(self.headers.get("Content-Length") or 0)
        if u.path == "/api/figurinhas/criar":
            if tam <= 0:
                raise ErroEnvio("arquivo vazio")
            if tam > FIG_MAX_ENTRADA:
                raise ErroEnvio("imagem maior que 10 MB", 413)
            corpo, falta = [], tam
            while falta > 0:
                bloco = self.rfile.read(min(1 << 20, falta))
                if not bloco:
                    break
                corpo.append(bloco)
                falta -= len(bloco)
            if falta:
                raise ErroEnvio("upload incompleto")
            return self.json(fig_criar(parse_qs(u.query), b"".join(corpo)))
        if tam > 64 * 1024:
            raise ErroEnvio("requisição grande demais", 413)
        dados = json.loads(self.rfile.read(tam) or b"{}")
        if not isinstance(dados, dict):
            raise ErroEnvio("requisição inválida")
        acao = dados.get("acao")
        f = {"salvar": fig_salvar, "preparar": fig_preparar, "favoritar": fig_favoritar,
             "remover": fig_remover, "restaurar": fig_restaurar}.get(acao)
        if not f:
            raise ErroEnvio("ação desconhecida")
        return self.json(f(dados))
    except ErroEnvio as e:
        self.close_connection = True
        self.json({"success": False, "erro": str(e)}, e.code)
    except Exception as e:
        self.close_connection = True
        self.json({"success": False, "erro": f"{type(e).__name__}: {e}"}, 500)


Handler.do_GET = _fig_do_GET
Handler.do_POST = _fig_do_POST
# ---------- fim [figurinhas] ----------


# ---------- [numeros] números clicáveis: "Conversar com +55 …" (inclusive número que ainda não tem conversa) ----------
# GET /api/numero?n=<dígitos> (só leitura). Se o número já tem conversa (pelo número, pelo @lid ou pela variante com/sem o
# 9º dígito) devolve a conversa existente. Se não tem, pergunta à ponte (GET /api/onwhatsapp, também só leitura) se o
# número tem WhatsApp; confirmado, o JID entra numa lista curta (10 min) e SÓ ELE pode receber a 1ª mensagem
# (enviar_mensagem consulta numero_liberado). Nunca libera um JID qualquer vindo do navegador.
NUM_TTL = 600            # segundos que um número confirmado fica liberado para a 1ª mensagem
NUM_CONSULTAS_MIN = 15   # consultas novas à ponte por minuto (respostas guardadas não contam)
_num_ok = {}             # jid -> expira (time.time())
_num_cache = {}          # dígitos -> (time.time(), resposta da ponte)
_num_consultas = []
_num_lock = threading.Lock()
NUM_DDDS = {11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 24, 27, 28, 31, 32, 33, 34, 35, 37, 38, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 51, 53, 54, 55, 61, 62, 63, 64, 65, 66, 67, 68, 69, 71, 73, 74, 75, 77, 79, 81, 82, 83, 84, 85,
            86, 87, 88, 89, 91, 92, 93, 94, 95, 96, 97, 98, 99}


def _num_br(local):
    """DDD + número (10 ou 11 dígitos) -> '55…' com o 9º dígito nos celulares, ou '' se não parece telefone do Brasil."""
    if len(local) not in (10, 11) or not local.isdigit() or int(local[:2]) not in NUM_DDDS:
        return ""
    n = local[2:]
    if len(n) == 9:
        return "55" + local if n[0] == "9" else ""
    if n[0] not in "23456789":
        return ""
    return "55" + local[:2] + ("9" + n if n[0] in "6789" else n)  # celular antigo, sem o 9º dígito


def numero_normalizar(n):
    """Dígitos do número em formato internacional sem '+' (ex.: '5511970530923') ou '' se inválido.
    O painel já manda normalizado; aqui só confere de novo (10-15 dígitos; 10/11 dígitos = Brasil sem o 55)."""
    s = str(n or "").strip()
    d = re.sub(r"\D", "", s)
    if not d or len(d) > 15:
        return ""
    if d.startswith("55") and len(d) in (12, 13):
        return _num_br(d[2:])
    if len(d) in (10, 11) and not s.startswith("+"):
        return _num_br(d)
    if 10 <= len(d) <= 15 and d[0] != "0" and not d.startswith("55"):
        return d
    return ""


def numero_variantes(d):
    """O mesmo número com e sem o 9º dígito (o WhatsApp guarda alguns celulares antigos sem ele)."""
    v = [d]
    if d.startswith("55") and len(d) == 13 and d[4] == "9":
        v.append(d[:4] + d[5:])
    elif d.startswith("55") and len(d) == 12 and d[4] in "6789":
        v.append(d[:4] + "9" + d[4:])
    return v


def numero_liberado(jid):
    with _num_lock:
        t = _num_ok.get(jid)
        return bool(t and t > time.time())


def _num_conversa(numeros, lid=""):
    """Conversa já existente para algum dos números (ou para o LID), já no JID canônico (@lid juntado ao número)."""
    _nomes, lid2pn = carregar_nomes()
    pn2lid = {p: l for l, p in lid2pn.items()}
    para = aliases()[1]
    cands = []
    for v in numeros:
        cands.append(v + "@s.whatsapp.net")
        if pn2lid.get(v):
            cands.append(pn2lid[v] + "@lid")
    if lid:
        cands.append(lid)
    db = ro(MSG_DB)
    try:
        for j in cands:
            if db.execute("select 1 from chats where jid=?", (j,)).fetchone():
                return para.get(j, j)
    finally:
        db.close()
    return ""


def _num_ponte(d):
    """Resposta de GET /api/onwhatsapp da ponte (com cache de NUM_TTL e freio de consultas por minuto)."""
    agora = time.time()
    with _num_lock:
        c = _num_cache.get(d)
        if c and agora - c[0] < NUM_TTL:
            return c[1]
        _num_consultas[:] = [t for t in _num_consultas if agora - t < 60]
        if len(_num_consultas) >= NUM_CONSULTAS_MIN:
            raise ErroEnvio("Muitas consultas de número seguidas. Tente de novo em 1 minuto.", 429)
        _num_consultas.append(agora)
    try:
        r = ponte_get("/api/onwhatsapp?phone=" + d, timeout=20)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise ErroEnvio("A ponte do WhatsApp ainda não tem a consulta de números (precisa atualizar a ponte).", 501)
        if e.code == 429:
            raise ErroEnvio("Muitas consultas de número seguidas. Tente de novo em 1 minuto.", 429)
        raise ErroEnvio(f"a ponte não conseguiu consultar o número ({e.code})", 502)
    except Exception as e:
        raise ErroEnvio(f"ponte do WhatsApp indisponível: {e}", 503)
    with _num_lock:
        for k in [k for k, (t, _) in _num_cache.items() if agora - t >= NUM_TTL]:
            _num_cache.pop(k, None)
        _num_cache[d] = (agora, r)
    return r


def api_numero(n):
    d = numero_normalizar(n)
    if not d:
        return {"success": False, "erro": "número inválido"}
    nomes, lid2pn = carregar_nomes()
    j = _num_conversa(numero_variantes(d))
    if j:
        return {"success": True, "existe": True, "conhecido": True, "jid": j, "numero": d,
                "nome": nome_chat(j, "", nomes, lid2pn)}
    try:
        r = _num_ponte(d)
    except ErroEnvio as e:
        return {"success": False, "erro": str(e)}
    if not r.get("success", True) or not r.get("exists"):
        return {"success": True, "existe": False, "numero": d}
    jid, lid = str(r.get("jid") or ""), str(r.get("lid") or "")
    m = re.fullmatch(r"(\d{8,15})@s\.whatsapp\.net", jid)
    if not m or (lid and not re.fullmatch(r"\d{1,20}@lid", lid)):
        return {"success": False, "erro": "resposta inesperada da ponte"}
    pn = m.group(1)
    j = _num_conversa(numero_variantes(pn), lid)  # o WhatsApp pode devolver o número canônico (ex.: sem o 9º dígito)
    if j:
        return {"success": True, "existe": True, "conhecido": True, "jid": j, "numero": pn,
                "nome": nome_chat(j, "", nomes, lid2pn)}
    with _num_lock:
        agora = time.time()
        for k in [k for k, t in _num_ok.items() if t <= agora]:
            _num_ok.pop(k, None)
        _num_ok[jid] = agora + NUM_TTL
    nm = str(r.get("name") or r.get("verified_name") or "")[:100]
    return {"success": True, "existe": True, "conhecido": False, "jid": jid, "lid": lid, "numero": pn, "nome": nm,
            "foto": "/api/avatar?jid=" + quote(jid), "validade": NUM_TTL}


# ---------- [saude] Saúde do sistema, backup completo em segundo local e threads periódicas blindadas ----------
# GET  /api/saude-sistema[?novo=1]   (só leitura, cache de 10 s)  -> cards da tela Configurações > Saúde do sistema
# POST /api/backup {acao: salvar | agora | testar}                 -> destino do backup, "fazer agora", "testar restauração"
# Nada aqui envia mensagem, mexe na sessão do WhatsApp ou sobe arquivo para a internet. O "segundo local" é sempre uma
# pasta local escolhida pelo operador (outro disco, pendrive ou pasta sincronizada do OneDrive).
import ctypes as _sd_ct
import hashlib as _sd_hl
import shutil as _sd_sh
import subprocess as _sd_sp
import tempfile as _sd_tmp
import traceback as _sd_tb
import zipfile as _sd_zip
from datetime import datetime as _sd_dt
from pathlib import Path as _sd_Path

_SD_T0 = time.time()
_SD_BKCFG = os.path.join(AQUI, "backup_config.json")
_SD_BKEST = os.path.join(AQUI, "backup_estado.json")
_SD_PASTA_DESTINO = "WhatsApp-Painel-Backup"   # subpasta criada dentro do segundo local
_SD_DIARIOS, _SD_SEMANAIS = 7, 4
_sd_arq_lock = threading.Lock()
_sd_bk_run = threading.Lock()                  # um backup extra por vez
_sd_teste_lock = threading.Lock()              # uma restauração de teste por vez
_sd_teste_ultimo = [0.0]
_sd_threads = {}                               # nome -> {vivo, inicios, erros, ultimo_erro, ultimo_erro_em}
_sd_sse = {"n": 0, "pico": 0}
_sd_sse_lock = threading.Lock()


def _sd_agora_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _sd_json_ler(path, padrao):
    try:
        with open(path, encoding="utf-8") as f:
            v = json.load(f)
        return v if isinstance(v, type(padrao)) else padrao
    except (OSError, ValueError):
        return padrao


def _sd_json_gravar(path, obj):
    with _sd_arq_lock:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1)
        os.replace(tmp, path)


def _sd_erro_txt(ex):
    return f"{type(ex).__name__}: {ex}"[:200]


# ---------- 4) threads periódicas: qualquer exceção é registrada e o laço volta sozinho ----------
def _sd_robusto(fn, nome):
    """Roda fn() (um laço infinito do painel). Se levantar exceção, grava em painel_log.txt e recomeça com espera
    crescente (5 s, 10 s... até 5 min; volta a 5 s se ficou de pé mais de 1 min)."""
    if getattr(fn, "_sd_envolvida", False):
        return fn

    def alvo():
        info = _sd_threads.setdefault(nome, {"vivo": False, "inicios": 0, "erros": 0, "ultimo_erro": "", "ultimo_erro_em": ""})
        espera = 5
        while True:
            info["inicios"] += 1
            info["vivo"] = True
            t0 = time.time()
            try:
                fn()
                info["vivo"] = False
                registrar("thread_fim", thread=nome)
                return
            except Exception as ex:
                info.update(vivo=False, ultimo_erro=_sd_erro_txt(ex), ultimo_erro_em=_sd_agora_iso())
                info["erros"] += 1
                registrar("thread_erro", thread=nome, erro=_sd_erro_txt(ex), reinicio_em=espera)
                try:
                    linhas = _sd_tb.format_exc().strip().splitlines()
                    registrar("thread_erro_local", thread=nome, onde=linhas[-3].strip() if len(linhas) >= 3 else "")
                except Exception:
                    pass
            if time.time() - t0 > 60:
                espera = 5
            time.sleep(espera)
            espera = min(espera * 2, 300)
    alvo.__name__ = nome
    alvo._sd_envolvida = True
    return alvo


for _sd_n in ("_vigiar_ponte", "_agendador", "_campanhas_loop", "_limpeza", "_backup", "_autonomia", "_rasc_cobranca"):
    if _sd_n in globals():
        globals()[_sd_n] = _sd_robusto(globals()[_sd_n], _sd_n)

# Os laços de campanhas, autonomia e rascunhos já seguram a exceção, mas só com print() (a janela do painel é oculta, então
# o erro se perdia). Este print() do módulo repassa o aviso ao painel_log.txt (no máximo 1 linha a cada 5 min por origem).
_sd_print0 = print
_SD_PREFIXOS_PRINT = ("campanhas", "autonomia", "rascunhos")


def print(*args, **kw):  # noqa: A001 - de propósito: só este módulo
    _sd_print0(*args, **kw)
    try:
        txt = " ".join(str(a) for a in args)
        for p in _SD_PREFIXOS_PRINT:
            if txt.startswith(p):
                registrar("erro_periodico", repetir=300, classe=p, origem=p, detalhe=txt[len(p):].strip(" :"))
                break
    except Exception:
        pass


# ---------- processos (só leitura): ponte, transcritor e notificador ----------
_sd_proc = {"t": 0.0, "ok": False, "v": {}}


def _sd_criacao(s):
    try:
        return time.mktime(time.strptime(str(s)[:14], "%Y%m%d%H%M%S"))
    except (ValueError, OverflowError):
        return 0.0


def _sd_listar_processos():
    """[{pid, nome, cmd, criado}] ou None se não deu para listar. Só leitura (wmic; se faltar, PowerShell)."""
    if os.name != "nt":  # [vps] Linux: lê /proc direto
        out = []
        try:
            boot = time.time() - float(open("/proc/uptime").read().split()[0])
            hz = os.sysconf("SC_CLK_TCK")
            for d in os.listdir("/proc"):
                if not d.isdigit():
                    continue
                try:
                    cmd = open(f"/proc/{d}/cmdline", "rb").read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
                    nome = open(f"/proc/{d}/comm").read().strip()
                    inicio = boot + int(open(f"/proc/{d}/stat").read().rsplit(")", 1)[1].split()[19]) / hz
                except (OSError, ValueError, IndexError):
                    continue
                out.append({"pid": int(d), "nome": nome, "cmd": cmd, "criado": inicio})
            return out
        except OSError:
            return None
    flags = 0x08000000 if os.name == "nt" else 0   # CREATE_NO_WINDOW
    try:
        r = _sd_sp.run(["wmic", "process", "get", "Name,ProcessId,CommandLine,CreationDate", "/format:list"],
                       capture_output=True, text=True, errors="replace", timeout=25, creationflags=flags)
        if r.returncode == 0 and "ProcessId=" in r.stdout:
            out, cur = [], {}
            for ln in r.stdout.splitlines():  # o wmic separa campos e registros com linhas em branco: ProcessId é o último campo
                if not ln.strip():
                    continue
                k, _, v = ln.strip().partition("=")
                cur[k] = v
                if k == "ProcessId":
                    out.append({"pid": int(v or 0), "nome": cur.get("Name", ""), "cmd": cur.get("CommandLine", ""),
                                "criado": _sd_criacao(cur.get("CreationDate", ""))})
                    cur = {}
            return out
    except (OSError, ValueError, _sd_sp.SubprocessError):
        pass
    try:
        ps = ("Get-CimInstance Win32_Process | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.ProcessId,$_.Name,"
              "$_.CreationDate.ToString('yyyyMMddHHmmss'),$_.CommandLine }")
        r = _sd_sp.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True, text=True,
                       errors="replace", timeout=40, creationflags=flags)
        if r.returncode == 0:
            out = []
            for ln in r.stdout.splitlines():
                p = ln.split("|", 3)
                if len(p) == 4 and p[0].isdigit():
                    out.append({"pid": int(p[0]), "nome": p[1], "cmd": p[3], "criado": _sd_criacao(p[2])})
            return out
    except (OSError, ValueError, _sd_sp.SubprocessError):
        pass
    return None


def _sd_proc_atualizar():
    lista = _sd_listar_processos()
    if lista is None:
        _sd_proc.update(t=time.time(), ok=False)
        return
    meu = os.getpid()

    def achar(exe=None, script=None):
        cand = []
        for p in lista:
            n = p["nome"].lower()
            if exe and (n == exe or n == exe[:-4][:15]):  # [vps] no Linux o nome vem sem .exe e cortado em 15 letras
                cand.append(p)
            elif script and script in p["cmd"] and (n in ("python.exe", "pythonw.exe", "uv.exe", "uv") or n.startswith("python")) and p["pid"] != meu:
                cand.append(p)
        if not cand:
            return {"vivo": False, "pid": 0, "desde": 0.0}
        cand.sort(key=lambda p: (not p["nome"].lower().startswith("python"), p["criado"] or 1e18))
        return {"vivo": True, "pid": cand[0]["pid"], "desde": cand[0]["criado"]}
    v = {"ponte": achar(exe="whatsapp-bridge.exe"), "transcritor": achar(script="transcritor_servico.py"),
         "notificador": achar(script="notificador.py")}
    _sd_proc.update(t=time.time(), ok=True, v=v)


_sd_ponte_est = {"chave": "", "desde": 0.0}


def _sd_ponte_chave():
    s = dict(saude)
    if s.get("qr"):
        k = "qr"
    elif not s.get("ponte"):
        k = "fora"
    elif not s.get("conectado"):
        k = "desconectado"
    else:
        k = "conectado"
    if k != _sd_ponte_est["chave"]:
        _sd_ponte_est.update(chave=k, desde=time.time())
    return k


def _sd_amostrador():
    """Anota a cada 15 s se o estado da ponte mudou (para dizer "há quanto tempo") e renova a lista de processos."""
    while True:
        try:
            _sd_ponte_chave()
            if time.time() - _sd_proc["t"] > 30:
                _sd_proc_atualizar()
        except Exception as ex:
            registrar("amostrador_erro", repetir=600, erro=_sd_erro_txt(ex))
        time.sleep(15)


# ---------- leitura de logs e erros recentes (sem texto de mensagem, números mascarados) ----------
_SD_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_SD_NUMEROS = re.compile(r"\d{6,}")
# lista fechada: o log da ponte também ecoa o texto das mensagens, então só linhas com a "cara" de erro do programa entram
_SD_ERR_PONTE = re.compile(r"\[\w+ ERROR\]|^\[stability\]|^(Failed to |REST API server error|Warning: could not|Client is not logged in|Message sent false)")
_SD_ERR_TRANSC = re.compile(r"^\S+ \S+ \S+ .*(falhou|Traceback)|^\S+ \S+ (Traceback|\w*Error|\w*Exception)")
_SD_ERR_NOTIF = re.compile(r"^\S+ \S+ (erro |falha |sqlite:|Traceback)")
_SD_ERR_PAINEL = re.compile(r" (thread_erro|thread_erro_local|erro_periodico|backup_erro|partida_falhou|amostrador_erro)\b")


def _sd_cauda(path, nbytes=262144):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            n = f.tell()
            f.seek(max(0, n - nbytes))
            return f.read().decode("utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _sd_limpar_linha(s, n=150):
    s = _SD_ANSI.sub("", s)
    s = _SD_NUMEROS.sub(lambda m: "…" + m.group(0)[-4:], s)
    s = "".join(c if c.isprintable() else " " for c in s).strip()
    return s if len(s) <= n else s[:n] + "…"


def _sd_quando(linha):
    m = re.match(r"(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d:\d\d)", linha)
    if m:
        return m.group(1) + " " + m.group(2)
    m = re.match(r"(\d\d:\d\d:\d\d)", linha)  # log da ponte só traz a hora: assume hoje (ou ontem, se a hora ainda não chegou)
    if m:
        d = _sd_dt.now()
        if m.group(1) > d.strftime("%H:%M:%S"):
            d = _sd_dt.fromtimestamp(d.timestamp() - 86400)
        return d.strftime("%Y-%m-%d") + " " + m.group(1)
    return ""


def _sd_erros_recentes(maximo=12):
    fontes = (("Ponte", os.path.join(BASE, "ponte_log.txt"), _SD_ERR_PONTE),
              ("Transcritor", os.path.join(BASE, "transcritor_log.txt"), _SD_ERR_TRANSC),
              ("Notificador", os.path.join(BASE, "notificador_log.txt"), _SD_ERR_NOTIF),
              ("Painel", LOG_PAINEL, _SD_ERR_PAINEL))
    achados = []
    for nome_, path, rx in fontes:
        for i, ln in enumerate(_sd_cauda(path)):
            ln = _SD_ANSI.sub("", ln)
            if not rx.search(ln) or " AVISO " in ln or " carga " in ln:
                continue
            achados.append({"fonte": nome_, "quando": _sd_quando(ln), "texto": _sd_limpar_linha(ln), "ordem": i})
    junto = {}  # junta repetidas (mesmo texto) e fica com as mais novas
    for a in achados:
        chave = (a["fonte"], re.sub(r"\S*\d\S*", "#", re.sub(r"^\S+ \S+ ", "", a["texto"])))  # ids e horas diferentes = mesmo erro
        if chave in junto:
            junto[chave]["n"] += 1
            junto[chave]["quando"] = a["quando"] or junto[chave]["quando"]
        else:
            junto[chave] = {**a, "n": 1}
    lista = sorted(junto.values(), key=lambda a: (a["quando"], a["ordem"]), reverse=True)[:maximo]
    for a in lista:
        a.pop("ordem", None)
    return lista


# ---------- seções da tela ----------
def _sd_memoria():
    """(memória do painel em MB, pico em MB, memória livre do PC em MB, total em MB) - Windows; None onde não der."""
    try:
        class _PMC(_sd_ct.Structure):
            _fields_ = [("cb", _sd_ct.c_ulong), ("PageFaultCount", _sd_ct.c_ulong), ("PeakWorkingSetSize", _sd_ct.c_size_t),
                        ("WorkingSetSize", _sd_ct.c_size_t), ("QuotaPeakPagedPoolUsage", _sd_ct.c_size_t),
                        ("QuotaPagedPoolUsage", _sd_ct.c_size_t), ("QuotaPeakNonPagedPoolUsage", _sd_ct.c_size_t),
                        ("QuotaNonPagedPoolUsage", _sd_ct.c_size_t), ("PagefileUsage", _sd_ct.c_size_t),
                        ("PeakPagefileUsage", _sd_ct.c_size_t)]

        class _MEM(_sd_ct.Structure):
            _fields_ = [("dwLength", _sd_ct.c_ulong), ("dwMemoryLoad", _sd_ct.c_ulong), ("ullTotalPhys", _sd_ct.c_ulonglong),
                        ("ullAvailPhys", _sd_ct.c_ulonglong), ("ullTotalPageFile", _sd_ct.c_ulonglong),
                        ("ullAvailPageFile", _sd_ct.c_ulonglong), ("ullTotalVirtual", _sd_ct.c_ulonglong),
                        ("ullAvailVirtual", _sd_ct.c_ulonglong), ("ullAvailExtendedVirtual", _sd_ct.c_ulonglong)]
        pmc = _PMC()
        pmc.cb = _sd_ct.sizeof(_PMC)
        k32 = _sd_ct.windll.kernel32
        k32.GetCurrentProcess.restype = _sd_ct.c_void_p
        psapi = _sd_ct.windll.psapi
        psapi.GetProcessMemoryInfo.argtypes = [_sd_ct.c_void_p, _sd_ct.c_void_p, _sd_ct.c_ulong]
        ok = psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(), _sd_ct.byref(pmc), pmc.cb)
        mem = _MEM()
        mem.dwLength = _sd_ct.sizeof(_MEM)
        tem = k32.GlobalMemoryStatusEx(_sd_ct.byref(mem))
        livre = round(mem.ullAvailPhys / 1048576) if tem else None
        total = round(mem.ullTotalPhys / 1048576) if tem else None
        if not ok:
            return None, None, livre, total
        return round(pmc.WorkingSetSize / 1048576, 1), round(pmc.PeakWorkingSetSize / 1048576, 1), livre, total
    except Exception:
        return None, None, None, None


def _sd_secao_ponte():
    s = dict(saude)
    k = _sd_ponte_chave()
    pr = _sd_proc["v"].get("ponte") or {}
    ultima = 0.0
    try:
        db = ro(MSG_DB)
        r = db.execute("select max(timestamp) from messages").fetchone()
        db.close()
        ultima = _sd_dt.fromisoformat(str((r[0] if r else "") or "").replace("Z", "+00:00")).timestamp()
    except Exception:
        ultima = 0.0
    nomes = {"conectado": "Conectado", "desconectado": "Desconectado do celular", "fora": "Fora do ar", "qr": "Aguardando QR Code"}
    return {"chave": k, "estado": nomes.get(k, k), "nivel": "ok" if k == "conectado" else "erro" if k in ("fora", "qr") else "atencao",
            "no_estado_desde": _sd_ponte_est["desde"], "religou_em": s.get("religou_em", ""), "falhas": s.get("falhas", 0),
            "verificado": s.get("verificado", ""),
            "processo_vivo": bool(pr.get("vivo")) if _sd_proc["ok"] else None,
            "uptime_s": round(time.time() - pr["desde"]) if pr.get("vivo") and pr.get("desde") else None,
            "ultima_mensagem": ultima or None}


def _sd_secao_painel():
    mem, pico, livre, total = _sd_memoria()
    return {"pid": os.getpid(), "uptime_s": round(time.time() - _SD_T0), "memoria_mb": mem, "memoria_pico_mb": pico,
            "pc_livre_mb": livre, "pc_total_mb": total, "threads": threading.active_count(), "porta": PORT,
            "https": bool(HTTPS_ATIVO), "python": ".".join(map(str, __import__("sys").version_info[:3])),
            "nivel": "atencao" if (mem or 0) > 800 else "ok"}


def _sd_desde_transcritor():
    try:
        with open(os.path.join(BASE, "transcritor_servico.py"), encoding="utf-8") as f:
            m = re.search(r'^DESDE\s*=\s*"([^"]+)"', f.read(), re.M)
        return m.group(1) if m else "2026-11-19 00:00"
    except OSError:
        return "2026-11-19 00:00"


def _sd_secao_transcritor():
    pr = _sd_proc["v"].get("transcritor") or {}
    out = {"processo_vivo": bool(pr.get("vivo")) if _sd_proc["ok"] else None,
           "uptime_s": round(time.time() - pr["desde"]) if pr.get("vivo") and pr.get("desde") else None,
           "fila": None, "a_refinar": None, "falhas": None, "ultimo": "", "media_previa_s": None, "media_refino_s": None}
    feitos = {}
    if os.path.exists(TRANS_DB):
        try:
            t = ro(TRANS_DB)
            for mid, cj, mod in t.execute("select id, chat_jid, modelo from transcricoes"):
                feitos[(mid, cj)] = mod
            t.close()
        except sqlite3.Error:
            feitos = None
    if feitos is not None:
        try:
            db = ro(MSG_DB)
            audios = db.execute("select id, chat_jid from messages where media_type='audio' and timestamp > ?",
                                (_sd_desde_transcritor(),)).fetchall()
            db.close()
            out["fila"] = sum(1 for a in audios if (a[0], a[1]) not in feitos)
            out["a_refinar"] = sum(1 for v in feitos.values() if v == "base")
            out["falhas"] = sum(1 for v in feitos.values() if v in ("falha", "base-final"))
        except sqlite3.Error:
            pass
    previa, refino = [], []
    for ln in _sd_cauda(os.path.join(BASE, "transcritor_log.txt"), 65536)[-300:]:
        m = re.search(r"(prévia|refinado) em (\d+)s", ln)
        if m:
            (previa if m.group(1) == "prévia" else refino).append(int(m.group(2)))
            out["ultimo"] = _sd_quando(ln) or out["ultimo"]
    if previa:
        out["media_previa_s"] = round(sum(previa[-20:]) / len(previa[-20:]), 1)
    if refino:
        out["media_refino_s"] = round(sum(refino[-20:]) / len(refino[-20:]), 1)
    out["nivel"] = "erro" if out["processo_vivo"] is False else "atencao" if (out["fila"] or 0) > 20 else "ok"
    return out


def _sd_secao_notificador():
    pr = _sd_proc["v"].get("notificador") or {}
    est = _sd_json_ler(os.path.join(BASE, "notificador_estado.json"), {})
    bat = est.get("batimento") or ""
    idade = None
    try:
        idade = round(time.time() - _sd_dt.fromisoformat(bat).timestamp())
    except (ValueError, TypeError):
        pass
    vivo = bool(pr.get("vivo")) if _sd_proc["ok"] else None
    nivel = "erro" if vivo is False or (idade is not None and idade > 120) else "ok"
    return {"processo_vivo": vivo, "ultimo_ciclo": bat, "idade_s": idade, "nivel": nivel,
            "uptime_s": round(time.time() - pr["desde"]) if pr.get("vivo") and pr.get("desde") else None}


_sd_dir_cache = {}


def _sd_tamanho_dir(path, ttl=600, so_midia=False):
    """(bytes, arquivos) de uma pasta, com cache (pasta com milhares de arquivos não é lida a cada 10 s)."""
    c = _sd_dir_cache.get((path, so_midia))
    if c and time.time() - c[0] < ttl:
        return c[1]
    total = n = 0
    for d, dirs, arqs in os.walk(path):
        if so_midia and os.path.normpath(d) == os.path.normpath(path):
            dirs[:] = [x for x in dirs if x != "avatars"]
        for a in arqs:
            if so_midia and a.lower().endswith((".db", ".db-wal", ".db-shm")):
                continue
            try:
                total += os.path.getsize(os.path.join(d, a))
                n += 1
            except OSError:
                pass
    _sd_dir_cache[(path, so_midia)] = (time.time(), (total, n))
    return total, n


def _sd_mb(n):
    return round((n or 0) / 1048576, 1)


def _sd_unidade(path):
    try:
        u = _sd_sh.disk_usage(path)
        return {"unidade": os.path.splitdrive(os.path.abspath(path))[0] or path, "livre_gb": round(u.free / 1073741824, 1),
                "total_gb": round(u.total / 1073741824, 1), "livre_pct": round(100 * u.free / u.total)}
    except OSError:
        return None


def _sd_tam(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _sd_secao_disco():
    cfg = backup_cfg()
    pasta_bk = os.path.join(AQUI, "backups")
    midia, n_midia = _sd_tamanho_dir(STORE, so_midia=True) if os.path.isdir(STORE) else (0, 0)
    raiz = os.path.join(cfg["destino"], _SD_PASTA_DESTINO) if cfg["destino"] else ""
    bk_dest = _sd_tamanho_dir(raiz)[0] if raiz and os.path.isdir(raiz) else 0
    un = [x for x in (_sd_unidade(AQUI), _sd_unidade(cfg["destino"]) if cfg["destino"] and os.path.isdir(cfg["destino"]) else None) if x]
    vistos, unidades = set(), []
    for x in un:
        if x["unidade"] not in vistos:
            vistos.add(x["unidade"])
            unidades.append(x)
    menor = min([u["livre_gb"] for u in unidades] or [999])
    return {"messages_db_mb": _sd_mb(_sd_tam(MSG_DB)), "messages_wal_mb": _sd_mb(_sd_tam(MSG_DB + "-wal")),
            "sessao_db_mb": _sd_mb(_sd_tam(WA_DB)), "transcricoes_db_mb": _sd_mb(_sd_tam(TRANS_DB)),
            "midia_mb": _sd_mb(midia), "midia_arquivos": n_midia, "backups_local_mb": _sd_mb(_sd_tamanho_dir(pasta_bk, ttl=120)[0]),
            "backups_destino_mb": _sd_mb(bk_dest), "unidades": unidades,
            "nivel": "erro" if menor < 2 else "atencao" if menor < 10 else "ok"}


# ---------- backup: configuração, destino, cópia consistente, rotação, teste de restauração ----------
def backup_cfg():
    c = _sd_json_ler(_SD_BKCFG, {})
    return {"destino": str(c.get("destino") or ""), "midia": bool(c.get("midia")), "sessao": bool(c.get("sessao"))}


def _sd_destino_valido(p):
    p = str(p or "").strip().strip('"')
    if not p:
        return ""
    if len(p) > 240 or not re.match(r"^[A-Za-z]:[\\/]", p):
        raise ErroEnvio("Use uma pasta deste computador com letra de unidade (por exemplo D:\\Backups). Pasta de rede não é aceita.")
    p = os.path.normpath(p)
    real = os.path.normcase(os.path.realpath(p))
    for proibido in (AQUI, STORE, BASE):
        pr = os.path.normcase(os.path.realpath(proibido))
        if real == pr or real.startswith(pr + os.sep):
            raise ErroEnvio("Escolha uma pasta fora do painel, da ponte e da pasta do WhatsApp-Assistente.")
    if os.path.splitdrive(p)[1] in ("\\", "/", ""):
        raise ErroEnvio("Escolha uma pasta dentro da unidade, não a raiz dela.")
    if not os.path.isdir(p):
        if not os.path.isdir(os.path.dirname(p)):
            raise ErroEnvio("A pasta não existe e a pasta de cima também não. Crie a pasta no Explorador e tente de novo.")
        try:
            os.mkdir(p)
        except OSError as ex:
            raise ErroEnvio(f"Não consegui criar a pasta: {ex.strerror or ex}")
    try:
        teste = os.path.join(p, ".teste-escrita-painel")
        with open(teste, "w") as f:
            f.write("ok")
        os.remove(teste)
    except OSError:
        raise ErroEnvio("Não consigo gravar nessa pasta (sem permissão ou unidade desconectada).")
    return p


def backup_salvar(dados):
    cfg = backup_cfg()
    if "destino" in dados:
        cfg["destino"] = _sd_destino_valido(dados.get("destino"))
    if "midia" in dados:
        cfg["midia"] = bool(dados.get("midia"))
    if "sessao" in dados:
        cfg["sessao"] = bool(dados.get("sessao"))
    _sd_json_gravar(_SD_BKCFG, cfg)
    registrar("backup_config", destino="sim" if cfg["destino"] else "nenhum", midia=int(cfg["midia"]), sessao=int(cfg["sessao"]))
    _sd_cache.update(t=0.0)
    return {"success": True, "config": cfg}


def _sd_sugestoes_destino():
    """Letras de unidade (menos a do painel) e a pasta do OneDrive, se existirem. Só lista; nada é enviado a lugar nenhum."""
    sug, vistos = [], set()
    sistema = os.path.splitdrive(os.path.abspath(AQUI))[0].upper()
    try:
        mascara = _sd_ct.windll.kernel32.GetLogicalDrives()
    except Exception:
        mascara = 0
    tipos = {2: "pendrive/disco removível", 3: "disco interno"}
    for i in range(26):
        if not mascara & (1 << i):
            continue
        letra = chr(65 + i) + ":"
        if letra.upper() == sistema:
            continue
        try:
            t = _sd_ct.windll.kernel32.GetDriveTypeW(letra + "\\")
        except Exception:
            continue
        if t not in tipos:
            continue
        u = _sd_unidade(letra + "\\")
        if u:
            sug.append({"caminho": letra + "\\Backups", "rotulo": f"Unidade {letra} ({tipos[t]})", "tipo": "disco", "livre_gb": u["livre_gb"]})
    for var in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        p = os.environ.get(var)
        if p and os.path.isdir(p) and p.lower() not in vistos:
            vistos.add(p.lower())
            u = _sd_unidade(p)
            sug.append({"caminho": os.path.join(p, "Backups"), "rotulo": "Pasta do OneDrive (sincroniza com a nuvem)",
                        "tipo": "nuvem", "livre_gb": u["livre_gb"] if u else None})
    home = os.path.expanduser("~")
    try:
        for n in os.listdir(home):
            p = os.path.join(home, n)
            if n.lower().startswith("onedrive") and os.path.isdir(p) and p.lower() not in vistos:
                vistos.add(p.lower())
                sug.append({"caminho": os.path.join(p, "Backups"), "rotulo": "Pasta do OneDrive (sincroniza com a nuvem)", "tipo": "nuvem", "livre_gb": None})
    except OSError:
        pass
    return sug


def _sd_sqlite_copiar(origem, destino):
    """Cópia consistente (API de backup do SQLite) de um banco em uso. Abre a origem só para leitura."""
    src = sqlite3.connect(_sd_Path(origem).as_uri() + "?mode=ro", uri=True, timeout=30)
    dst = sqlite3.connect(destino)
    try:
        src.backup(dst, pages=1024, sleep=0.005)
        dst.execute("PRAGMA journal_mode=DELETE")
    finally:
        dst.close()
        src.close()


def _sd_integridade(path):
    """(ok, detalhe) do PRAGMA integrity_check numa CÓPIA (aberta imutável, sem criar arquivos ao lado)."""
    try:
        c = sqlite3.connect(_sd_Path(path).as_uri() + "?mode=ro&immutable=1", uri=True, timeout=30)
        try:
            linhas = [r[0] for r in c.execute("PRAGMA integrity_check")]
            tabelas = c.execute("select count(*) from sqlite_master where type='table'").fetchone()[0]
        finally:
            c.close()
        if linhas == ["ok"]:
            return True, f"integridade ok, {tabelas} tabelas"
        return False, "integrity_check: " + "; ".join(linhas[:3])
    except sqlite3.Error as ex:
        return False, "não abriu: " + str(ex)[:120]


def _sd_sha256(path):
    h = _sd_hl.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _sd_espelhar_midia(raiz_destino):
    """Copia só o que é novo ou mudou (mtime/tamanho) de STORE para <destino>\\midia. Nunca apaga nada no destino."""
    dest_raiz = os.path.join(raiz_destino, "midia")
    copiados = pulados = erros = bytes_ = 0
    for d, dirs, arqs in os.walk(STORE):
        rel = os.path.relpath(d, STORE)
        if rel == ".":
            dirs[:] = [x for x in dirs if x != "avatars"]
        for a in arqs:
            if rel == "." and a.lower().endswith((".db", ".db-wal", ".db-shm", ".png")):
                continue
            src = os.path.join(d, a)
            dst = os.path.join(dest_raiz, a) if rel == "." else os.path.join(dest_raiz, rel, a)
            try:
                s = os.stat(src)
                if os.path.exists(dst):
                    t = os.stat(dst)
                    if t.st_size == s.st_size and t.st_mtime >= s.st_mtime - 2:
                        pulados += 1
                        continue
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                _sd_sh.copy2(src, dst)
                copiados += 1
                bytes_ += s.st_size
            except OSError:
                erros += 1
    return {"copiados": copiados, "ja_existiam": pulados, "erros": erros, "mb": _sd_mb(bytes_)}


def _sd_rotacionar(raiz):
    for sub, manter, rx in (("diario", _SD_DIARIOS, r"^\d{4}-\d{2}-\d{2}$"), ("semanal", _SD_SEMANAIS, r"^\d{4}-W\d{2}$")):
        base = os.path.join(raiz, sub)
        if not os.path.isdir(base):
            continue
        nomes = sorted(n for n in os.listdir(base) if re.match(rx, n) and os.path.isdir(os.path.join(base, n)))
        for n in nomes[:-manter]:
            _sd_sh.rmtree(os.path.join(base, n), ignore_errors=True)
        for n in os.listdir(base):  # sobras de cópia interrompida
            if n.endswith(".parcial"):
                _sd_sh.rmtree(os.path.join(base, n), ignore_errors=True)


def _sd_backup_extra(pasta, dia, forcar=False):
    """Cópia diária para o segundo local: messages.db (API de backup do SQLite), whatsapp.db (SENSÍVEL, só se marcado),
    cópia do zip completo e, se marcado, mídia incremental. 7 diárias + 4 semanais. Sem destino configurado não faz nada."""
    cfg = backup_cfg()
    if not cfg["destino"]:
        return None
    est = _sd_json_ler(_SD_BKEST, {})
    ex = est.get("extra") or {}
    if not forcar and ex.get("dia") == dia and ex.get("ok") and ex.get("destino") == cfg["destino"] \
            and ex.get("midia") == cfg["midia"] and ex.get("sessao") == cfg["sessao"]:
        return ex
    if not _sd_bk_run.acquire(blocking=False):
        return None
    t0 = time.time()
    res = {"dia": dia, "em": _sd_agora_iso(), "ok": False, "destino": cfg["destino"], "midia": cfg["midia"], "sessao": cfg["sessao"],
           "itens": [], "erro": ""}
    try:
        if not os.path.isdir(cfg["destino"]):
            raise OSError("a pasta do segundo local não está acessível (pendrive desconectado?)")
        raiz = os.path.join(cfg["destino"], _SD_PASTA_DESTINO)
        diario = os.path.join(raiz, "diario", dia)
        tmp = diario + ".parcial"
        _sd_sh.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp)
        precisa = _sd_tam(MSG_DB) * 2 + (_sd_tam(WA_DB) * 2 if cfg["sessao"] else 0) + 50 * 1048576
        livre = _sd_sh.disk_usage(cfg["destino"]).free
        if livre < precisa:
            raise OSError(f"pouco espaço no segundo local ({_sd_mb(livre)} MB livres, preciso de ~{_sd_mb(precisa)} MB)")
        manifest = {"versao": 1, "dia": dia, "criado_em": _sd_agora_iso(), "itens": []}

        def guardar(nome_arq, origem, copiar, sensivel=False):
            dst = os.path.join(tmp, nome_arq)
            copiar(origem, dst)
            ok_, det = _sd_integridade(dst) if nome_arq.endswith(".db") else (True, "copiado")
            manifest["itens"].append({"arquivo": nome_arq, "bytes": os.path.getsize(dst), "sha256": _sd_sha256(dst), "sensivel": sensivel})
            res["itens"].append({"nome": nome_arq, "ok": ok_, "detalhe": det, "mb": _sd_mb(os.path.getsize(dst)), "sensivel": sensivel})
        if os.path.exists(MSG_DB):
            guardar("messages.db", MSG_DB, _sd_sqlite_copiar)
        if cfg["sessao"] and os.path.exists(WA_DB):
            guardar("SENSIVEL-whatsapp-sessao.db", WA_DB, _sd_sqlite_copiar, sensivel=True)
            with open(os.path.join(tmp, "LEIA-ME-SENSIVEL.txt"), "w", encoding="utf-8") as f:
                f.write("ATENCAO: SENSIVEL-whatsapp-sessao.db tem as chaves da sessao do WhatsApp.\n"
                        "Quem tiver esse arquivo pode usar a sessao. Nao compartilhe, nao envie por e-mail e guarde so em local privado.\n")
        zip_dia = os.path.join(pasta, f"completo-{dia}.zip")
        if os.path.exists(zip_dia):
            guardar(f"completo-{dia}.zip", zip_dia, _sd_sh.copy2)
        with open(os.path.join(tmp, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=1)
        if os.path.isdir(diario):
            _sd_sh.rmtree(diario)
        os.replace(tmp, diario)
        iso = _sd_dt.strptime(dia, "%Y-%m-%d").isocalendar()
        sem = os.path.join(raiz, "semanal", f"{iso[0]}-W{iso[1]:02d}")
        if not os.path.isdir(sem):  # a primeira cópia de cada semana vira a "semanal"
            os.makedirs(os.path.dirname(sem), exist_ok=True)
            _sd_sh.rmtree(sem + ".parcial", ignore_errors=True)
            _sd_sh.copytree(diario, sem + ".parcial")
            os.replace(sem + ".parcial", sem)
        _sd_rotacionar(raiz)
        if cfg["midia"] and os.path.isdir(STORE):
            if _sd_sh.disk_usage(cfg["destino"]).free < 1536 * 1048576:
                res["midia_resultado"] = {"erro": "pouco espaço no destino; mídia não copiada"}
            else:
                res["midia_resultado"] = _sd_espelhar_midia(raiz)
        res["ok"] = bool(res["itens"]) and all(i["ok"] for i in res["itens"])
        if not res["itens"]:
            res["erro"] = "nada para copiar"
    except Exception as ex:
        res["erro"] = _sd_erro_txt(ex)
        registrar("backup_erro", repetir=3600, classe="extra", etapa="extra", erro=_sd_erro_txt(ex))
    finally:
        res["duracao_s"] = round(time.time() - t0, 1)
        est = _sd_json_ler(_SD_BKEST, {})
        est["extra"] = res
        try:
            _sd_json_gravar(_SD_BKEST, est)
        except OSError:
            pass
        _sd_bk_run.release()
    if res["ok"]:
        registrar("backup_extra_ok", dia=dia, itens=len(res["itens"]), segundos=res["duracao_s"])
    return res


def _sd_zip_extrair_seguro(z, dest):
    base = os.path.realpath(dest)
    total = 0
    for info in z.infolist():
        alvo = os.path.realpath(os.path.join(dest, info.filename))
        if alvo != base and not alvo.startswith(base + os.sep):
            raise ValueError("caminho suspeito dentro do zip: " + info.filename[:60])
        total += info.file_size
    if total > 4 * 1024 ** 3:
        raise ValueError("zip grande demais para testar")
    z.extractall(dest)


def _sd_verificar_pasta(pasta, itens, prefixo):
    """Confere o que foi restaurado numa pasta temporária: JSON válido e SQLite com integrity_check ok."""
    n_json = n_db = 0
    for d, _, arqs in os.walk(pasta):
        for a in arqs:
            f = os.path.join(d, a)
            rel = os.path.relpath(f, pasta).replace(os.sep, "/")
            if a.lower().endswith(".json"):
                n_json += 1
                try:
                    with open(f, encoding="utf-8") as fh:
                        json.load(fh)
                except (OSError, ValueError) as ex:
                    itens.append({"nome": f"{prefixo}: {rel}", "ok": False, "detalhe": "JSON inválido: " + str(ex)[:80]})
            elif a.lower().endswith(".db"):
                n_db += 1
                ok_, det = _sd_integridade(f)
                itens.append({"nome": f"{prefixo}: {rel}", "ok": ok_, "detalhe": det})
    return n_json, n_db


def _sd_testar_zip(zip_path, destino_tmp, itens, rotulo):
    nome_zip = os.path.basename(zip_path)
    try:
        with _sd_zip.ZipFile(zip_path) as z:
            ruim = z.testzip()
            if ruim:
                itens.append({"nome": f"{rotulo}: zip {nome_zip}", "ok": False, "detalhe": "arquivo corrompido dentro do zip: " + ruim[:60]})
                return
            nomes = z.namelist()
            os.makedirs(destino_tmp, exist_ok=True)
            _sd_zip_extrair_seguro(z, destino_tmp)
    except (OSError, _sd_zip.BadZipFile, ValueError) as ex:
        itens.append({"nome": f"{rotulo}: zip {nome_zip}", "ok": False, "detalhe": str(ex)[:120]})
        return
    itens.append({"nome": f"{rotulo}: zip {nome_zip}", "ok": True,
                  "detalhe": f"zip íntegro, {len(nomes)} arquivos, {_sd_mb(os.path.getsize(zip_path))} MB"})
    if "painel/painel_estado.json" not in nomes:
        itens.append({"nome": f"{rotulo}: painel_estado.json", "ok": None, "detalhe": "não está no zip"})
    n_json, n_db = _sd_verificar_pasta(destino_tmp, itens, rotulo)
    itens.append({"nome": f"{rotulo}: restaurado em pasta temporária", "ok": True, "detalhe": f"{n_json} JSON válidos, {n_db} bancos conferidos"})


def _sd_testar_dir(diario, destino_tmp, itens):
    rot = "Segundo local"
    try:
        with open(os.path.join(diario, "manifest.json"), encoding="utf-8") as f:
            man = json.load(f)
    except (OSError, ValueError) as ex:
        itens.append({"nome": f"{rot}: manifest.json", "ok": False, "detalhe": "ausente ou inválido: " + str(ex)[:80]})
        return
    os.makedirs(destino_tmp, exist_ok=True)
    for it in man.get("itens") or []:
        nome_arq = os.path.basename(str(it.get("arquivo") or ""))
        src = os.path.join(diario, nome_arq)
        rotulo = f"{rot}: {nome_arq}" + (" (SENSÍVEL)" if it.get("sensivel") else "")
        if not os.path.isfile(src):
            itens.append({"nome": rotulo, "ok": False, "detalhe": "arquivo listado no manifesto não existe"})
            continue
        dst = os.path.join(destino_tmp, nome_arq)
        _sd_sh.copy2(src, dst)  # "restaura" para a pasta temporária
        if os.path.getsize(dst) != it.get("bytes") or _sd_sha256(dst) != it.get("sha256"):
            itens.append({"nome": rotulo, "ok": False, "detalhe": "tamanho ou SHA-256 diferente do manifesto (arquivo alterado ou corrompido)"})
            continue
        if nome_arq.endswith(".db"):
            ok_, det = _sd_integridade(dst)
            itens.append({"nome": rotulo, "ok": ok_, "detalhe": "SHA-256 confere; " + det})
        elif nome_arq.endswith(".zip"):
            _sd_testar_zip(dst, os.path.join(destino_tmp, "zip-" + nome_arq), itens, rot)
        else:
            itens.append({"nome": rotulo, "ok": True, "detalhe": "SHA-256 confere"})


def backup_testar(origem="manual"):
    """Restaura o backup mais recente numa pasta temporária (apagada no fim) e confere: integridade do zip, SHA-256,
    PRAGMA integrity_check dos bancos e validade dos JSON. Também confere se o banco ao vivo é copiável (cópia temporária)."""
    if not _sd_teste_lock.acquire(blocking=False):
        raise ErroEnvio("Já existe um teste de restauração rodando.", 409)
    t0 = time.time()
    itens = []
    tmp = _sd_tmp.mkdtemp(prefix="painel-teste-restauro-")
    try:
        pasta = os.path.join(AQUI, "backups")
        zips = sorted(n for n in (os.listdir(pasta) if os.path.isdir(pasta) else []) if re.match(r"^completo-\d{4}-\d{2}-\d{2}\.zip$", n))
        if zips:
            _sd_testar_zip(os.path.join(pasta, zips[-1]), os.path.join(tmp, "local"), itens, "Backup local")
        else:
            itens.append({"nome": "Backup local", "ok": False, "detalhe": "nenhum backup completo encontrado em backups\\"})
        cfg = backup_cfg()
        if cfg["destino"]:
            base = os.path.join(cfg["destino"], _SD_PASTA_DESTINO, "diario")
            dias = sorted(n for n in (os.listdir(base) if os.path.isdir(base) else []) if re.match(r"^\d{4}-\d{2}-\d{2}$", n))
            if dias:
                _sd_testar_dir(os.path.join(base, dias[-1]), os.path.join(tmp, "destino"), itens)
            else:
                itens.append({"nome": "Segundo local", "ok": False, "detalhe": "configurado, mas ainda sem nenhuma cópia diária"})
        else:
            itens.append({"nome": "Segundo local", "ok": None, "detalhe": "não configurado: mensagens e sessão do WhatsApp não têm cópia fora da pasta do painel"})
        if os.path.exists(MSG_DB):
            vivo = os.path.join(tmp, "ao-vivo-messages.db")
            try:
                t1 = time.time()
                _sd_sqlite_copiar(MSG_DB, vivo)
                ok_, det = _sd_integridade(vivo)
                itens.append({"nome": "Banco de mensagens ao vivo (cópia temporária)", "ok": ok_, "detalhe": f"{det}; copiado em {time.time() - t1:.1f}s"})
            except Exception as ex:
                itens.append({"nome": "Banco de mensagens ao vivo (cópia temporária)", "ok": False, "detalhe": _sd_erro_txt(ex)})
    except Exception as ex:
        itens.append({"nome": "Teste", "ok": False, "detalhe": _sd_erro_txt(ex)})
    finally:
        _sd_sh.rmtree(tmp, ignore_errors=True)
        _sd_teste_ultimo[0] = time.time()
        _sd_teste_lock.release()
    res = {"em": _sd_agora_iso(), "origem": origem, "duracao_s": round(time.time() - t0, 1), "itens": itens,
           "ok": not any(i["ok"] is False for i in itens), "completo": all(i["ok"] is True for i in itens),
           "pasta_temporaria_apagada": not os.path.exists(tmp)}
    est = _sd_json_ler(_SD_BKEST, {})
    est["teste"] = res
    try:
        _sd_json_gravar(_SD_BKEST, est)
    except OSError:
        pass
    registrar("backup_teste", origem=origem, ok=int(res["ok"]), segundos=res["duracao_s"])
    _sd_cache.update(t=0.0)
    return {"success": True, "teste": res}


def _sd_backup_agora():
    """Botão "Fazer backup agora": garante o zip do dia e faz a cópia para o segundo local."""
    try:
        pasta = os.path.join(AQUI, "backups")
        os.makedirs(pasta, exist_ok=True)
        dia = time.strftime("%Y-%m-%d")
        _sd_bc0(pasta, dia)
        _sd_backup_extra(pasta, dia, forcar=True)
    except Exception as ex:
        registrar("backup_erro", repetir=60, classe="agora", etapa="agora", erro=_sd_erro_txt(ex))
    _sd_cache.update(t=0.0)


# O laço _backup (a cada 1 h) chama _backup_completo(pasta, dia): estendido aqui, sem mexer no original.
_sd_bc0 = _backup_completo


def _backup_completo(pasta, dia):  # noqa: F811
    _sd_bc0(pasta, dia)
    if not os.path.exists(os.path.join(pasta, f"completo-{dia}.zip")):
        registrar("backup_erro", repetir=3600, classe="zip", etapa="zip_completo", dia=dia, erro="o zip do dia não foi criado")
    try:
        _sd_backup_extra(pasta, dia)
    except Exception as ex:
        registrar("backup_erro", repetir=3600, classe="extra2", etapa="extra", erro=_sd_erro_txt(ex))
    try:  # teste de restauração toda semana (e na primeira vez)
        t = (_sd_json_ler(_SD_BKEST, {}).get("teste") or {}).get("em")
        velho = True
        if t:
            velho = (_sd_dt.now() - _sd_dt.fromisoformat(t)).total_seconds() > 7 * 86400
        if velho and time.time() - _sd_teste_ultimo[0] > 3600:
            backup_testar("automatico")
    except Exception as ex:
        registrar("backup_erro", repetir=3600, classe="teste", etapa="teste_semanal", erro=_sd_erro_txt(ex))


def _sd_secao_backup():
    pasta = os.path.join(AQUI, "backups")
    zips = sorted(n for n in (os.listdir(pasta) if os.path.isdir(pasta) else []) if re.match(r"^completo-\d{4}-\d{2}-\d{2}\.zip$", n))
    ult = None
    if zips:
        f = os.path.join(pasta, zips[-1])
        ult = {"arquivo": zips[-1], "em": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(os.path.getmtime(f))),
               "mb": _sd_mb(os.path.getsize(f)), "idade_h": round((time.time() - os.path.getmtime(f)) / 3600, 1)}
    est = _sd_json_ler(_SD_BKEST, {})
    cfg = backup_cfg()
    teste = est.get("teste")
    dias_teste = None
    if teste and teste.get("em"):
        try:
            dias_teste = round((_sd_dt.now() - _sd_dt.fromisoformat(teste["em"])).total_seconds() / 86400, 1)
        except ValueError:
            pass
    extra = est.get("extra")
    destino_ok = bool(cfg["destino"]) and os.path.isdir(cfg["destino"])
    nivel = "ok"
    if not ult or ult["idade_h"] > 36:
        nivel = "erro"
    elif not cfg["destino"] or not destino_ok or (extra and not extra.get("ok")) or not teste or not teste.get("ok") \
            or (dias_teste is not None and dias_teste > 8):
        nivel = "atencao"
    return {"ultimo_completo": ult, "diarios_locais": len(zips),
            "config": {"destino": cfg["destino"], "destino_definido": bool(cfg["destino"]), "destino_ok": destino_ok,
                       "midia": cfg["midia"], "sessao": cfg["sessao"]},
            "extra": extra, "teste": teste, "dias_desde_teste": dias_teste, "sugestoes": _sd_sugestoes_destino(),
            "retencao": {"diarios": _SD_DIARIOS, "semanais": _SD_SEMANAIS}, "nivel": nivel}


def _sd_secao_campanhas():
    ce = _camp_ro()
    agora = _camp_agora()
    prox = ""
    for c in ce["lista"]:
        p = _camp_proximo(c, ce["execucoes"], ce["pausado_tudo"], agora)
        if p and (not prox or p < prox):
            prox = p
    corte = agora - _ctd(hours=24)
    erros, motivo = 0, ""
    for x in ce["execucoes"].values():
        if x.get("status") != "erro":
            continue
        d = _camp_dt(x.get("em")) or _camp_dt(x.get("quando"))
        if d and d >= corte:
            erros += 1
            motivo = motivo or str(x.get("motivo") or "")[:100]
    return {"ativas": sum(1 for c in ce["lista"] if c.get("ativo")), "total": len(ce["lista"]), "pausado_tudo": ce["pausado_tudo"],
            "fila": len(ce["fila"]), "proximo_envio": prox, "erros_24h": erros, "ultimo_motivo_erro": motivo,
            "ultimo_envio": ce["ultimo_envio"], "nivel": "atencao" if erros else "ok"}


def _sd_secao_threads():
    vivas = {t._target.__name__ for t in threading.enumerate() if getattr(t, "_target", None) is not None and hasattr(t._target, "__name__")}
    return [{"nome": n, "vivo": n in vivas, "inicios": i["inicios"], "erros": i["erros"], "ultimo_erro": i["ultimo_erro"],
             "ultimo_erro_em": i["ultimo_erro_em"]} for n, i in sorted(_sd_threads.items())]


_sd_cache = {"t": 0.0, "v": None}
_sd_cache_lock = threading.Lock()


def _sd_secao(nome_, fn):
    try:
        return fn()
    except Exception as ex:
        registrar("saude_secao_erro", repetir=600, classe=nome_, secao=nome_, erro=_sd_erro_txt(ex))
        return {"erro": _sd_erro_txt(ex), "nivel": "atencao"}


def _sd_montar():
    if time.time() - _sd_proc["t"] > 45:
        _sd_proc_atualizar()
    s = {"success": True, "gerado_em": _sd_agora_iso(), "ttl_s": 10,
         "ponte": _sd_secao("ponte", _sd_secao_ponte), "painel": _sd_secao("painel", _sd_secao_painel),
         "transcritor": _sd_secao("transcritor", _sd_secao_transcritor), "notificador": _sd_secao("notificador", _sd_secao_notificador),
         "disco": _sd_secao("disco", _sd_secao_disco), "backup": _sd_secao("backup", _sd_secao_backup),
         "campanhas": _sd_secao("campanhas", _sd_secao_campanhas),
         "sse": {"clientes": _sd_sse["n"], "pico": _sd_sse["pico"]}, "threads": _sd_secao("threads", _sd_secao_threads),
         "erros": _sd_secao("erros", _sd_erros_recentes), "processos_ok": _sd_proc["ok"]}
    rot = {"ponte": "WhatsApp (ponte)", "painel": "Painel", "transcritor": "Transcritor de áudios", "notificador": "Notificador",
           "disco": "Disco", "backup": "Backup", "campanhas": "Campanhas"}
    alertas = []
    for k, r in rot.items():
        n = s[k].get("nivel") if isinstance(s[k], dict) else ""
        if n in ("erro", "atencao"):
            alertas.append({"nivel": n, "secao": k, "texto": r})
    if isinstance(s["threads"], list) and any(not t["vivo"] for t in s["threads"]):
        alertas.append({"nivel": "erro", "secao": "threads", "texto": "Rotina interna do painel parada"})
    s["alertas"] = alertas
    s["geral"] = "erro" if any(a["nivel"] == "erro" for a in alertas) else "atencao" if alertas else "ok"
    return s


def saude_sistema(remoto=False, novo=False):
    """Cache de 10 s. Para quem está em outro aparelho, a pasta do backup e as sugestões de unidade não vão junto."""
    with _sd_cache_lock:
        if novo or _sd_cache["v"] is None or time.time() - _sd_cache["t"] > 10:
            _sd_cache.update(v=_sd_montar(), t=time.time())
        v = _sd_cache["v"]
    v = dict(v, remoto=bool(remoto))
    if remoto and isinstance(v.get("backup"), dict) and "config" in v["backup"]:
        v = json.loads(json.dumps(v))
        v["backup"]["config"]["destino"] = ""
        v["backup"]["sugestoes"] = []
        if isinstance(v["backup"].get("extra"), dict):
            v["backup"]["extra"]["destino"] = ""
    return v


# ---------- rotas ----------
_sd_get0 = Handler.do_GET
_sd_post0 = Handler.do_POST
_sd_stream0 = Handler.stream


def _sd_stream(self):
    with _sd_sse_lock:
        _sd_sse["n"] += 1
        _sd_sse["pico"] = max(_sd_sse["pico"], _sd_sse["n"])
    try:
        return _sd_stream0(self)
    finally:
        with _sd_sse_lock:
            _sd_sse["n"] = max(0, _sd_sse["n"] - 1)


def _sd_do_GET(self):
    u = urlparse(self.path)
    if u.path != "/api/saude-sistema":
        return _sd_get0(self)
    if not self.portaria(post=False):
        return
    try:
        q = parse_qs(u.query)
        return self.json(saude_sistema(remoto=bool(getattr(self, "remoto", False)), novo=q.get("novo", [""])[0] == "1"))
    except Exception as e:
        registrar("saude_erro", repetir=300, erro=_sd_erro_txt(e))
        self.json({"success": False, "erro": f"{type(e).__name__}: {e}"}, 500)


def _sd_do_POST(self):
    u = urlparse(self.path)
    if u.path != "/api/backup":
        return _sd_post0(self)
    if not self.portaria(post=True):
        return
    try:
        espera = ritmo_espera(self.client_address[0], u.path)
        tam = int(self.headers.get("Content-Length") or 0)
        if espera:
            if 0 <= tam <= 1024 * 1024:
                self.rfile.read(tam)
            else:
                self.close_connection = True
            return self.enviar(429, json.dumps({"success": False, "limite": True, "espera": espera,
                                                "erro": f"Muitas ações em pouco tempo. Tente de novo em {espera} s."}, ensure_ascii=False),
                               extra={"Retry-After": str(espera)})
        if tam > 16 * 1024:
            raise ErroEnvio("requisição grande demais", 413)
        dados = json.loads(self.rfile.read(tam) or b"{}")
        if not isinstance(dados, dict):
            raise ErroEnvio("requisição inválida")
        acao = dados.get("acao")
        if acao == "salvar":
            if getattr(self, "remoto", False):
                raise ErroEnvio("A pasta do backup só pode ser mudada no computador do painel.", 403)
            return self.json(backup_salvar(dados))
        if acao == "agora":
            if _sd_bk_run.locked():
                raise ErroEnvio("Já tem um backup rodando.", 409)
            threading.Thread(target=_sd_backup_agora, daemon=True).start()
            return self.json({"success": True, "iniciado": True})
        if acao == "testar":
            if time.time() - _sd_teste_ultimo[0] < 15:
                raise ErroEnvio("O último teste acabou de rodar. Espere alguns segundos.", 429)
            return self.json(backup_testar("manual"))
        raise ErroEnvio("ação desconhecida")
    except ErroEnvio as e:
        self.json({"success": False, "erro": str(e)}, e.code)
    except Exception as e:
        self.close_connection = True
        registrar("backup_erro", repetir=300, classe="rota", etapa="rota", erro=_sd_erro_txt(e))
        self.json({"success": False, "erro": f"{type(e).__name__}: {e}"}, 500)


Handler.stream = _sd_stream
Handler.do_GET = _sd_do_GET
Handler.do_POST = _sd_do_POST

if __name__ == "__main__" and os.environ.get("PAINEL_SEM_AMOSTRADOR") != "1":
    threading.Thread(target=_sd_robusto(_sd_amostrador, "_sd_amostrador"), daemon=True).start()
# ---------- fim [saude] ----------


# ---------- [pareamento] Reconectar / escanear QR / retomar sessão (proxy para a ponte) ----------
# GET  /api/pareamento            -> estado (cache 1 s). {suportado:false} se a ponte for a versão antiga (sem /api/pair/*)
# GET  /api/pareamento/qr.png     -> QR atual (no-store)
# POST /api/pareamento/iniciar    {forcar, confirmacao}  (forcar exige confirmacao == "DESVINCULAR")
# POST /api/pareamento/cancelar
# POST /api/ponte/retomar         (reconecta a sessão existente; se a ponte não responde, roda ponte_comando_reiniciar)
# config.json: "proxy_confiavel" (bool, padrão false) e "ponte_comando_reiniciar" (texto, opcional).
# SEGURANÇA: o painel decidia "local" só pelo IP da conexão TCP. Atrás de um proxy reverso no mesmo host (nginx -> 127.0.0.1)
# a conexão SEMPRE chega de 127.0.0.1 e o pedido parecia local, sem login. Este bloco embrulha Handler.portaria:
# qualquer cabeçalho de proxy (X-Forwarded-*, X-Real-IP, Forwarded) ou o Host público (PAINEL_PROXY) torna o pedido REMOTO (login).
import shlex as _pa_shlex, subprocess as _pa_subprocess
_pa_get0 = Handler.do_GET
_pa_post0 = Handler.do_POST
_pa_portaria0 = Handler.portaria
PA_CABECALHOS_PROXY = ("x-forwarded-for", "x-real-ip", "forwarded", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port")
PA_LIM_SESSAO = (6, 600)     # ações por sessão / 10 min
PA_LIM_GLOBAL = (20, 3600)   # ações no total / hora
_pa_lock = threading.Lock()
_pa_rl_sessao = {}
_pa_rl_global = []
_pa_cache = {"t": 0.0, "v": None}


def _pa_confiavel():
    return _cfg_painel().get("proxy_confiavel") is True


def _pa_ip_proxy(self):
    """IP do cliente informado pelo proxy: último salto do X-Forwarded-For, senão X-Real-IP. '' se inválido."""
    bruto = (self.headers.get("X-Forwarded-For") or "").split(",")[-1].strip() or (self.headers.get("X-Real-IP") or "").strip()
    try:
        ipaddress.ip_address(bruto)
        return bruto
    except ValueError:
        return ""


def _pa_estrito(self):
    """True se o pedido passou por proxy (cabeçalho de proxy ou Host público): nunca vale como 'local'."""
    if any(self.headers.get(h) for h in PA_CABECALHOS_PROXY):
        return True
    host = (self.headers.get("Host") or "").lower()
    return bool(PROXY) and host == PROXY


def _pa_portaria(self, post):
    if not _pa_portaria0(self, post):
        return False
    self._pa_via_proxy = _pa_estrito(self)
    if not self._pa_via_proxy or self.remoto:
        return True
    # parecia local (conexão de 127.0.0.1) mas veio por proxy: regras de acesso remoto
    if _pa_confiavel():
        real = _pa_ip_proxy(self)
        if real:
            self.client_address = (real, self.client_address[1])
    self.remoto = True
    caminho = urlparse(self.path).path
    if caminho in ("/login", "/api/login") or sessao_valida(self._token()):
        return True
    if post:
        self.close_connection = True
    registrar("sessao_vencida" if self._token() else "sem_login", self.client_address[0], repetir=600, rota=caminho, via="proxy-local")
    if not post and caminho in ("/", "/index.html"):
        self.enviar(302, "", "text/plain; charset=utf-8", {"Location": "/login"})
    else:
        self.json({"success": False, "erro": "faça login", "login": True}, 401)
    return False


Handler.portaria = _pa_portaria


def _pa_quem(self):
    tok = self._token()
    return ("s:" + _chave(tok)[:8]) if tok and sessao_valida(tok) else "local"


def _pa_autorizado(self):
    """Defesa em profundidade: pedido que passou por proxy, ou de fora, sem sessão válida não executa nada aqui."""
    if (getattr(self, "remoto", False) or getattr(self, "_pa_via_proxy", False)) and not sessao_valida(self._token()):
        self.json({"success": False, "erro": "faça login", "login": True}, 401)
        return False
    return True


def _pa_limite(quem, agora=None):
    """0 se pode seguir (e fica contado); senão, segundos de espera."""
    agora = agora or time.time()
    with _pa_lock:
        h = [t for t in _pa_rl_sessao.get(quem, []) if agora - t < PA_LIM_SESSAO[1]]
        _pa_rl_global[:] = [t for t in _pa_rl_global if agora - t < PA_LIM_GLOBAL[1]]
        if len(h) >= PA_LIM_SESSAO[0]:
            return max(1, int(PA_LIM_SESSAO[1] - (agora - h[0])) + 1)
        if len(_pa_rl_global) >= PA_LIM_GLOBAL[0]:
            return max(1, int(PA_LIM_GLOBAL[1] - (agora - _pa_rl_global[0])) + 1)
        h.append(agora)
        _pa_rl_sessao[quem] = h
        _pa_rl_global.append(agora)
        if len(_pa_rl_sessao) > 200:
            _pa_rl_sessao.clear()
        return 0


def _pa_ponte(metodo, rota, corpo=None, timeout=8):
    """(status, bytes, tipo). status 0 = ponte não respondeu."""
    dados = json.dumps(corpo).encode() if corpo is not None else (b"" if metodo == "POST" else None)
    req = urllib.request.Request(PONTE + rota, data=dados, method=metodo,
                                 headers={"Content-Type": "application/json"} if dados is not None else {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(2_000_000), r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(200_000), e.headers.get("Content-Type", "")
        except Exception:
            return e.code, b"", ""
    except Exception:
        return 0, b"", ""


def _pa_json(b):
    try:
        v = json.loads(b.decode("utf-8", "replace"))
        return v if isinstance(v, dict) else {}
    except Exception:
        return {}


def pareamento_status():
    agora = time.time()
    with _pa_lock:
        if _pa_cache["v"] is not None and agora - _pa_cache["t"] < 1.0:
            return _pa_cache["v"]
    st, b, _ = _pa_ponte("GET", "/api/pair/status", timeout=4)
    if st in (404, 405, 501):
        v = {"success": True, "suportado": False}
    elif st == 0:
        v = {"success": True, "suportado": None, "ponte_fora": True}
    elif st == 200:
        v = _pa_json(b)
        v.update(success=True, suportado=True)
    else:
        v = {"success": True, "suportado": None, "ponte_fora": True, "erro": f"a ponte respondeu {st}"}
    with _pa_lock:
        _pa_cache.update(t=agora, v=v)
    return v


def _pa_invalida():
    with _pa_lock:
        _pa_cache["v"] = None


def _pa_registrar(self, evento, **campos):
    registrar(evento, self.client_address[0], quem=_pa_quem(self), via="proxy" if getattr(self, "_pa_via_proxy", False) else "direto", **campos)


def _pa_corpo(self, maximo=4096):
    tam = int(self.headers.get("Content-Length") or 0)
    if tam > maximo:
        self.close_connection = True
        raise ErroEnvio("requisição grande demais", 413)
    d = json.loads(self.rfile.read(tam) or b"{}") if tam else {}
    if not isinstance(d, dict):
        raise ErroEnvio("requisição inválida")
    return d


def _pa_resposta(self, st, b, legado_msg=None):
    d = _pa_json(b)
    if st == 0:
        return self.json({"success": False, "erro": "A ponte do WhatsApp não está respondendo."}, 503)
    if st in (404, 405, 501):
        return self.json({"success": False, "legado": True, "erro": legado_msg or "Esta ponte é de uma versão antiga e não tem este recurso."}, 501)
    if st == 409:
        return self.json({"success": False, "conflito": True, "erro": str(d.get("erro") or "Ação indisponível no estado atual da ponte.")}, 409)
    if st == 429:
        return self.json({"success": False, "limite": True, "erro": "A ponte limitou as tentativas de QR. Espere alguns minutos."}, 429)
    if 200 <= st < 300:
        d["success"] = d.get("success") is not False
        return self.json(d)
    return self.json({"success": False, "erro": str(d.get("erro") or f"A ponte respondeu {st}.")}, 502)


def _pa_do_GET(self):
    u = urlparse(self.path)
    if u.path not in ("/api/pareamento", "/api/pareamento/qr.png"):
        return _pa_get0(self)
    if not self.portaria(post=False) or not _pa_autorizado(self):
        return
    try:
        if u.path == "/api/pareamento":
            return self.json(pareamento_status())
        st, b, _ = _pa_ponte("GET", "/api/pair/qr.png", timeout=5)
        if st == 200 and b[:4] == b"\x89PNG":
            return self.enviar(200, b, "image/png", {"Cache-Control": "no-store, max-age=0"})
        return self.enviar(404, "sem QR no momento", "text/plain; charset=utf-8", {"Cache-Control": "no-store"})
    except Exception as e:
        registrar("pareamento_erro", self.client_address[0], repetir=60, erro=f"{type(e).__name__}: {e}")
        self.json({"success": False, "erro": "Erro ao consultar a ponte."}, 500)


def _pa_do_POST(self):
    u = urlparse(self.path)
    if u.path not in ("/api/pareamento/iniciar", "/api/pareamento/cancelar", "/api/ponte/retomar"):
        return _pa_post0(self)
    if not self.portaria(post=True):
        return
    try:
        if not _pa_autorizado(self):
            self.close_connection = True
            return
        dados = _pa_corpo(self)
        acao = u.path.rsplit("/", 1)[-1]
        forcar = acao == "iniciar" and dados.get("forcar") is True
        if forcar and dados.get("confirmacao") != "DESVINCULAR":  # recusado antes de qualquer contagem ou chamada à ponte
            _pa_registrar(self, "pareamento_recusado", acao="iniciar", motivo="sem DESVINCULAR")
            raise ErroEnvio("Para desvincular o aparelho, digite DESVINCULAR para confirmar.", 400)
        if acao != "cancelar":  # cancelar só reduz risco: nunca fica preso no limite
            espera = _pa_limite(_pa_quem(self))
            if espera:
                _pa_registrar(self, "pareamento_limite", acao=acao, espera=espera)
                return self.enviar(429, json.dumps({"success": False, "limite": True, "espera": espera,
                                   "erro": f"Muitas tentativas de reconexão. Tente de novo em {espera} s."}, ensure_ascii=False),
                                   extra={"Retry-After": str(espera)})
        if acao == "iniciar":
            if forcar:
                _pa_registrar(self, "PAREAMENTO_FORCADO_DESVINCULA_APARELHO")
                print("[pareamento] !!! pareamento FORÇADO: o aparelho atual será desvinculado (ip=%s)" % self.client_address[0], flush=True)
            else:
                _pa_registrar(self, "pareamento_iniciar")
            st, b, _ = _pa_ponte("POST", "/api/pair/start", {"force": forcar}, timeout=15)
            _pa_invalida()
            if st == 409 and not forcar:
                return self.json({"success": False, "conflito": True, "logado": True,
                                  "erro": "O WhatsApp já está conectado neste número. Para entrar de novo é preciso desvincular o aparelho."}, 409)
            return _pa_resposta(self, st, b, legado_msg="Esta ponte é antiga e não gera QR por aqui.")
        if acao == "cancelar":
            _pa_registrar(self, "pareamento_cancelar")
            st, b, _ = _pa_ponte("POST", "/api/pair/cancel", {}, timeout=8)
            _pa_invalida()
            return _pa_resposta(self, st, b)
        # retomar
        _pa_registrar(self, "ponte_retomar")
        st, b, _ = _pa_ponte("POST", "/api/reconnect", {}, timeout=15)
        _pa_invalida()
        if st == 409:
            return self.json({"success": False, "conflito": True, "erro": "Há um pareamento (QR) em andamento. Cancele-o antes de reconectar."}, 409)
        if st == 0:
            cmd = _cfg_painel().get("ponte_comando_reiniciar")
            if isinstance(cmd, str) and cmd.strip():
                _pa_registrar(self, "ponte_retomar_comando")
                try:
                    r = _pa_subprocess.run(_pa_shlex.split(cmd), shell=False, timeout=20,  # Windows: use "/" nos caminhos
                                           capture_output=True, stdin=_pa_subprocess.DEVNULL)
                    ok = r.returncode == 0
                except Exception as e:
                    registrar("ponte_retomar_comando_erro", self.client_address[0], erro=type(e).__name__)
                    ok = False
                if ok:
                    return self.json({"success": True, "via": "comando", "message": "A ponte foi reiniciada."})
                return self.json({"success": False, "erro": "A ponte não respondeu e o comando de reinício falhou."}, 502)
        return _pa_resposta(self, st, b, legado_msg="Esta ponte é antiga e não tem o botão de reconectar.")
    except ErroEnvio as e:
        self.json({"success": False, "erro": str(e)}, e.code)
    except Exception as e:
        self.close_connection = True
        registrar("pareamento_erro", self.client_address[0], repetir=60, erro=f"{type(e).__name__}: {e}")
        self.json({"success": False, "erro": "Erro interno ao falar com a ponte."}, 500)


Handler.do_GET = _pa_do_GET
Handler.do_POST = _pa_do_POST
# ---------- fim [pareamento] ----------


# ---------- [historico-sync] progresso da sincronização de histórico (ponte: /api/history/sync-status) ----------
_hs_cache = {"t": 0.0, "v": None}
_hs_lock = threading.Lock()


def _hs_do_GET(self):
    u = urlparse(self.path)
    if u.path != "/api/historico-sync":
        return _hs_get0(self)
    if not self.portaria(post=False) or not _pa_autorizado(self):
        return
    with _hs_lock:
        if _hs_cache["v"] is None or time.time() - _hs_cache["t"] > 2:
            try:
                with urllib.request.urlopen(PONTE + "/api/history/sync-status", timeout=5) as r_:
                    _hs_cache["v"] = json.loads(r_.read().decode("utf-8"))
            except urllib.error.HTTPError as e_:
                _hs_cache["v"] = {"success": False, "suportado": e_.code != 404, "erro": "ponte respondeu %d" % e_.code}
            except Exception:
                _hs_cache["v"] = {"success": False, "suportado": True, "erro": "ponte indisponível"}
            _hs_cache["t"] = time.time()
        v_ = _hs_cache["v"]
    return self.json(v_)


_hs_get0 = Handler.do_GET
Handler.do_GET = _hs_do_GET
# ---------- fim [historico-sync] ----------

# ---------- [cadencias] sequências de mensagens agendadas por contato, com cancelamento automático quando a pessoa responde ----------
# GET  /api/cadencias[?id=]   -> lista (próximo toque, resumo, avisos não lidos)
# POST /api/cadencias {acao: previa|criar|cancelar|pausar|retomar|cancelar_passo|editar_passo|testar|apagar|dispensar_aviso}
# Estado em painel_estado.json["cadencias"] = {lista: [...], avisos: [...]}. O motor (_cad_loop) é uma thread como a das campanhas:
#  - marca o passo "enviando" e grava ANTES de enviar (queda no meio nunca reenvia sozinho; na partida vira "falhou" ou "enviado" se achou no banco);
#  - passo com mais de 60 min de atraso é pulado (PC/painel desligado) e avisa;
#  - mínimo de 20 s entre quaisquer dois envios (compartilhado com as campanhas) + 3 a 12 s de folga entre cadências diferentes;
#  - ANTES de cada envio e a cada volta do laço confere no messages.db (só leitura) se a pessoa respondeu depois do 1º toque;
#  - nunca marca a conversa como lida; o envio sai com X-Origem "painel:cadencia" (aparece na auditoria da ponte);
#  - 1ª mensagem para número sem conversa só pelo mecanismo de números liberados (10 min), nunca JID arbitrário.
# Acesso de máquina (MCP/scripts): config.json "api_token": "sha256:<hex>" + cabeçalho Authorization: Bearer <token>, só nestas rotas.
import random as _cad_rd
from datetime import datetime as _cad_datetime, timedelta as _cad_td, timezone as _cad_tzmod

CAD_TZ = _cad_tzmod(_cad_td(hours=-3))      # Brasília (sem horário de verão desde 2019)

CAD_MAX_PASSOS = 10
CAD_MAX_ATIVAS = 200
CAD_TEXTO_MAX = 4000
CAD_ATRASO_MAX_MIN = 60
CAD_DEDUP_S = 3600
CAD_GAP = 20                  # s entre dois envios quaisquer (cadências e campanhas)
CAD_JITTER = (3.0, 12.0)      # s extras entre cadências diferentes
CAD_LOOP_S = 15
CAD_MIN_FUTURO_S = 60
CAD_HIST_MAX = 300
CAD_AVISOS_MAX = 100
CAD_TOKEN_LIMITE = (30, 600)  # pedidos por janela (s) por token
CAD_BODY_MAX = 128 * 1024
CAD_ORIGEM_ENVIO = "painel:cadencia"
_cad_origem_tl = threading.local()
_cad_lock_proprio = threading.Lock()
_cad_mem = {"ultimo_ts": 0.0, "ultimo_cad": "", "jitter": 0.0}
_cad_rate = {}
_cad_rate_lock = threading.Lock()
_cad_teste_ultimo = [0.0]
CAD_STATUS_ATIVOS = ("ativa", "pausada")


def _cad_agora():
    return _cad_datetime.now(CAD_TZ).replace(tzinfo=None)


def _cad_iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%S")


def _cad_epoch(d):
    return d.replace(tzinfo=CAD_TZ).timestamp()


def _cad_err(ex):
    return f"{type(ex).__name__}: {ex}"[:200]


def _cad_estado(e):
    """Seção "cadencias" do painel_estado.json (cria o que faltar). Usar só dentro do _estado_lock."""
    c = e.get("cadencias")
    if not isinstance(c, dict):
        c = e["cadencias"] = {}
    if not isinstance(c.get("lista"), list):
        c["lista"] = []
    if not isinstance(c.get("avisos"), list):
        c["avisos"] = []
    return c


def _cad_ro():
    c = estado_ler_cache().get("cadencias")
    c = c if isinstance(c, dict) else {}
    return {"lista": c.get("lista") or [], "avisos": c.get("avisos") or []}


# ---------- números: 9º dígito ----------
def cad_numero_normalizar(n):
    """(dígitos com DDI, erro). 10/11 dígitos sem '+' = Brasil. NÃO adiciona nem tira o 9º dígito (isso é a resolução)."""
    s = str(n or "").strip()
    d = re.sub(r"\D", "", s)
    if d.startswith("00"):
        d = d[2:]
    if not d:
        return "", "informe o número"
    if len(d) in (10, 11) and not s.startswith("+"):
        d = "55" + d
    if d.startswith("55") and len(d) in (12, 13):
        loc = d[2:]
        if int(loc[:2]) not in NUM_DDDS:
            return "", "DDD inválido"
        parte = loc[2:]
        if len(parte) == 9 and parte[0] != "9":
            return "", "celular com 9 dígitos precisa começar com 9"
        if len(parte) == 8 and parte[0] not in "23456789":
            return "", "número inválido"
        return d, ""
    if 10 <= len(d) <= 15 and d[0] != "0":
        return d, ""
    return "", "número inválido (use DDD + número)"


def cad_variantes(d):
    """[(número, rótulo)] na ordem a tentar: primeiro a forma informada, depois a outra (com/sem o 9º dígito)."""
    if d.startswith("55") and len(d) == 13 and d[4] == "9":
        return [(d, "com_9"), (d[:4] + d[5:], "sem_9")]
    if d.startswith("55") and len(d) == 12 and d[4] in "6789":
        return [(d, "sem_9"), (d[:4] + "9" + d[4:], "com_9")]
    return [(d, "unico")]


def _cad_rotulo(pn):
    if pn.startswith("55") and len(pn) == 13 and pn[4] == "9":
        return "com_9"
    if pn.startswith("55") and len(pn) == 12 and pn[4] in "6789":
        return "sem_9"
    return "unico"


def _cad_consultar(d):
    """Uma forma exata do número (sem normalizar): conversa existente ou pergunta à ponte (só leitura). Quando a ponte
    confirma e não há conversa, libera o JID por 10 min em _num_ok (o único caminho para a 1ª mensagem)."""
    j = _num_conversa([d])
    if j:
        return {"existe": True, "jid": j, "fonte": "conversa", "numero": re.sub(r"\D", "", j.split("@")[0]) if j.endswith("@s.whatsapp.net") else d}
    r = _num_ponte(d)
    if not r.get("success", True) or not r.get("exists"):
        return {"existe": False}
    jid, lid = str(r.get("jid") or ""), str(r.get("lid") or "")
    m = re.fullmatch(r"(\d{8,15})@s\.whatsapp\.net", jid)
    if not m or (lid and not re.fullmatch(r"\d{1,20}@lid", lid)):
        raise ErroEnvio("resposta inesperada da ponte", 502)
    pn = m.group(1)
    j = _num_conversa(numero_variantes(pn), lid)
    if j:
        return {"existe": True, "jid": j, "fonte": "conversa", "numero": pn}
    with _num_lock:
        agora = time.time()
        for k in [k for k, t in _num_ok.items() if t <= agora]:
            _num_ok.pop(k, None)
        _num_ok[jid] = agora + NUM_TTL
    return {"existe": True, "jid": jid, "fonte": "ponte", "numero": pn, "lid": lid,
            "nome": str(r.get("name") or r.get("verified_name") or "")[:100]}


def cad_resolver(d):
    """Resolve o número (já normalizado) tentando as formas com e sem o 9º dígito. Nunca levanta: erro de ponte vira
    {"indisponivel": True}; nenhuma forma com WhatsApp vira {"numero_invalido": True}."""
    res = {"ok": False, "tentativas": [], "jid": "", "numero": "", "variante": "", "nome": "", "usou_8_digitos": False}
    for num, rot in cad_variantes(d):
        try:
            r = _cad_consultar(num)
        except ErroEnvio as ex:
            res.update(erro=str(ex), indisponivel=True, codigo=ex.code)
            return res
        res["tentativas"].append({"numero": num, "variante": rot, "existe": bool(r["existe"]), "fonte": r.get("fonte", "")})
        if r["existe"]:
            pn = r.get("numero") or num
            res.update(ok=True, jid=r["jid"], numero=pn, variante=_cad_rotulo(pn), nome=r.get("nome", ""), fonte=r.get("fonte", ""))
            res["usou_8_digitos"] = res["variante"] == "sem_9" and any(v == "com_9" for _, v in cad_variantes(d))
            res["canonico_difere"] = pn != num
            return res
    res.update(numero_invalido=True, erro="Nenhuma forma deste número (com ou sem o 9º dígito) tem WhatsApp")
    return res


def _cad_nome_contato(jid, dado=""):
    dado = str(dado or "").strip()[:100]
    if dado:
        return dado
    try:
        nomes, lid2pn = carregar_nomes()
        db = ro(MSG_DB)
        try:
            r = db.execute("select name from chats where jid=?", (jid,)).fetchone()
        finally:
            db.close()
        n = nome_chat(jid, (r or [""])[0] or "", nomes, lid2pn)
        return "" if (not n or n.startswith("+") or n.isdigit()) else n[:100]
    except Exception:
        return ""


# ---------- textos ----------
def cad_render(texto, nome_contato, agora=None):
    """{nome} = primeiro nome; {data} = dd/mm/aaaa; {hora} = HH:MM. Sem nome, o {nome} some (e a vírgula/espaço antes dele)."""
    agora = agora or _cad_agora()
    prim = (str(nome_contato or "").strip().split() or [""])[0]
    t = str(texto or "")
    if prim:
        t = t.replace("{nome}", prim)
    else:
        t = re.sub(r"[ \t]*\{nome\}", "", t)
        t = re.sub(r"[ \t]+([,.!?;:])", r"\1", t)
    return t.replace("{data}", agora.strftime("%d/%m/%Y")).replace("{hora}", agora.strftime("%H:%M"))


def _cad_hash_textos(passos):
    return hashlib.sha1("\x1f".join(str(p.get("texto") or "").strip() for p in passos).encode("utf-8")).hexdigest()


# ---------- validação ----------
def _cad_quando(v):
    s = str(v or "").strip().replace(" ", "T", 1)
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?", s):
        s = s[:16]
        try:
            _cad_datetime.strptime(s, "%Y-%m-%dT%H:%M")
            return s
        except ValueError:
            pass
    raise ErroEnvio(f"data/hora inválida: {str(v)[:30]!r} (use AAAA-MM-DDTHH:MM)")


def cad_validar_passos(passos, agora, permitir_passado=False):
    if not isinstance(passos, list) or not passos:
        raise ErroEnvio("informe pelo menos 1 passo")
    if len(passos) > CAD_MAX_PASSOS:
        raise ErroEnvio(f"no máximo {CAD_MAX_PASSOS} passos por cadência")
    out = []
    for i, p in enumerate(passos, 1):
        if not isinstance(p, dict):
            raise ErroEnvio(f"passo {i}: inválido")
        texto = str(p.get("texto") if p.get("texto") is not None else p.get("message") or "").strip()
        if not texto:
            raise ErroEnvio(f"passo {i}: escreva a mensagem")
        if len(texto) > CAD_TEXTO_MAX:
            raise ErroEnvio(f"passo {i}: texto passa de {CAD_TEXTO_MAX} caracteres")
        q = _cad_quando(p.get("quando") if p.get("quando") is not None else p.get("when"))
        if not permitir_passado and _cad_datetime.strptime(q, "%Y-%m-%dT%H:%M") < agora + _cad_td(seconds=CAD_MIN_FUTURO_S):
            raise ErroEnvio(f"passo {i}: o horário {q[8:10]}/{q[5:7]} {q[11:16]} precisa estar pelo menos 1 minuto no futuro")
        out.append({"quando": q, "texto": texto})
    out.sort(key=lambda p: p["quando"])
    for a, b in zip(out, out[1:]):
        if a["quando"] == b["quando"]:
            raise ErroEnvio("dois passos no mesmo horário: separe por pelo menos 1 minuto")
    return out


def _cad_novo_passo(p):
    return {"id": secrets.token_hex(4), "quando": p["quando"], "texto": p["texto"], "status": "agendado",
            "enviado_em": "", "erro": "", "id_msg": ""}


# ---------- criação ----------
def _cad_entrada_contato(d):
    """(dígitos|'' , jid_informado|'') a partir de {numero|jid}."""
    jid = str(d.get("jid") or "").strip()
    if jid:
        if jid.endswith("@s.whatsapp.net"):
            return jid.split("@")[0].split(":")[0], ""
        if jid.endswith("@lid"):
            return "", jid
        raise ErroEnvio("cadência é só para contato individual (não grupo, canal ou lista)")
    return str(d.get("numero") or d.get("recipient") or ""), ""


def cad_preparar(d, agora, simular):
    """Valida e resolve; devolve (cadência pronta, resolução). Não grava."""
    passos = cad_validar_passos(d.get("passos"), agora, bool(d.get("permitir_passado")))
    entrada, jid_inf = _cad_entrada_contato(d)
    res = {"ok": False, "tentativas": [], "jid": "", "numero": "", "variante": "", "nome": "", "usou_8_digitos": False}
    numero = ""
    if jid_inf:
        if not jid_conhecido(jid_inf):
            raise ErroEnvio("conversa desconhecida")
        res.update(ok=True, jid=jid_inf, variante="lid", fonte="conversa")
    else:
        numero, erro = cad_numero_normalizar(entrada)
        if erro:
            raise ErroEnvio(erro)
        if d.get("sem_verificar"):
            res.update(ok=True, jid="", numero=numero, variante="", pendente=True)
        else:
            res = cad_resolver(numero)
            if res.get("indisponivel"):
                raise ErroEnvio("não consegui conferir o número agora: " + str(res.get("erro")), int(res.get("codigo") or 503))
    nome_c = _cad_nome_contato(res.get("jid", ""), d.get("contato_nome") or d.get("nome_contato") or res.get("nome")) if res.get("jid") \
        else str(d.get("contato_nome") or d.get("nome_contato") or "").strip()[:100]
    nome_cad = str(d.get("nome") or "").strip()[:80] or ("Cadência " + (nome_c or numero or "contato"))[:80]
    c = {"id": secrets.token_hex(6), "nome": nome_cad,
         "contato": {"numero": res.get("numero") or numero, "numero_informado": numero or entrada, "jid_resolvido": res.get("jid", ""),
                     "nome": nome_c, "variante": res.get("variante", ""), "usou_8_digitos": bool(res.get("usou_8_digitos")),
                     "tentativas": res.get("tentativas", []), "verificado_em": _cad_iso(agora) if res.get("ok") and not res.get("pendente") else ""},
         "passos": [_cad_novo_passo(p) for p in passos], "status": "ativa",
         "regra": {"parar_se_responder": d.get("stop_on_reply", d.get("parar_se_responder", True)) is not False},
         "origem": "painel", "criada_em": _cad_iso(agora), "criada_ts": _cad_epoch(agora),
         "primeira_envio_em": "", "primeira_envio_ts": 0, "resposta": None}
    return c, res


def _cad_chave_dup(c):
    return (_cad_hash_textos(c["passos"]), set(numero_variantes(c["contato"].get("numero") or "")) | {c["contato"].get("jid_resolvido")})


def _cad_resumo_publico(c, agora=None):
    """Resumo por passo para o chamador (criar/previa)."""
    nome_c = c["contato"].get("nome", "")
    return {"id": c["id"], "nome": c["nome"], "status": c["status"], "contato": dict(c["contato"]),
            "passos": [{"id": p["id"], "quando": p["quando"], "status": p["status"], "texto": p["texto"],
                        "texto_renderizado": cad_render(p["texto"], nome_c, _cad_datetime.strptime(p["quando"], "%Y-%m-%dT%H:%M"))} for p in c["passos"]]}


def cad_criar(d, origem, ip="", via=""):
    agora = _cad_agora()
    simular = bool(d.get("simular"))
    c, res = cad_preparar(d, agora, simular)
    c["origem"] = origem
    resp = {"success": True, "resolucao": res, "cadencia": _cad_resumo_publico(c)}
    if simular:
        resp["simulado"] = True
        resp["success"] = bool(res.get("ok"))
        if not res.get("ok"):
            resp["erro"] = res.get("erro", "número sem WhatsApp")
        return resp
    with _estado_lock:
        e = estado_ler()
        ce = _cad_estado(e)
        if not res.get("ok"):  # nenhuma forma do número tem WhatsApp: fica registrada como numero_invalido e avisa
            c["status"] = "numero_invalido"
            for p in c["passos"]:
                p.update(status="cancelado", erro="número sem WhatsApp")
            _cad_aviso(e, "numero_invalido", c, "Número sem WhatsApp (testei com e sem o 9º dígito): " + (c["contato"]["numero_informado"] or ""))
            ce["lista"].append(c)
            _cad_podar(ce)
            estado_gravar(e)
            resp.update(success=False, numero_invalido=True, erro=res.get("erro"), id=c["id"])
            registrar("cadencia_invalida", ip, origem=origem, id=c["id"], via=via)
            return resp
        ativas = [x for x in ce["lista"] if x.get("status") in CAD_STATUS_ATIVOS]
        if len(ativas) >= CAD_MAX_ATIVAS:
            raise ErroEnvio(f"limite de {CAD_MAX_ATIVAS} cadências ativas: cancele ou apague alguma", 429)
        if not d.get("ignorar_duplicada"):
            h, nums = _cad_chave_dup(c)
            for x in ce["lista"]:
                if x.get("status") in ("cancelada", "numero_invalido") or agora_ts_menos(x) > CAD_DEDUP_S:
                    continue
                h2, nums2 = _cad_chave_dup(x)
                if h2 == h and (nums & nums2 - {""}):
                    raise ErroEnvio(f"cadência igual (mesmo número e mesmos textos) criada há menos de 1 h: {x['id']}", 409)
        ce["lista"].append(c)
        _cad_podar(ce)
        estado_gravar(e)
    registrar("cadencia_criada", ip, origem=origem, id=c["id"], passos=len(c["passos"]), via=via or "sessao")
    resp["id"] = c["id"]
    resp["cadencia"] = _cad_resumo_publico(c)
    return resp


def agora_ts_menos(c):
    return _cad_epoch(_cad_agora()) - float(c.get("criada_ts") or 0)


def _cad_podar(ce):
    """Guarda só as últimas CAD_HIST_MAX cadências já encerradas (as ativas nunca saem)."""
    ativos = [x for x in ce["lista"] if x.get("status") in CAD_STATUS_ATIVOS]
    feitos = [x for x in ce["lista"] if x.get("status") not in CAD_STATUS_ATIVOS][-CAD_HIST_MAX:]
    ce["lista"][:] = [x for x in ce["lista"] if x in ativos or x in feitos]
    if len(ce["avisos"]) > CAD_AVISOS_MAX:
        ce["avisos"][:] = ce["avisos"][-CAD_AVISOS_MAX:]


def _cad_aviso(e, tipo, c, texto):
    ce = _cad_estado(e)
    j = (c.get("contato") or {}).get("jid_resolvido") or ""
    try:
        conversa = aliases()[1].get(j, j) if j else ""
    except Exception:
        conversa = j
    ce["avisos"].append({"id": secrets.token_hex(5), "tipo": tipo, "cadencia_id": c.get("id"), "jid": conversa,
                         "nome": (c.get("contato") or {}).get("nome") or c.get("nome") or "", "cadencia": c.get("nome", ""),
                         "texto": texto[:300], "em": _cad_iso(_cad_agora()), "lido": False})


# ---------- resposta do contato ----------
def _cad_ts(s):
    s = str(s or "").strip()
    try:
        d = _cad_datetime.fromisoformat(s)
    except ValueError:
        try:
            d = _cad_datetime.fromisoformat(s.replace(" ", "T", 1))
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=CAD_TZ)
    return d.timestamp()


def _cad_jids(c):
    """Todos os chats do mesmo contato: o JID resolvido, as duas formas do número (com/sem 9) e os @lid ligados a eles."""
    ct = c.get("contato") or {}
    cands = [ct.get("jid_resolvido") or ""]
    num = ct.get("numero") or ""
    for v in (numero_variantes(num) if num else []):
        cands.append(v + "@s.whatsapp.net")
    out = []
    para = aliases()[1]
    for x in cands:
        if not x:
            continue
        for y in jids_da_conversa(para.get(x, x)) + [x]:
            if y not in out:
                out.append(y)
    try:
        _n, lid2pn = carregar_nomes()
        pn2lid = {p: l for l, p in lid2pn.items()}
        for v in (numero_variantes(num) if num else []):
            if pn2lid.get(v) and pn2lid[v] + "@lid" not in out:
                out.append(pn2lid[v] + "@lid")
    except Exception:
        pass
    return out


def _cad_resumo_msg(content, mt):
    t = (content or "").strip()
    if t:
        return t[:140]
    return {"image": "[imagem]", "audio": "[áudio]", "video": "[vídeo]", "document": "[documento]", "sticker": "[figurinha]"}.get(mt or "", "[mensagem]")


def _cad_resposta(c, desde_ts):
    """Primeira mensagem RECEBIDA do contato depois de desde_ts, ou None. Reação (tabela própria) e ligação (media_type
    "call") não contam; linha sem texto e sem mídia (protocolo) também não."""
    jids = _cad_jids(c)
    if not jids:
        return None
    corte = _cad_datetime.fromtimestamp(desde_ts - 86400, CAD_TZ).strftime("%Y-%m-%d")
    db = ro(MSG_DB)
    try:
        rows = db.execute("select content, media_type, timestamp from messages where chat_jid in (%s) and is_from_me=0 "
                          "and timestamp>=? and coalesce(media_type,'')!='call' order by timestamp" % ",".join("?" * len(jids)),
                          (*jids, corte)).fetchall()
    finally:
        db.close()
    for content, mt, ts in rows:
        t = _cad_ts(ts)
        if t is None or t <= desde_ts:
            continue
        if not (content or "").strip() and not (mt or ""):
            continue
        return {"ts": t, "em": _cad_iso(_cad_datetime.fromtimestamp(t, CAD_TZ).replace(tzinfo=None)), "texto": _cad_resumo_msg(content, mt)}
    return None


def _cad_base_resposta(c):
    return float(c.get("primeira_envio_ts") or 0) or float(c.get("criada_ts") or 0)


def _cad_tem_pendente(c):
    return any(p.get("status") in ("agendado", "enviando") for p in c.get("passos", []))


def _cad_aplicar_resposta(e, c, r):
    """Dentro do _estado_lock: cancela o que falta e avisa. O passo "enviando" não é mexido (já saiu ou vai sair)."""
    n = 0
    for p in c["passos"]:
        if p["status"] == "agendado":
            p.update(status="cancelado_resposta", erro="")
            n += 1
    c["status"] = "parada_resposta"
    c["resposta"] = {"em": r["em"], "texto_resumo": r["texto"], "detectada_em": _cad_iso(_cad_agora()), "passos_cancelados": n}
    _cad_aviso(e, "parada_resposta", c, f"{(c['contato'].get('nome') or c['nome'])} respondeu: {r['texto']}")
    registrar("cadencia_parada_resposta", id=c["id"], cancelados=n)


def cad_varrer_respostas():
    """Confere todas as cadências ativas/pausadas com passos pendentes. Devolve quantas pararam."""
    cands = [x for x in _cad_ro()["lista"] if x.get("status") in CAD_STATUS_ATIVOS and (x.get("regra") or {}).get("parar_se_responder", True)
             and _cad_tem_pendente(x)]
    parou = 0
    for c in cands:
        try:
            r = _cad_resposta(c, _cad_base_resposta(c))
        except Exception as ex:
            registrar("cadencia_erro", repetir=300, etapa="resposta", erro=_cad_err(ex))
            continue
        if not r:
            continue
        with _estado_lock:
            e = estado_ler()
            for x in _cad_estado(e)["lista"]:
                if x["id"] == c["id"] and x["status"] in CAD_STATUS_ATIVOS and _cad_tem_pendente(x):
                    _cad_aplicar_resposta(e, x, r)
                    parou += 1
                    estado_gravar(e)
    return parou


# ---------- envio ----------
def _cad_lock_global():
    return globals().get("_camp_envio_lock") or _cad_lock_proprio


def _cad_gap_necessario(cid):
    g = max(CAD_GAP, globals().get("CAMP_GAP_GLOBAL", 0))
    if _cad_mem["ultimo_cad"] and _cad_mem["ultimo_cad"] != cid:
        g += _cad_mem["jitter"]
    return g


def _cad_ultimo_envio_ts():
    u = _cad_mem["ultimo_ts"]
    try:
        d = _camp_dt(_camp_ro().get("ultimo_envio"))
        if d:
            u = max(u, d.timestamp())
    except Exception:
        pass
    return u


def _cad_marcar_envio(e, cid, agora):
    _cad_mem.update(ultimo_ts=_cad_epoch(agora), ultimo_cad=cid, jitter=_cad_rd.uniform(*CAD_JITTER))
    try:  # as campanhas respeitam o mesmo intervalo mínimo
        _camp_estado(e)["ultimo_envio"] = _camp_iso(_camp_agora())
    except Exception:
        pass


def _cad_nao_saiu(ex):
    s = str(ex)
    return "10061" in s or "recusou" in s.lower() or "refused" in s.lower()


def _cad_status_final(c):
    if c["status"] == "ativa" and not _cad_tem_pendente(c):
        c["status"] = "concluida"
        c["concluida_em"] = _cad_iso(_cad_agora())


def _cad_enviar_texto(jid, texto, origem=CAD_ORIGEM_ENVIO):
    _cad_origem_tl.v = origem
    try:
        return enviar_mensagem({"jid": jid, "texto": texto, "sem_ler": True})
    finally:
        _cad_origem_tl.v = ""


def _cad_proximo_devido(ce, agora_s, agora_ts):
    cand = None
    for c in ce["lista"]:
        if c.get("status") != "ativa":
            continue
        for p in c["passos"]:
            if p.get("status") == "agendado" and p["quando"] + ":00" <= agora_s and float(p.get("retomar_ts") or 0) <= agora_ts:
                k = (p["quando"], c.get("criada_em", ""), c["id"])
                if cand is None or k < cand[0]:
                    cand = (k, c, p)
                break  # só o primeiro agendado de cada cadência: os seguintes esperam a vez
    return cand


def cad_enviar_proximo(agora=None):
    """Trata no máximo 1 passo vencido. Devolve None (nada a fazer), "espera" (intervalo mínimo) ou uma descrição."""
    agora = agora or _cad_agora()
    ats = _cad_epoch(agora)
    with _cad_lock_global():
        # 1) escolhe o passo e decide pular / parar por resposta / esperar o intervalo
        with _estado_lock:
            e = estado_ler()
            ce = _cad_estado(e)
            cand = _cad_proximo_devido(ce, _cad_iso(agora), ats)
            if not cand:
                return None
            _, c, p = cand
            cid, pid = c["id"], p["id"]
            atraso_min = (agora - _cad_datetime.strptime(p["quando"], "%Y-%m-%dT%H:%M")).total_seconds() / 60
            if atraso_min > CAD_ATRASO_MAX_MIN:
                p.update(status="pulado", erro=f"não enviado: {int(atraso_min)} min de atraso (o painel ou o PC estava desligado no horário)")
                _cad_aviso(e, "passo_pulado", c, f"Toque das {p['quando'][11:16]} de {p['quando'][8:10]}/{p['quando'][5:7]} pulado: {int(atraso_min)} min de atraso")
                _cad_status_final(c)
                estado_gravar(e)
                return f"pulado:{cid}:{pid}"
            if ats - _cad_ultimo_envio_ts() < _cad_gap_necessario(cid):
                return "espera"
            c_copia, p_copia = dict(c), dict(p)
        # 2) conferência de resposta ANTES de qualquer envio
        if (c_copia.get("regra") or {}).get("parar_se_responder", True):
            r = _cad_resposta(c_copia, _cad_base_resposta(c_copia))
            if r:
                with _estado_lock:
                    e = estado_ler()
                    for x in _cad_estado(e)["lista"]:
                        if x["id"] == cid and x["status"] in CAD_STATUS_ATIVOS and _cad_tem_pendente(x):
                            _cad_aplicar_resposta(e, x, r)
                            estado_gravar(e)
                return f"parada_resposta:{cid}"
        # 3) número: sem conversa ainda (ou sem JID) = confere de novo na ponte antes de enviar (e libera o JID por 10 min)
        ct = c_copia["contato"]
        jid = ct.get("jid_resolvido") or ""
        if not jid or not jid_conhecido(jid):
            base = ct.get("numero_informado") or ct.get("numero") or ""
            if ct.get("variante") == "lid" or not base:
                return _cad_falha_pre(cid, pid, "sem número para enviar (a conversa sumiu do banco)", definitiva=True)
            d_, erro = cad_numero_normalizar(base)
            res = cad_resolver(d_) if not erro else {"numero_invalido": True, "erro": erro}
            if res.get("indisponivel"):
                return _cad_falha_pre(cid, pid, "ponte indisponível para conferir o número: " + str(res.get("erro")), definitiva=False, ats=ats)
            if not res.get("ok"):
                with _estado_lock:
                    e = estado_ler()
                    for x in _cad_estado(e)["lista"]:
                        if x["id"] == cid and x["status"] in CAD_STATUS_ATIVOS:
                            x["status"] = "numero_invalido"
                            for q in x["passos"]:
                                if q["status"] == "agendado":
                                    q.update(status="cancelado", erro="número sem WhatsApp na conferência final")
                            _cad_aviso(e, "numero_invalido", x, "Número sem WhatsApp na conferência final (com e sem o 9º dígito)")
                            estado_gravar(e)
                return f"numero_invalido:{cid}"
            jid = res["jid"]
            with _estado_lock:
                e = estado_ler()
                for x in _cad_estado(e)["lista"]:
                    if x["id"] == cid:
                        x["contato"].update(jid_resolvido=jid, numero=res["numero"], variante=res["variante"], tentativas=res["tentativas"],
                                            usou_8_digitos=bool(res.get("usou_8_digitos")), verificado_em=_cad_iso(agora))
                        if not x["contato"].get("nome"):
                            x["contato"]["nome"] = _cad_nome_contato(jid, res.get("nome"))
                estado_gravar(e)
        # 4) marca "enviando" ANTES de enviar (chave de idempotência); confere de novo se ainda vale
        chave = f"{cid}:{pid}:{secrets.token_hex(3)}"
        with _estado_lock:
            e = estado_ler()
            alvo = [x for x in _cad_estado(e)["lista"] if x["id"] == cid and x["status"] == "ativa"]
            q = [y for y in alvo[0]["passos"] if y["id"] == pid and y["status"] == "agendado"] if alvo else []
            if not q:
                return None  # cancelado/pausado nesse meio-tempo
            x, q = alvo[0], q[0]
            texto = cad_render(q["texto"], x["contato"].get("nome", ""), agora)
            q.update(status="enviando", chave=chave, t_envio=ats, texto_enviado=texto, enviado_em=_cad_iso(agora), erro="")
            _cad_marcar_envio(e, cid, agora)
            estado_gravar(e)
        # 5) envio
        status, erro, id_msg, simulado = "enviado", "", "", False
        try:
            r = _cad_enviar_texto(jid, texto)
            if not r or not r.get("success"):
                raise ErroEnvio((r or {}).get("message") or "falha no envio", 502)
            id_msg = str(r.get("id") or r.get("message_id") or "")
            simulado = bool(r.get("dry_run"))
        except Exception as ex:
            status, erro = "falhou", (str(ex) or type(ex).__name__)[:300]
            if _cad_nao_saiu(ex):
                status, erro = "retry", erro
        with _estado_lock:
            e = estado_ler()
            for x in _cad_estado(e)["lista"]:
                if x["id"] != cid:
                    continue
                for q in x["passos"]:
                    if q["id"] != pid or q.get("chave") != chave or q["status"] != "enviando":
                        continue
                    if status == "retry":  # a ponte recusou a conexão: certamente não saiu; tenta de novo adiante
                        n = int(q.get("tentativas") or 0) + 1
                        if n >= 5:
                            q.update(status="falhou", erro="ponte fora do ar: " + erro, tentativas=n)
                            _cad_aviso(e, "passo_falhou", x, "Toque não enviado: a ponte do WhatsApp estava fora do ar")
                        else:
                            q.update(status="agendado", erro="ponte fora do ar, nova tentativa", tentativas=n, retomar_ts=ats + 60)
                    else:
                        q.update(status=status, enviado_em=_cad_iso(_cad_agora()), erro=("simulação: nada saiu" if simulado else erro), id_msg=id_msg)
                        if not x.get("primeira_envio_ts"):
                            x["primeira_envio_ts"], x["primeira_envio_em"] = q["t_envio"], _cad_iso(_cad_datetime.fromtimestamp(q["t_envio"], CAD_TZ).replace(tzinfo=None))
                        if status == "falhou":
                            _cad_aviso(e, "passo_falhou", x, "Toque não confirmado: " + erro[:120] + " (confira na conversa antes de reenviar)")
                    _cad_status_final(x)
            estado_gravar(e)
        return f"{status}:{cid}:{pid}"


def _cad_falha_pre(cid, pid, motivo, definitiva, ats=0):
    """Falha ANTES de enviar (nada saiu): tenta de novo em 60 s, ou marca como falhou quando é definitiva."""
    with _estado_lock:
        e = estado_ler()
        for x in _cad_estado(e)["lista"]:
            if x["id"] != cid:
                continue
            for q in x["passos"]:
                if q["id"] == pid and q["status"] == "agendado":
                    if definitiva:
                        q.update(status="falhou", erro=motivo)
                        _cad_aviso(e, "passo_falhou", x, motivo)
                        _cad_status_final(x)
                    else:
                        q.update(erro=motivo, retomar_ts=ats + 60)
        estado_gravar(e)
    return f"pre_falha:{cid}"


def _cad_ja_saiu(c, texto, t_envio):
    """O texto já aparece como enviado por mim depois de t_envio? (confirma passo que ficou "enviando")"""
    try:
        jids = _cad_jids(c)
        db = ro(MSG_DB)
        try:
            rows = db.execute("select content, timestamp from messages where chat_jid in (%s) and is_from_me=1 and timestamp>=?" % ",".join("?" * len(jids)),
                              (*jids, _cad_datetime.fromtimestamp(float(t_envio) - 86400, CAD_TZ).strftime("%Y-%m-%d"))).fetchall()
        finally:
            db.close()
        return any((cc or "").strip() == texto.strip() and (_cad_ts(ts) or 0) >= float(t_envio) - 5 for cc, ts in rows)
    except Exception:
        return False


def cad_recuperar():
    """Na partida: passo que ficou "enviando" (painel caiu no meio) é conferido no banco; se não achou, vira "falhou" pedindo
    conferência. Nunca reenvia sozinho."""
    n = 0
    with _estado_lock:
        e = estado_ler()
        for c in _cad_estado(e)["lista"]:
            for p in c["passos"]:
                if p.get("status") != "enviando":
                    continue
                n += 1
                if _cad_ja_saiu(c, p.get("texto_enviado") or "", p.get("t_envio") or 0):
                    p.update(status="enviado", erro="confirmado após reiniciar o painel")
                else:
                    p.update(status="falhou", erro="falhou-confirmar: o painel parou durante o envio; confira na conversa se saiu antes de reenviar")
                    _cad_aviso(e, "passo_falhou", c, "Toque interrompido pela queda do painel: confira na conversa se saiu")
                if not c.get("primeira_envio_ts") and p.get("t_envio"):
                    c["primeira_envio_ts"] = p["t_envio"]
                    c["primeira_envio_em"] = _cad_iso(_cad_datetime.fromtimestamp(p["t_envio"], CAD_TZ).replace(tzinfo=None))
            _cad_status_final(c)
        if n:
            estado_gravar(e)
    return n


def cad_tick(agora=None):
    """Uma volta do motor: confere respostas e envia o que venceu (no máximo 25 passos). Devolve o último resultado."""
    agora = agora or _cad_agora()
    cad_varrer_respostas()
    ult = None
    for _ in range(25):
        ult = cad_enviar_proximo(agora)
        if ult is None or ult == "espera":
            break
    return ult


def _cad_loop():
    time.sleep(6)
    try:
        cad_recuperar()
    except Exception as ex:
        registrar("cadencia_erro", etapa="recuperar", erro=_cad_err(ex))
    while True:
        espera = CAD_LOOP_S
        try:
            if cad_tick() == "espera":
                espera = 3
        except Exception as ex:
            registrar("cadencia_erro", repetir=300, etapa="tick", erro=_cad_err(ex))
        time.sleep(espera)


# envio com o rótulo de origem para a auditoria da ponte (X-Origem); só o /api/send feito pelo motor leva o cabeçalho
_cad_chamar_ponte0 = chamar_ponte


def chamar_ponte(rota, corpo, timeout=180):
    org = getattr(_cad_origem_tl, "v", "")
    if not org or rota != "/api/send":
        return _cad_chamar_ponte0(rota, corpo, timeout)
    req = urllib.request.Request(PONTE + rota, data=json.dumps(corpo).encode(), headers={"Content-Type": "application/json", "X-Origem": org})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            txt = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as ex:
        txt = ex.read().decode("utf-8", "replace")
        try:
            return json.loads(txt)
        except Exception:
            raise ErroEnvio(f"ponte respondeu {ex.code}: {txt[:200]}", 502)
    except Exception as ex:
        raise ErroEnvio(f"ponte do WhatsApp indisponível: {ex}", 503)
    try:
        return json.loads(txt)
    except Exception:
        return {"success": True, "message": txt[:200]}


# ---------- API ----------
def _cad_publica(c, agora_s):
    pas = c.get("passos") or []
    prox = next((p for p in pas if p.get("status") == "agendado"), None)
    j = (c.get("contato") or {}).get("jid_resolvido") or ""
    try:
        conversa = aliases()[1].get(j, j) if j else ""
    except Exception:
        conversa = j
    return {**{k: v for k, v in c.items() if k not in ("criada_ts",)},
            "conversa": conversa,
            "proximo": ({"passo_id": prox["id"], "quando": prox["quando"], "n": pas.index(prox) + 1, "de": len(pas)} if prox and c.get("status") in CAD_STATUS_ATIVOS else None),
            "enviados": sum(1 for p in pas if p.get("status") == "enviado"), "total": len(pas)}


def cad_api_listar(q=None):
    ce = _cad_ro()
    agora_s = _cad_iso(_cad_agora())
    lista = [_cad_publica(c, agora_s) for c in ce["lista"]]
    if q and q.get("id"):
        lista = [c for c in lista if c["id"] == q["id"][0]]
    ativas = sorted([c for c in lista if c["status"] in CAD_STATUS_ATIVOS], key=lambda c: (c["proximo"] or {}).get("quando", "9999"))
    resto = sorted([c for c in lista if c["status"] not in CAD_STATUS_ATIVOS], key=lambda c: c.get("criada_em", ""), reverse=True)
    avisos = [a for a in ce["avisos"] if not a.get("lido")]
    cont = lambda s: sum(1 for c in lista if c["status"] == s)
    return {"success": True, "agora": agora_s, "cadencias": ativas + resto, "avisos": avisos[-30:],
            "resumo": {"ativas": cont("ativa"), "pausadas": cont("pausada"), "paradas_resposta": cont("parada_resposta"), "concluidas": cont("concluida"),
                       "canceladas": cont("cancelada"), "numero_invalido": cont("numero_invalido"), "avisos_nao_lidos": len(avisos)},
            "limites": {"passos": CAD_MAX_PASSOS, "ativas": CAD_MAX_ATIVAS, "texto": CAD_TEXTO_MAX, "gap": max(CAD_GAP, globals().get("CAMP_GAP_GLOBAL", 0)),
                        "atraso_min": CAD_ATRASO_MAX_MIN, "meu_jid": meu_jid_teste()}}


def _cad_mexer(cid, fn):
    """Aplica fn(estado, cadência) dentro do lock; devolve o que fn devolver."""
    with _estado_lock:
        e = estado_ler()
        c = next((x for x in _cad_estado(e)["lista"] if x["id"] == cid), None)
        if not c:
            raise ErroEnvio("cadência não encontrada", 404)
        r = fn(e, c)
        estado_gravar(e)
    return r


def cad_api_post(d, origem="painel", ip="", via=""):
    acao = str(d.get("acao") or "")
    cid = str(d.get("id") or "")
    if acao in ("criar", "previa"):
        if acao == "previa":
            d = {**d, "simular": True}
        return cad_criar(d, origem, ip, via)
    if acao == "verificar_numero":  # só confere o número (com e sem o 9º dígito); não grava nada
        entrada, jid_inf = _cad_entrada_contato(d)
        if jid_inf:
            return {"success": jid_conhecido(jid_inf), "resolucao": {"ok": jid_conhecido(jid_inf), "jid": jid_inf, "variante": "lid", "tentativas": []}}
        numero, erro = cad_numero_normalizar(entrada)
        if erro:
            raise ErroEnvio(erro)
        res = cad_resolver(numero)
        if res.get("indisponivel"):
            raise ErroEnvio("não consegui conferir o número agora: " + str(res.get("erro")), int(res.get("codigo") or 503))
        if res.get("ok"):
            res["nome"] = _cad_nome_contato(res["jid"], res.get("nome"))
        return {"success": bool(res.get("ok")), "resolucao": res, "erro": "" if res.get("ok") else res.get("erro", "")}
    if acao == "dispensar_aviso":
        with _estado_lock:
            e = estado_ler()
            n = 0
            for a in _cad_estado(e)["avisos"]:
                if not a.get("lido") and (d.get("todos") or a["id"] == cid):
                    a["lido"] = True
                    n += 1
            estado_gravar(e)
        return {"success": True, "dispensados": n}
    if acao == "testar":
        if time.time() - _cad_teste_ultimo[0] < 5:
            raise ErroEnvio("aguarde alguns segundos entre testes", 429)
        texto, nome_c = str(d.get("texto") or ""), str(d.get("contato_nome") or "")
        if cid:
            c = next((x for x in _cad_ro()["lista"] if x["id"] == cid), None)
            if not c:
                raise ErroEnvio("cadência não encontrada", 404)
            p = next((x for x in c["passos"] if x["id"] == str(d.get("passo_id") or "")), c["passos"][0])
            texto, nome_c = p["texto"], c["contato"].get("nome", "")
        if not texto.strip():
            raise ErroEnvio("escreva a mensagem")
        _cad_teste_ultimo[0] = time.time()
        corpo = "[Teste de cadência] " + cad_render(texto[:CAD_TEXTO_MAX], nome_c)
        r = _cad_enviar_texto(meu_jid_teste(), corpo, CAD_ORIGEM_ENVIO + "-teste")  # destino fixo: o próprio operador
        return {"success": True, "para": meu_jid_teste(), "dry_run": bool((r or {}).get("dry_run"))}
    if not cid:
        raise ErroEnvio("informe o id da cadência")
    if acao == "cancelar":
        def f(e, c):
            if c["status"] not in CAD_STATUS_ATIVOS:
                raise ErroEnvio("a cadência já terminou")
            for p in c["passos"]:
                if p["status"] == "agendado":
                    p["status"] = "cancelado"
            c["status"], c["cancelada_em"] = "cancelada", _cad_iso(_cad_agora())
        _cad_mexer(cid, f)
        return {"success": True}
    if acao in ("pausar", "retomar"):
        def f(e, c):
            if acao == "pausar" and c["status"] != "ativa":
                raise ErroEnvio("só dá para pausar uma cadência ativa")
            if acao == "retomar" and c["status"] != "pausada":
                raise ErroEnvio("a cadência não está pausada")
            c["status"] = "pausada" if acao == "pausar" else "ativa"
            if acao == "retomar" and d.get("pular_vencidos"):
                for p in c["passos"]:
                    if p["status"] == "agendado" and p["quando"] < _cad_iso(_cad_agora())[:16]:
                        p.update(status="pulado", erro="passou do horário enquanto a cadência estava pausada")
                _cad_status_final(c)
        _cad_mexer(cid, f)
        return {"success": True}
    if acao in ("cancelar_passo", "editar_passo"):
        pid = str(d.get("passo_id") or "")

        def f(e, c):
            if c["status"] not in CAD_STATUS_ATIVOS:
                raise ErroEnvio("a cadência já terminou")
            p = next((x for x in c["passos"] if x["id"] == pid), None)
            if not p:
                raise ErroEnvio("passo não encontrado", 404)
            if p["status"] != "agendado":
                raise ErroEnvio("só dá para mexer num passo ainda agendado")
            if acao == "cancelar_passo":
                p["status"] = "cancelado"
                _cad_status_final(c)
                return
            if d.get("texto") is not None:
                t = str(d["texto"]).strip()
                if not t or len(t) > CAD_TEXTO_MAX:
                    raise ErroEnvio(f"texto vazio ou acima de {CAD_TEXTO_MAX} caracteres")
                p["texto"] = t
            if d.get("quando") is not None:
                qd = _cad_quando(d["quando"])
                if not d.get("permitir_passado") and _cad_datetime.strptime(qd, "%Y-%m-%dT%H:%M") < _cad_agora() + _cad_td(seconds=CAD_MIN_FUTURO_S):
                    raise ErroEnvio("o horário precisa estar pelo menos 1 minuto no futuro")
                if any(x is not p and x["status"] != "cancelado" and x["quando"] == qd for x in c["passos"]):
                    raise ErroEnvio("já existe outro passo nesse horário")
                p["quando"] = qd
                c["passos"].sort(key=lambda x: x["quando"])
        _cad_mexer(cid, f)
        return {"success": True}
    if acao == "apagar":
        with _estado_lock:
            e = estado_ler()
            ce = _cad_estado(e)
            c = next((x for x in ce["lista"] if x["id"] == cid), None)
            if not c:
                raise ErroEnvio("cadência não encontrada", 404)
            if c["status"] in CAD_STATUS_ATIVOS:
                raise ErroEnvio("cancele a cadência antes de apagar")
            ce["lista"].remove(c)
            estado_gravar(e)
        return {"success": True}
    raise ErroEnvio("ação inválida")


# ---------- acesso por token (MCP/scripts) e rotas ----------
def _cad_token_hash():
    v = str(_cfg_painel().get("api_token") or "").strip()
    if not v:
        return ""
    if v.startswith("sha256:"):
        return v[7:].lower()
    return hashlib.sha256(v.encode("utf-8")).hexdigest()  # valor em texto puro (aceito, mas troque por sha256:<hex>)


def cad_token_ok(tok):
    h = _cad_token_hash()
    if not h or not tok:
        return False
    return hmac.compare_digest(hashlib.sha256(tok.encode("utf-8")).hexdigest(), h)


def _cad_rate_ok(tok):
    chave = hashlib.sha256(tok.encode("utf-8")).hexdigest()[:16]
    agora = time.time()
    with _cad_rate_lock:
        v = [t for t in _cad_rate.get(chave, []) if agora - t < CAD_TOKEN_LIMITE[1]]
        if len(v) >= CAD_TOKEN_LIMITE[0]:
            _cad_rate[chave] = v
            return max(1, int(CAD_TOKEN_LIMITE[1] - (agora - v[0])))
        v.append(agora)
        _cad_rate[chave] = v
        if len(_cad_rate) > 50:
            for k in [k for k, x in _cad_rate.items() if not x or agora - x[-1] > CAD_TOKEN_LIMITE[1]]:
                _cad_rate.pop(k, None)
    return 0


def _cad_acesso(self, post):
    """True se pode seguir. Com "Authorization: Bearer" vale só o token (IP privado e Host válido continuam exigidos);
    sem o cabeçalho vale a portaria normal do painel (login fora deste PC, mesma origem nos POST)."""
    auth = self.headers.get("Authorization") or ""
    self.via_token = False
    if not auth.lower().startswith("bearer "):
        return self.portaria(post=post)
    if not hasattr(self, "_peer"):
        self._peer = self.client_address[0]
    ip = self._peer
    self.via_proxy = False
    if PROXY and ip_cliente_ok(ip) and not ip_local(ip) and self.headers.get("X-Forwarded-For"):
        real = self.headers["X-Forwarded-For"].split(",")[-1].strip()
        try:
            ipaddress.ip_address(real)
            self.client_address = (real, self.client_address[1])
            self.via_proxy = True
            ip = real
        except ValueError:
            pass
    if not self.via_proxy and not ip_cliente_ok(ip):
        self.close_connection = True
        registrar("recusado_ip_externo", ip, repetir=60)
        self.enviar(403, "acesso permitido só pela rede local", "text/plain; charset=utf-8")
        return False
    host = self.headers.get("Host", "")
    if not host_ok(host):
        self.close_connection = True
        registrar("recusado_host", ip, repetir=60, host=host)
        self.enviar(403, "proibido", "text/plain; charset=utf-8")
        return False
    self.https = self.connection.__class__.__name__ == "SSLSocket" or (self.via_proxy and self.headers.get("X-Forwarded-Proto") == "https")
    self.remoto = not ip_local(ip)
    tok = auth[7:].strip()
    if not _cad_token_hash():
        self.close_connection = True
        self.json({"success": False, "erro": "token de API não configurado no painel (config.json: api_token)"}, 401)
        return False
    if not cad_token_ok(tok):
        self.close_connection = True
        registrar("cadencia_token_invalido", ip, repetir=60, rota=urlparse(self.path).path)
        self.json({"success": False, "erro": "token inválido"}, 401)
        return False
    espera = _cad_rate_ok(tok)
    if espera:
        self.close_connection = True
        registrar("limite", ip, repetir=60, classe="cadencia_token", rota=urlparse(self.path).path, espera=espera)
        self.enviar(429, json.dumps({"success": False, "limite": True, "espera": espera, "erro": f"Limite de {CAD_TOKEN_LIMITE[0]} pedidos por {CAD_TOKEN_LIMITE[1] // 60} min. Tente em {espera} s."}, ensure_ascii=False),
                    extra={"Retry-After": str(espera)})
        return False
    self.via_token = True
    return True


def _cad_do_GET(self):
    u = urlparse(self.path)
    if u.path != "/api/cadencias":
        return _cad_get0(self)
    if not _cad_acesso(self, False):
        return
    try:
        self.json(cad_api_listar(parse_qs(u.query)))
    except Exception as ex:
        registrar("cadencia_erro", repetir=300, etapa="api_get", erro=_cad_err(ex))
        self.json({"success": False, "erro": _cad_err(ex)}, 500)


def _cad_do_POST(self):
    u = urlparse(self.path)
    if u.path != "/api/cadencias":
        return _cad_post0(self)
    if not _cad_acesso(self, True):
        return
    try:
        tam = int(self.headers.get("Content-Length") or 0)
        if not self.via_token:
            espera = ritmo_espera(self.client_address[0], u.path)
            if espera:
                if 0 <= tam <= 1024 * 1024:
                    self.rfile.read(tam)
                else:
                    self.close_connection = True
                return self.enviar(429, json.dumps({"success": False, "limite": True, "espera": espera,
                                                    "erro": f"Muitas ações em pouco tempo. Tente de novo em {espera} s."}, ensure_ascii=False),
                                   extra={"Retry-After": str(espera)})
        if tam > CAD_BODY_MAX:
            self.close_connection = True
            raise ErroEnvio("requisição grande demais", 413)
        d = json.loads(self.rfile.read(tam) or b"{}")
        if not isinstance(d, dict):
            raise ErroEnvio("requisição inválida")
        origem = "painel"
        if self.via_token:
            o = str(d.get("origem") or "")
            origem = o if re.fullmatch(r"(mcp|script):[A-Za-z0-9_.\- ]{1,32}", o) else "mcp:api"
        self.json(cad_api_post(d, origem, self.client_address[0], "token" if self.via_token else "sessao"))
    except ErroEnvio as ex:
        self.json({"success": False, "erro": str(ex)}, ex.code)
    except Exception as ex:
        self.close_connection = True
        registrar("cadencia_erro", repetir=300, etapa="api_post", erro=_cad_err(ex))
        self.json({"success": False, "erro": _cad_err(ex)}, 500)


_cad_get0 = Handler.do_GET
_cad_post0 = Handler.do_POST
Handler.do_GET = _cad_do_GET
Handler.do_POST = _cad_do_POST

if "_sd_robusto" in globals():
    _cad_loop = _sd_robusto(_cad_loop, "_cad_loop")
if __name__ == "__main__" and os.environ.get("PAINEL_SEM_CADENCIAS") != "1":
    threading.Thread(target=_cad_loop, daemon=True).start()
# ---------- fim [cadencias] ----------


# ---------- [conta-openai] entrar com a conta do ChatGPT (Codex CLI, login por código) e usar o plano no lugar da chave de API ----------
import shutil as _co_sh, subprocess as _co_sp, tempfile as _co_tmp
_CO_BIN = _co_sh.which("codex") or os.path.expanduser("~/.local/bin/codex")
_co_lock = threading.Lock()
_co = {"proc": None, "url": "", "codigo": "", "inicio": 0.0, "erro": "", "status_t": 0.0, "logado": False}
_co_exec_sem = threading.Semaphore(1)   # 1 vCPU: uma chamada por vez
_CO_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_CO_URL = re.compile(r"https://auth\.openai\.com/\S+")
_CO_COD = re.compile(r"^[A-Z0-9]{4}-[A-Z0-9]{4,6}$")


def _co_instalado():
    return bool(_CO_BIN) and os.path.isfile(_CO_BIN) and os.access(_CO_BIN, os.X_OK)


def _co_logado(forcar=False):
    with _co_lock:
        if not forcar and time.time() - _co["status_t"] < 15:
            return _co["logado"]
    ok = False
    if _co_instalado():
        try:
            r = _co_sp.run([_CO_BIN, "login", "status"], capture_output=True, text=True, timeout=20, stdin=_co_sp.DEVNULL)
            ok = r.returncode == 0 and "not logged" not in (r.stdout + r.stderr).lower()
        except Exception:
            ok = False
    with _co_lock:
        _co.update(logado=ok, status_t=time.time())
    return ok


def _co_definir_provedor(prov):
    cfg = _cfg_painel()
    cfg.setdefault("ia", {})["provedor"] = prov
    tmp = CONFIG_PAINEL + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG_PAINEL)


def _co_ler_login(proc):
    try:
        for linha in proc.stdout:
            l = _CO_ANSI.sub("", linha).strip()
            m = _CO_URL.search(l)
            with _co_lock:
                if m and not _co["url"]:
                    _co["url"] = m.group(0)
                if _CO_COD.match(l):
                    _co["codigo"] = l
        rc = proc.wait()
    except Exception as ex:
        rc = -1
        print("[conta-openai] leitura do login:", ex, flush=True)
    with _co_lock:
        _co["proc"] = None
        _co["status_t"] = 0.0
    if rc == 0 and _co_logado(True):
        _co_definir_provedor("chatgpt")
        print("[conta-openai] conta OpenAI conectada pelo login por código", flush=True)
    else:
        with _co_lock:
            if not _co["erro"]:
                _co["erro"] = "O login não foi concluído (o código expirou ou foi cancelado). Tente de novo."


def co_status():
    with _co_lock:
        and_ = _co["proc"] is not None
        d = {"instalado": _co_instalado(), "em_andamento": and_, "url": _co["url"] if and_ else "", "codigo": _co["codigo"] if and_ else "",
             "expira_em": max(0, int(_co["inicio"] + 900 - time.time())) if and_ else 0, "erro": _co["erro"]}
    d["conectado"] = _co_logado()
    d["provedor"] = _ia_cfg().get("provedor", "")
    d["success"] = True
    return d


def co_acao(dados):
    acao = str(dados.get("acao") or "")
    if acao not in ("entrar", "cancelar", "sair", "usar"):
        raise ErroEnvio("ação inválida")
    if not _co_instalado():
        raise ErroEnvio("o Codex (login da conta OpenAI) não está instalado neste servidor")
    if acao == "entrar":
        if _co_logado(True):
            _co_definir_provedor("chatgpt")
            return co_status()
        with _co_lock:
            if _co["proc"] is None:
                _co.update(url="", codigo="", erro="", inicio=time.time())
                p = _co_sp.Popen([_CO_BIN, "login", "--device-auth"], stdout=_co_sp.PIPE, stderr=_co_sp.STDOUT, stdin=_co_sp.DEVNULL,
                                 text=True, encoding="utf-8", errors="replace")
                _co["proc"] = p
                threading.Thread(target=_co_ler_login, args=(p,), daemon=True, name="conta-openai-login").start()

                def _matar(p_=p):
                    time.sleep(940)
                    if p_.poll() is None:
                        p_.terminate()
                threading.Thread(target=_matar, daemon=True).start()
        for _ in range(40):  # espera o link e o código aparecerem (até ~8 s)
            with _co_lock:
                if (_co["url"] and _co["codigo"]) or _co["proc"] is None:
                    break
            time.sleep(0.2)
        return co_status()
    if acao == "cancelar":
        with _co_lock:
            p = _co["proc"]
        if p and p.poll() is None:
            p.terminate()
        with _co_lock:
            _co["erro"] = ""
        return co_status()
    if acao == "sair":
        try:
            _co_sp.run([_CO_BIN, "logout"], capture_output=True, text=True, timeout=20, stdin=_co_sp.DEVNULL)
        except Exception:
            pass
        if _ia_cfg().get("provedor") == "chatgpt":
            _co_definir_provedor("")
        with _co_lock:
            _co["status_t"] = 0.0
        return co_status()
    if not _co_logado(True):  # usar
        raise ErroEnvio("entre com a conta OpenAI primeiro")
    _co_definir_provedor("chatgpt")
    return co_status()


def _co_exec(instrucao, conteudo):
    if not _co_instalado():
        raise ErroEnvio("o Codex não está instalado neste servidor")
    if not _co_logado():
        raise ErroEnvio("entre com a sua conta OpenAI em Integrações (IA)")
    prompt = (IA_SISTEMA + "\n\n" + conteudo + "\n\n" + instrucao +
              "\n\nIMPORTANTE: responda apenas com o texto pedido, em português do Brasil. Não rode comandos e não leia nem crie arquivos.")
    if not _co_exec_sem.acquire(timeout=90):
        raise ErroEnvio("a IA está ocupada; tente de novo em instantes", 429)
    try:
        with _co_tmp.TemporaryDirectory(prefix="painel-codex-") as d:
            saida = os.path.join(d, "resposta.txt")
            cmd = [_CO_BIN, "exec", "--skip-git-repo-check", "--ephemeral", "--sandbox", "read-only", "--color", "never",
                   "-C", d, "-o", saida, "-c", 'model_reasoning_effort="low"', "-"]
            try:
                r = _co_sp.run(cmd, input=prompt, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
            except _co_sp.TimeoutExpired:
                raise ErroEnvio("a IA demorou demais para responder; tente de novo", 504)
            txt = ""
            if os.path.exists(saida):
                with open(saida, encoding="utf-8", errors="replace") as f:
                    txt = f.read().strip()
            if r.returncode != 0 or not txt:
                err = _CO_ANSI.sub("", (r.stderr or "") + (r.stdout or ""))[-600:].lower()
                print("[conta-openai] codex exec falhou rc=%s: %s" % (r.returncode, err[-300:].replace("\n", " ")), flush=True)
                if "usage limit" in err or "rate limit" in err or "429" in err or "quota" in err:
                    raise ErroEnvio("limite de uso do seu plano da OpenAI atingido; tente mais tarde", 429)
                if "login" in err or "401" in err or "unauthorized" in err or "auth" in err:
                    with _co_lock:
                        _co["status_t"] = 0.0
                    raise ErroEnvio("a conta OpenAI desconectou; entre de novo em Integrações (IA)", 400)
                raise ErroEnvio("a IA (conta OpenAI) não respondeu; tente de novo", 502)
            return txt
    finally:
        _co_exec_sem.release()


_co_ia_chamar0 = ia_chamar


def ia_chamar(instrucao, conteudo, max_tokens=2000):  # noqa: F811 — embrulha: provedor "chatgpt" usa a conta, o resto segue igual
    if _ia_cfg().get("provedor") == "chatgpt":
        return _co_exec(instrucao, conteudo)
    return _co_ia_chamar0(instrucao, conteudo, max_tokens)


_co_pub0 = ia_config_publica


def ia_config_publica():  # noqa: F811
    d = _co_pub0()
    con = _co_logado()
    d["conta_openai"] = {"instalado": _co_instalado(), "conectado": con}
    if d.get("provedor") == "chatgpt":
        d["ativa"] = con
    return d


_co_salvar0 = ia_salvar


def ia_salvar(dados):  # noqa: F811
    if str(dados.get("provedor") or "") == "chatgpt":
        if not _co_logado(True):
            raise ErroEnvio("entre com a conta OpenAI primeiro (botão no cartão Conta OpenAI)")
        _co_definir_provedor("chatgpt")
        return {"success": True, **ia_config_publica()}
    return _co_salvar0(dados)


def _co_do_GET(self):
    if urlparse(self.path).path != "/api/ia/conta":
        return _co_get0(self)
    if not self.portaria(post=False) or not _pa_autorizado(self):
        return
    return self.json(co_status())


def _co_do_POST(self):
    if urlparse(self.path).path != "/api/ia/conta":
        return _co_post0(self)
    if not self.portaria(post=True):
        return
    try:
        if not _pa_autorizado(self):
            self.close_connection = True
            return
        dados = _pa_corpo(self)
        print("[conta-openai] acao=%s ip=%s" % (str(dados.get("acao"))[:10], self.client_address[0]), flush=True)
        return self.json(co_acao(dados))
    except ErroEnvio as e:
        return self.json({"success": False, "erro": str(e)}, getattr(e, "code", 400) or 400)
    except Exception as e:
        print("[conta-openai] erro:", type(e).__name__, e, flush=True)
        return self.json({"success": False, "erro": "erro interno ao falar com o Codex"}, 500)


_co_get0 = Handler.do_GET
_co_post0 = Handler.do_POST
Handler.do_GET = _co_do_GET
Handler.do_POST = _co_do_POST
# ---------- fim [conta-openai] ----------

# ---------- [conta-claude] entrar com a conta do Claude (Claude Code: claude setup-token) e usar o plano no lugar da chave de API ----------
import pty as _cc_pty, fcntl as _cc_fcntl, termios as _cc_termios, struct as _cc_struct, signal as _cc_signal
_CC_BIN = _co_sh.which("claude") or os.path.expanduser("~/.local/bin/claude")
_cc_lock = threading.Lock()
_cc = {"pid": None, "fd": None, "url": "", "inicio": 0.0, "erro": "", "buf": "", "codigo_enviado": False}
_cc_exec_sem = threading.Semaphore(1)
_CC_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_CC_CSI = re.compile(r"\x1b\[[0-9;?<>=]*[ -/]*[@-~]|\x1b[=>78NOPc]")
_CC_URLRE = re.compile(r"https://claude\.ai/oauth/authorize\?[A-Za-z0-9%&=._~+\-]+")
_CC_TOKRE = re.compile(r"sk-ant-oat\d{2}-[A-Za-z0-9_\-]{40,}(?=[^A-Za-z0-9_\-])")


def _cc_instalado():
    return bool(_CC_BIN) and os.path.isfile(os.path.realpath(_CC_BIN)) and os.access(_CC_BIN, os.X_OK)


def _cc_token():
    return str(_ia_cfg().get("claude_oauth") or "")


def _cc_gravar(**campos):
    cfg = _cfg_painel()
    ia = cfg.setdefault("ia", {})
    for k, v in campos.items():
        if v is None:
            ia.pop(k, None)
        else:
            ia[k] = v
    tmp = CONFIG_PAINEL + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG_PAINEL)


def _cc_limpo(t):
    return _CC_CSI.sub("", _CC_OSC.sub("", t))


def _cc_matar():
    with _cc_lock:
        pid, fd = _cc["pid"], _cc["fd"]
        _cc.update(pid=None, fd=None)
    if pid:
        try:
            os.kill(pid, _cc_signal.SIGTERM)
        except OSError:
            pass
        try:
            os.waitpid(pid, os.WNOHANG)
        except OSError:
            pass
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass


def _cc_leitor(pid, fd):
    fim = time.time() + 900
    while time.time() < fim:
        try:
            dado = os.read(fd, 4096)
        except OSError:
            break
        if not dado:
            break
        texto = dado.decode("utf-8", errors="replace")
        with _cc_lock:
            if _cc["pid"] != pid:
                return
            _cc["buf"] = (_cc["buf"] + texto)[-40000:]
            bruto = _cc["buf"]
        if not _cc["url"]:
            m = _CC_URLRE.search(_cc_limpo(bruto)) or _CC_URLRE.search(bruto)
            if m:
                with _cc_lock:
                    _cc["url"] = m.group(0)
        tok = _CC_TOKRE.search(_cc_limpo(bruto))
        if tok:
            _cc_gravar(claude_oauth=tok.group(0), provedor="claude_conta")
            print("[conta-claude] conta Claude conectada (token de longa duração guardado só no config.json)", flush=True)
            with _cc_lock:
                _cc.update(erro="", buf="")
            _cc_matar()
            return
    with _cc_lock:
        mesmo = _cc["pid"] == pid
        if mesmo and not _cc["erro"]:
            fim_txt = _cc_limpo(_cc["buf"])[-400:].lower()
            _cc["erro"] = ("O código não foi aceito. Gere um novo login e cole o código inteiro." if ("invalid" in fim_txt or "error" in fim_txt)
                           else "O login não foi concluído. Tente de novo.")
            _cc["buf"] = ""
    if mesmo:
        _cc_matar()


def cc_status():
    with _cc_lock:
        and_ = _cc["pid"] is not None
        d = {"instalado": _cc_instalado(), "em_andamento": and_, "url": _cc["url"] if and_ else "",
             "codigo_enviado": _cc["codigo_enviado"] if and_ else False, "erro": _cc["erro"],
             "expira_em": max(0, int(_cc["inicio"] + 900 - time.time())) if and_ else 0}
    d["conectado"] = bool(_cc_token())
    d["provedor"] = _ia_cfg().get("provedor", "")
    d["success"] = True
    return d


def cc_acao(dados):
    acao = str(dados.get("acao") or "")
    if acao not in ("entrar", "codigo", "cancelar", "sair", "usar"):
        raise ErroEnvio("ação inválida")
    if not _cc_instalado():
        raise ErroEnvio("o Claude Code (login da conta Claude) não está instalado neste servidor")
    if acao == "entrar":
        with _cc_lock:
            rodando = _cc["pid"] is not None
        if not rodando:
            pid, fd = _cc_pty.fork()
            if pid == 0:  # filho: terminal largo para o link e o token não quebrarem em linhas
                try:
                    _cc_fcntl.ioctl(1, _cc_termios.TIOCSWINSZ, _cc_struct.pack("HHHH", 50, 500, 0, 0))
                except Exception:
                    pass
                env = dict(os.environ, TERM="xterm-256color", COLUMNS="500", LINES="50", NO_COLOR="1", BROWSER="true")
                os.execve(os.path.realpath(_CC_BIN), [_CC_BIN, "setup-token"], env)
            with _cc_lock:
                _cc.update(pid=pid, fd=fd, url="", erro="", buf="", inicio=time.time(), codigo_enviado=False)
            threading.Thread(target=_cc_leitor, args=(pid, fd), daemon=True, name="conta-claude-login").start()
        for _ in range(60):  # até ~12 s pelo link
            with _cc_lock:
                if _cc["url"] or _cc["pid"] is None:
                    break
            time.sleep(0.2)
        return cc_status()
    if acao == "codigo":
        cod = re.sub(r"\s+", "", str(dados.get("codigo") or ""))
        if not re.fullmatch(r"[A-Za-z0-9#_\-.]{8,400}", cod):
            raise ErroEnvio("código inválido: copie o código inteiro que aparece na página do Claude")
        with _cc_lock:
            fd = _cc["fd"]
            if fd is None:
                raise ErroEnvio("o login expirou; clique em Entrar de novo")
            _cc["codigo_enviado"] = True
        os.write(fd, cod.encode())  # o Ink trata texto+Enter num pedaço só como colagem: Enter vai separado
        time.sleep(0.6)
        os.write(fd, b"\r")
        def _cc_diag(fd_=fd):
            for espera in (3, 8, 15):
                time.sleep(espera)
                if _cc_token():
                    return
                with _cc_lock:
                    if _cc["fd"] != fd_:
                        return
                    tela = re.sub(r"\s+", " ", _cc_limpo(_cc["buf"]))[-220:]
                print("[conta-claude] após o código (%ss): %s" % (espera, _CC_TOKRE.sub("sk-ant-***", tela)), flush=True)
                if espera == 3:
                    try:
                        os.write(fd_, b"\r")  # um segundo Enter, se o primeiro não pegou
                    except OSError:
                        return
        threading.Thread(target=_cc_diag, daemon=True).start()
        for _ in range(100):  # até ~20 s pelo token
            if _cc_token() and _ia_cfg().get("provedor") == "claude_conta":
                break
            with _cc_lock:
                if _cc["pid"] is None:
                    break
            time.sleep(0.2)
        return cc_status()
    if acao == "cancelar":
        _cc_matar()
        with _cc_lock:
            _cc["erro"] = ""
        return cc_status()
    if acao == "sair":
        _cc_matar()
        prov = _ia_cfg().get("provedor")
        _cc_gravar(claude_oauth=None, **({"provedor": ""} if prov == "claude_conta" else {}))
        return cc_status()
    if not _cc_token():  # usar
        raise ErroEnvio("entre com a conta Claude primeiro")
    _cc_gravar(provedor="claude_conta")
    return cc_status()


def _cc_exec(instrucao, conteudo):
    tok = _cc_token()
    if not _cc_instalado():
        raise ErroEnvio("o Claude Code não está instalado neste servidor")
    if not tok:
        raise ErroEnvio("entre com a sua conta Claude em Integrações (IA)")
    prompt = (IA_SISTEMA + "\n\n" + conteudo + "\n\n" + instrucao +
              "\n\nIMPORTANTE: responda apenas com o texto pedido, em português do Brasil. Não use ferramentas e não leia nem crie arquivos.")
    if not _cc_exec_sem.acquire(timeout=90):
        raise ErroEnvio("a IA está ocupada; tente de novo em instantes", 429)
    try:
        with _co_tmp.TemporaryDirectory(prefix="painel-claude-") as d:
            env = dict(os.environ, CLAUDE_CODE_OAUTH_TOKEN=tok, NO_COLOR="1", DISABLE_AUTOUPDATER="1")
            env.pop("ANTHROPIC_API_KEY", None)
            cmd = [os.path.realpath(_CC_BIN), "-p", "--output-format", "text", "--permission-mode", "default",
                   "--disallowedTools", "Bash,Edit,Write,Read,Glob,Grep,WebFetch,WebSearch,NotebookEdit,Task,TodoWrite"]
            try:
                r = _co_sp.run(cmd, input=prompt, capture_output=True, text=True, encoding="utf-8", errors="replace",
                               timeout=180, cwd=d, env=env)
            except _co_sp.TimeoutExpired:
                raise ErroEnvio("a IA demorou demais para responder; tente de novo", 504)
            txt = (r.stdout or "").strip()
            if r.returncode != 0 or not txt:
                err = ((r.stderr or "") + (r.stdout or ""))[-600:].lower()
                print("[conta-claude] claude -p falhou rc=%s: %s" % (r.returncode, err[-300:].replace("\n", " ")), flush=True)
                if "rate limit" in err or "usage limit" in err or "429" in err or "limit reached" in err:
                    raise ErroEnvio("limite de uso do seu plano do Claude atingido; tente mais tarde", 429)
                if "401" in err or "invalid" in err or "oauth" in err or "unauthorized" in err or "expired" in err:
                    _cc_gravar(claude_oauth=None, provedor=("chatgpt" if _co_logado() else ""))
                    raise ErroEnvio("a conta Claude desconectou; entre de novo em Integrações (IA)", 400)
                raise ErroEnvio("a IA (conta Claude) não respondeu; tente de novo", 502)
            return txt
    finally:
        _cc_exec_sem.release()


_cc_ia_chamar0 = ia_chamar


def ia_chamar(instrucao, conteudo, max_tokens=2000):  # noqa: F811
    if _ia_cfg().get("provedor") == "claude_conta":
        return _cc_exec(instrucao, conteudo)
    return _cc_ia_chamar0(instrucao, conteudo, max_tokens)


_cc_pub0 = ia_config_publica


def ia_config_publica():  # noqa: F811
    d = _cc_pub0()
    con = bool(_cc_token())
    d["conta_claude"] = {"instalado": _cc_instalado(), "conectado": con}
    if d.get("provedor") == "claude_conta":
        d["ativa"] = con
    return d


_cc_salvar0 = ia_salvar


def ia_salvar(dados):  # noqa: F811
    if str(dados.get("provedor") or "") == "claude_conta":
        if not _cc_token():
            raise ErroEnvio("entre com a conta Claude primeiro (botão no cartão Conta Claude)")
        _cc_gravar(provedor="claude_conta")
        return {"success": True, **ia_config_publica()}
    return _cc_salvar0(dados)


def _cc_do_GET(self):
    if urlparse(self.path).path != "/api/ia/conta-claude":
        return _cc_get0(self)
    if not self.portaria(post=False) or not _pa_autorizado(self):
        return
    return self.json(cc_status())


def _cc_do_POST(self):
    if urlparse(self.path).path != "/api/ia/conta-claude":
        return _cc_post0(self)
    if not self.portaria(post=True):
        return
    try:
        if not _pa_autorizado(self):
            self.close_connection = True
            return
        dados = _pa_corpo(self)
        print("[conta-claude] acao=%s ip=%s" % (str(dados.get("acao"))[:10], self.client_address[0]), flush=True)
        return self.json(cc_acao(dados))
    except ErroEnvio as e:
        return self.json({"success": False, "erro": str(e)}, getattr(e, "code", 400) or 400)
    except Exception as e:
        print("[conta-claude] erro:", type(e).__name__, e, flush=True)
        return self.json({"success": False, "erro": "erro interno ao falar com o Claude Code"}, 500)


_cc_get0 = Handler.do_GET
_cc_post0 = Handler.do_POST
Handler.do_GET = _cc_do_GET
Handler.do_POST = _cc_do_POST
# ---------- fim [conta-claude] ----------

from crm import instalar_crm
instalar_crm(Handler, globals())

if __name__ == "__main__":
    import socket, sys

    if "--nova-senha" in sys.argv:
        i = sys.argv.index("--nova-senha")
        nova = sys.argv[i + 1] if len(sys.argv) > i + 1 else gerar_senha()
        if len(nova) < 8:
            print("A senha precisa ter pelo menos 8 caracteres.")
            sys.exit(1)
        definir_senha(nova)
        registrar("senha_trocada", origem="terminal")
        print("Senha trocada. Veja", ACESSO_TXT)
        sys.exit(0)
    if not _cfg_painel().get("senha_hash"):
        definir_senha(gerar_senha())  # primeira vez: senha forte aleatória, anotada em ACESSO.txt

    CTX_TLS = None if PROXY else preparar_https()  # atrás do proxy o TLS é do NPM
    HTTPS_ATIVO = bool(CTX_TLS)

    class Servidor(ThreadingHTTPServer):
        daemon_threads = True

        address_family = socket.AF_INET6 if HOST in ("0.0.0.0", "::") and socket.has_ipv6 else socket.AF_INET

        def finish_request(self, request, client_address):
            # roda na thread da conexão: um aparelho "parado" não trava o painel para os outros
            if CTX_TLS:
                try:
                    request.settimeout(10)
                    if request.recv(1, socket.MSG_PEEK) == b"\x16":  # handshake TLS: é https
                        request = CTX_TLS.wrap_socket(request, server_side=True)
                    request.settimeout(None)
                except (OSError, ValueError):
                    try:
                        request.close()
                    except OSError:
                        pass
                    return
            super().finish_request(request, client_address)
        # [reuso] Linux: SO_REUSEADDR só ignora conexões em TIME_WAIT (não deixa dois programas escutarem juntos);
        # sem ele, todo reinício esperava ~60 s pelas conexões keep-alive do proxy. No Windows segue desligado.
        allow_reuse_address = os.name != "nt"
        allow_reuse_port = False

        def handle_error(self, request, client_address):
            # [semreset] proxy/navegador que fecha a conexão keep-alive (ex.: no reinício) não é erro: sem traceback no journal
            if isinstance(sys.exc_info()[1], (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, TimeoutError)):
                return
            super().handle_error(request, client_address)

        def server_bind(self):
            if self.address_family == socket.AF_INET6:  # escuta IPv4 e IPv6 (localhost no Windows tenta ::1 primeiro)
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            super().server_bind()

    try:
        srv = Servidor(("::" if Servidor.address_family == socket.AF_INET6 else HOST, PORT), Handler)
    except OSError as e:
        print(f"ERRO: a porta {PORT} já está em uso por outro programa ({e}). Feche-o e tente de novo.")
        registrar("partida_falhou", porta=PORT, motivo="porta em uso")
        sys.exit(1)
    try:
        bloqueios_do_log()  # [segpers]
    except Exception:
        pass
    registrar("partida", escuta=",".join(HOSTS), porta=PORT, https="sim" if HTTPS_ATIVO else "nao", pid=os.getpid())
    print(f"Painel do WhatsApp em http://localhost:{PORT}  (rede local com senha: veja ACESSO.txt; Ctrl+C para parar)")
    _sessoes_carregar()
    avatar_limpar_antigos()  # cache de fotos: tira o que ninguém pediu no último mês
    threading.Thread(target=avatar_aquecer, daemon=True).start()  # fotos do disco para a memória (sem ponte)
    threading.Thread(target=_vigiar_ponte, daemon=True).start()
    threading.Thread(target=_agendador, daemon=True).start()
    threading.Thread(target=_campanhas_loop, daemon=True).start()  # [campanhas] só envia campanhas ligadas pelo operador
    threading.Thread(target=_limpeza, daemon=True).start()
    threading.Thread(target=_backup, daemon=True).start()
    threading.Thread(target=_autonomia, daemon=True).start()  # [autonomia] só etiqueta; nunca envia
    threading.Thread(target=_rasc_cobranca, daemon=True).start()  # [rascunhos] só cria rascunho; nunca envia

    def _escutar_extra(h):  # [escutaip] endereço extra; tenta de novo até a interface aparecer
        fam = socket.AF_INET6 if ":" in h else socket.AF_INET
        cls = type("ServidorExtra", (Servidor,), {"address_family": fam})
        espera, avisou = 5, False
        while True:
            try:
                s2 = cls((h, PORT), Handler)
                break
            except OSError as e:
                if not avisou:
                    registrar("escuta_espera", escuta=h, porta=PORT, motivo=str(e)[:80])
                    avisou = True
                time.sleep(espera)
                espera = min(espera * 2, 60)
        if avisou:
            registrar("escuta_ok", escuta=h, porta=PORT)
        s2.serve_forever()

    for _h in HOSTS[1:]:
        threading.Thread(target=_escutar_extra, args=(_h,), daemon=True).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
