package main

// Pareamento sob demanda (QR) e "retomar sessão", sem encerrar o processo.
//
// Estados do pareamento (pair_state): idle | qr | paired | expired | error
// Estados de conexão (connState, /api/me e /api/pair/status): starting, connected, disconnected, replaced,
// loggedout, unpaired, reconnecting, banned, failed, outdated.
//
// Endpoints (somente 127.0.0.1, atrás do guardLocal):
//   GET  /api/pair/status   GET /api/pair/qr.png   POST /api/pair/start {force}   POST /api/pair/cancel
//   POST /api/reconnect

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mdp/qrterminal"
	qrcode "github.com/skip2/go-qrcode"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store/sqlstore"
	waLog "go.mau.fi/whatsmeow/util/log"
)

const (
	pairMinGap     = 8 * time.Second
	pairMaxPerHour = 12
	pairQRFile     = "qr.png"
	pairLogPrefix  = "[pareamento] "
)

// configuração por ambiente (testes nunca tocam o store real)
var storeDir = envOr("BRIDGE_STORE", "store")

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func bridgePort() int {
	if v := os.Getenv("BRIDGE_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			return n
		}
	}
	return 8080
}

var (
	pairClient    *whatsmeow.Client
	waContainer   *sqlstore.Container // para recriar o dispositivo depois de um logout
	pairLogger    waLog.Logger
	pm            pairMachine
	reconnectBusy atomic.Bool
)

type pairMachine struct {
	mu          sync.Mutex
	state       string // idle|qr|paired|expired|error
	active      bool   // tentativa em andamento
	gen         int    // identifica a tentativa (goroutines antigas não escrevem)
	cancel      context.CancelFunc
	code        string
	png         []byte
	generatedAt time.Time
	expiresAt   time.Time
	errMsg      string
	starts      []time.Time
}

func pairingActive() bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.active
}

func pairState() string {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.state == "" {
		return "idle"
	}
	return pm.state
}

func plog(format string, a ...any) { fmt.Printf(pairLogPrefix+format+"\n", a...) }

// ---------- decisões puras (testáveis) ----------

type decisaoIn struct {
	LoggedIn bool
	Force    bool
	Active   bool
	Now      time.Time
	Starts   []time.Time // inícios anteriores (qualquer idade)
}

type decisao struct {
	OK     bool
	Code   int // HTTP quando !OK
	Msg    string
	Logout bool // precisa desvincular o aparelho atual antes (force)
}

func decidirInicio(in decisaoIn) decisao {
	if in.Active {
		return decisao{Code: 409, Msg: "Já existe um pareamento em andamento. Cancele ou aguarde o QR expirar."}
	}
	if in.LoggedIn && !in.Force {
		return decisao{Code: 409, Msg: "Este número já está conectado. Parear de novo desvincula o aparelho no celular; use force=true somente com confirmação."}
	}
	var last time.Time
	n := 0
	for _, t := range in.Starts {
		if in.Now.Sub(t) < time.Hour {
			n++
		}
		if t.After(last) {
			last = t
		}
	}
	if !last.IsZero() && in.Now.Sub(last) < pairMinGap {
		return decisao{Code: 429, Msg: "Aguarde alguns segundos antes de gerar outro QR."}
	}
	if n >= pairMaxPerHour {
		return decisao{Code: 429, Msg: "Limite de tentativas de pareamento por hora atingido. Tente mais tarde."}
	}
	return decisao{OK: true, Logout: in.LoggedIn && in.Force}
}

func decidirReconexao(loggedIn, pairing bool) (int, string) {
	if pairing {
		return 409, "Pareamento em andamento: conclua ou cancele antes de retomar a sessão."
	}
	if !loggedIn {
		return 409, "Não há sessão vinculada neste servidor; faça o pareamento (QR)."
	}
	return 0, ""
}

// ---------- dispositivo ----------

// resetDevice deixa client.Store como um dispositivo novo e não vinculado (o whatsmeow marca o antigo como
// Deleted após logout, o que impediria um novo pareamento no mesmo processo).
func resetDevice(client *whatsmeow.Client) {
	if waContainer == nil {
		return
	}
	if client.Store.ID != nil || client.Store.Deleted {
		*client.Store = *waContainer.NewDevice()
	}
}

// handleLoggedOut: chamado pelo evento LoggedOut. Mantém o processo vivo; nenhum QR automático.
func handleLoggedOut(client *whatsmeow.Client, q *eventQueue, logger waLog.Logger) {
	logger.Warnf("Device logged out; keeping process alive, pairing is on demand (POST /api/pair/start)")
	q.flush(5 * time.Second) // grava o que já chegou
	_ = client.Store.Delete(context.Background())
	connMu.Lock()
	noReconnect = true
	retryAfter = time.Time{}
	connMu.Unlock()
	if !pairingActive() {
		resetDevice(client)
		setConnState("loggedout", "aparelho desvinculado no celular; pareie novamente")
	}
}

// ---------- pareamento ----------

// iniciarPareamento devolve (httpCode, mensagem). httpCode 0 = iniciado.
func iniciarPareamento(force bool) (int, string) {
	client := pairClient
	if client == nil {
		return 500, "cliente não inicializado"
	}
	pm.mu.Lock()
	d := decidirInicio(decisaoIn{LoggedIn: client.Store.ID != nil, Force: force, Active: pm.active, Now: time.Now(), Starts: pm.starts})
	if !d.OK {
		pm.mu.Unlock()
		plog("start recusado (%d): %s", d.Code, d.Msg)
		return d.Code, d.Msg
	}
	now := time.Now()
	keep := pm.starts[:0]
	for _, t := range pm.starts {
		if now.Sub(t) < time.Hour {
			keep = append(keep, t)
		}
	}
	pm.starts = append(keep, now)
	pm.active = true
	pm.gen++
	gen := pm.gen
	pm.state, pm.code, pm.png, pm.errMsg = "idle", "", nil, ""
	pm.generatedAt, pm.expiresAt = time.Time{}, time.Time{}
	pm.mu.Unlock()

	fail := func(code int, msg string) (int, string) {
		pm.mu.Lock()
		if pm.gen == gen {
			pm.active, pm.state, pm.errMsg = false, "error", msg
		}
		pm.mu.Unlock()
		plog("falha ao iniciar: %s", msg)
		return code, msg
	}

	if d.Logout {
		plog("force=true: desvinculando o aparelho atual (client.Logout)")
		if err := client.Logout(context.Background()); err != nil {
			plog("Logout falhou (%v); removendo sessão local mesmo assim (o aparelho pode continuar listado no celular)", err)
			client.Disconnect()
			_ = client.Store.Delete(context.Background())
		}
	}
	if client.IsConnected() {
		client.Disconnect()
	}
	resetDevice(client)
	setConnState("unpaired", "aguardando leitura do QR")

	ctx, cancel := context.WithCancel(context.Background())
	qrChan, err := client.GetQRChannel(ctx)
	if err != nil {
		cancel()
		return fail(500, "não foi possível preparar o QR: "+err.Error())
	}
	if err := client.Connect(); err != nil {
		cancel()
		client.Disconnect()
		return fail(502, "falha ao conectar ao WhatsApp: "+err.Error())
	}
	pm.mu.Lock()
	pm.cancel = cancel
	pm.mu.Unlock()
	plog("pareamento iniciado (tentativa %d na última hora)", len(pm.starts))
	go consumirQR(client, qrChan, ctx, cancel, gen)
	return 0, "pareamento iniciado"
}

func consumirQR(client *whatsmeow.Client, ch <-chan whatsmeow.QRChannelItem, ctx context.Context, cancel context.CancelFunc, gen int) {
	defer cancel()
	first := true
	final := func(state, msg string) {
		pm.mu.Lock()
		if pm.gen == gen {
			pm.active, pm.state, pm.errMsg = false, state, msg
			pm.code, pm.png = "", nil
		}
		pm.mu.Unlock()
	}
	for item := range ch {
		pm.mu.Lock()
		stale := pm.gen != gen
		pm.mu.Unlock()
		if stale {
			return
		}
		switch item.Event {
		case "code":
			png, err := qrcode.Encode(item.Code, qrcode.Medium, 512)
			if err != nil {
				plog("erro ao gerar PNG: %v", err)
				continue
			}
			now := time.Now()
			pm.mu.Lock()
			pm.state, pm.code, pm.png = "qr", item.Code, png
			pm.generatedAt, pm.expiresAt = now, now.Add(item.Timeout)
			pm.mu.Unlock()
			_ = os.WriteFile(pairQRFile, png, 0o644) // compatibilidade com o painel antigo
			if first {
				first = false
				fmt.Println("\nScan this QR code with your WhatsApp app:")
				qrterminal.GenerateHalfBlock(item.Code, qrterminal.L, os.Stdout)
			}
			plog("novo QR (válido por %s)", item.Timeout.Round(time.Second))
		case "success":
			final("paired", "")
			_ = os.Remove(pairQRFile)
			setConnState("connected", "")
			connMu.Lock()
			noReconnect, retryAfter = false, time.Time{}
			connMu.Unlock()
			plog("pareado com sucesso")
			return
		case "timeout":
			final("expired", "QR expirou sem leitura")
			_ = os.Remove(pairQRFile)
			setConnState("unpaired", "QR expirado")
			plog("QR expirou")
			return
		case "error":
			msg := "erro no pareamento"
			if item.Error != nil {
				msg = item.Error.Error()
			}
			final("error", msg)
			_ = os.Remove(pairQRFile)
			setConnState("unpaired", msg)
			plog("erro: %s", msg)
			return
		default:
			if len(item.Event) > 4 && item.Event[:4] == "err-" {
				final("error", item.Event)
				_ = os.Remove(pairQRFile)
				client.Disconnect()
				setConnState("unpaired", item.Event)
				plog("erro: %s", item.Event)
				return
			}
			plog("evento ignorado: %s", item.Event)
		}
	}
	// canal fechado sem evento final
	pm.mu.Lock()
	still := pm.gen == gen && pm.active
	pm.mu.Unlock()
	if still {
		final("expired", "canal de QR encerrado")
		_ = os.Remove(pairQRFile)
		if client.Store.ID == nil {
			setConnState("unpaired", "QR encerrado")
		}
	}
}

func cancelarPareamento() bool {
	pm.mu.Lock()
	was := pm.active
	cancel := pm.cancel
	pm.gen++ // invalida a goroutine
	pm.active, pm.state, pm.code, pm.png, pm.errMsg = false, "idle", "", nil, ""
	pm.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if was {
		if pairClient != nil && pairClient.Store.ID == nil {
			pairClient.Disconnect()
			setConnState("unpaired", "pareamento cancelado")
		}
		_ = os.Remove(pairQRFile)
	}
	return was
}

// ---------- retomar sessão ----------

func retomarSessao(client *whatsmeow.Client, logger waLog.Logger) (int, string) {
	if code, msg := decidirReconexao(client.Store.ID != nil, pairingActive()); code != 0 {
		return code, msg
	}
	if !reconnectBusy.CompareAndSwap(false, true) {
		return 0, "já existe uma reconexão em andamento"
	}
	client.Disconnect()
	connMu.Lock()
	retryAfter, noReconnect = time.Time{}, false
	connMu.Unlock()
	setConnState("reconnecting", "retomada manual")
	go func() {
		defer reconnectBusy.Store(false)
		connectWithRetry(client, logger)
	}()
	return 0, "reconectando"
}

// ---------- REST ----------

func registerPareamento(client *whatsmeow.Client, store *MessageStore) {
	pairClient = client
	pairLogger = waLog.Stdout("Pareamento", "INFO", true)

	http.HandleFunc("/api/pair/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			fail(w, http.StatusMethodNotAllowed, "GET only")
			return
		}
		cs, reason, _ := connStatus()
		now := time.Now()
		pm.mu.Lock()
		st := pm.state
		if st == "" {
			st = "idle"
		}
		hasQR := len(pm.png) > 0
		out := map[string]interface{}{
			"success": true, "state": st, "active": pm.active,
			"conn_state": cs, "conn_reason": reason,
			"logged_in": client.Store.ID != nil, "has_qr": hasQR,
			"qr_age_s": 0, "expires_in_s": 0,
		}
		if hasQR {
			out["qr_age_s"] = int(now.Sub(pm.generatedAt).Seconds())
			if e := int(pm.expiresAt.Sub(now).Seconds()); e > 0 {
				out["expires_in_s"] = e
			}
			out["generated_at"] = pm.generatedAt.Unix()
			out["expires_at"] = pm.expiresAt.Unix()
			out["code"] = pm.code
		}
		if pm.errMsg != "" {
			out["message"] = pm.errMsg
		}
		n := 0
		for _, t := range pm.starts {
			if now.Sub(t) < time.Hour {
				n++
			}
		}
		out["attempts_hour"] = n
		pm.mu.Unlock()
		writeJSON(w, 200, out)
	})

	http.HandleFunc("/api/pair/qr.png", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			fail(w, http.StatusMethodNotAllowed, "GET only")
			return
		}
		pm.mu.Lock()
		png := pm.png
		pm.mu.Unlock()
		if len(png) == 0 {
			http.Error(w, "no qr", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(png)
	})

	http.HandleFunc("/api/pair/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fail(w, http.StatusMethodNotAllowed, "POST only")
			return
		}
		var req struct {
			Force bool `json:"force"`
		}
		if r.ContentLength != 0 {
			if !decodePost(w, r, &req) {
				return
			}
		}
		plog("POST /api/pair/start force=%v", req.Force)
		code, msg := iniciarPareamento(req.Force)
		if code != 0 {
			writeJSON(w, code, map[string]interface{}{"success": false, "message": msg})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"success": true, "message": msg, "state": pairState()})
	})

	http.HandleFunc("/api/pair/cancel", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fail(w, http.StatusMethodNotAllowed, "POST only")
			return
		}
		was := cancelarPareamento()
		plog("POST /api/pair/cancel (havia pareamento ativo: %v)", was)
		writeJSON(w, 200, map[string]interface{}{"success": true, "cancelled": was})
	})

	http.HandleFunc("/api/reconnect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fail(w, http.StatusMethodNotAllowed, "POST only")
			return
		}
		plog("POST /api/reconnect")
		code, msg := retomarSessao(client, pairLogger)
		if code != 0 {
			writeJSON(w, code, map[string]interface{}{"success": false, "message": msg})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"success": true, "message": msg, "conn_state": "reconnecting"})
	})
}
