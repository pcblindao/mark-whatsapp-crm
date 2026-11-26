package main

// Auditoria de envios (19/11/2026): toda ação que sai para o WhatsApp (envio, encaminhar, reação, edição, apagar)
// fica registrada em C:\Users\<user>\WhatsApp-Assistente\enviadas\auditoria\AAAA-MM-DD.jsonl com a ORIGEM:
// qual programa deste PC pediu (painel, sessão do Claude via MCP, script), hora, destino, texto e resultado.
// A origem vem do processo dono da conexão TCP (netstat), então não depende de quem chama se identificar;
// quem quiser pode mandar o cabeçalho X-Origem (ex.: "painel:agendada") para detalhar.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var auditTipos = map[string]string{
	"/api/send":    "envio",
	"/api/forward": "encaminhar",
	"/api/react":   "reacao",
	"/api/edit":    "edicao",
	"/api/revoke":  "apagar",
}

var auditMu sync.Mutex

type auditRec struct {
	http.ResponseWriter
	code int
	buf  bytes.Buffer
}

func (r *auditRec) WriteHeader(c int) { r.code = c; r.ResponseWriter.WriteHeader(c) }
func (r *auditRec) Write(b []byte) (int, error) {
	if r.buf.Len() < 600 {
		r.buf.Write(b[:min(len(b), 600-r.buf.Len())])
	}
	return r.ResponseWriter.Write(b)
}

func auditDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(storeDir, "auditoria")
	}
	return filepath.Join(home, "WhatsApp-Assistente", "enviadas", "auditoria")
}


type procInfo struct {
	Nome string `json:"nome,omitempty"`
	Cmd  string `json:"cmd,omitempty"`
	Pai  int    `json:"pai,omitempty"`
}


func classificarOrigem(hdr string, p, pai procInfo) string {
	if hdr != "" {
		return hdr
	}
	c := strings.ToLower(p.Cmd + " " + pai.Cmd)
	switch {
	case strings.Contains(c, `painel\server.py`) || strings.Contains(c, "painel/server.py"):
		return "painel"
	case strings.Contains(c, "whatsapp-mcp-server") || strings.Contains(c, "whatsapp_mcp"):
		return "sessao-claude (MCP)"
	case strings.Contains(c, "whatsapp-assistente\\") && strings.Contains(c, ".py"):
		for _, campo := range strings.Fields(p.Cmd) {
			if strings.HasSuffix(strings.ToLower(strings.Trim(campo, `"`)), ".py") {
				return "script:" + filepath.Base(strings.Trim(campo, `"`))
			}
		}
		return "script"
	case strings.Contains(c, "curl") || strings.Contains(c, "powershell") || strings.Contains(c, "invoke-webrequest"):
		return "linha-de-comando"
	case p.Nome != "":
		return "processo:" + p.Nome
	}
	return "desconhecida"
}

func auditar(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tipo, ok := auditTipos[r.URL.Path]
		if !ok || r.Method != http.MethodPost {
			h.ServeHTTP(w, r)
			return
		}
		corpo, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(corpo))
		pid := pidDoCliente(r.RemoteAddr) // enquanto a conexão está aberta
		infos := make(chan [2]procInfo, 1) // lê o processo JÁ (em paralelo ao envio): quem chamou ainda está vivo esperando a resposta
		go func() { defer func() { _ = recover() }(); p := infoProcesso(pid); infos <- [2]procInfo{p, infoProcesso(p.Pai)} }()
		hdr := strings.TrimSpace(r.Header.Get("X-Origem"))
		inicio := time.Now()
		rec := &auditRec{ResponseWriter: w, code: 200}
		h.ServeHTTP(rec, r)
		dur := time.Since(inicio)
		resp := rec.buf.String()
		go gravarAuditoria(tipo, corpo, pid, infos, hdr, rec.code, resp, inicio, dur)
	})
}

func gravarAuditoria(tipo string, corpo []byte, pid int, infos chan [2]procInfo, hdr string, code int, resp string, quando time.Time, dur time.Duration) {
	defer func() { _ = recover() }()
	var dados map[string]any
	_ = json.Unmarshal(corpo, &dados)
	pega := func(chaves ...string) string {
		for _, k := range chaves {
			if v, ok := dados[k]; ok && v != nil {
				if s := fmt.Sprint(v); s != "" {
					return s
				}
			}
		}
		return ""
	}
	var p, pai procInfo
	select {
	case par := <-infos:
		p, pai = par[0], par[1]
	case <-time.After(10 * time.Second):
	}
	var rj map[string]any
	_ = json.Unmarshal([]byte(resp), &rj)
	ok := code < 300
	if v, achou := rj["success"].(bool); achou {
		ok = ok && v
	}
	reg := map[string]any{
		"hora":     quando.Format("2006-01-02 15:04:05"),
		"tipo":     tipo,
		"para":     pega("recipient", "chat_jid"),
		"conversa": pega("chat_jid"),
		"texto":    pega("message", "emoji"),
		"midia":    pega("media_path"),
		"msg_id":   pega("message_id"),
		"origem":   classificarOrigem(hdr, p, pai),
		"pid":      pid,
		"processo": p,
		"pai":      pai,
		"ok":       ok,
		"http":     code,
		"ms":       dur.Milliseconds(),
	}
	if !ok {
		reg["resposta"] = resp
	} else if id, achou := rj["id"]; achou {
		reg["id_enviado"] = id
	}
	linha, err := json.Marshal(reg)
	if err != nil {
		return
	}
	dir := auditDir()
	auditMu.Lock()
	defer auditMu.Unlock()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, quando.Format("2006-01-02")+".jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(linha, '\n'))
	fmt.Printf("[auditoria] %s %s para=%s origem=%s ok=%v\n", reg["hora"], tipo, reg["para"], reg["origem"], ok)
}
