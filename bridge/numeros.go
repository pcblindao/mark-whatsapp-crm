package main

// Números clicáveis no painel (2026-11-20): GET /api/onwhatsapp?phone=NUMERO
// Pergunta ao WhatsApp (usync, client.IsOnWhatsApp) se o número tem conta e devolve o JID canônico
// (o WhatsApp corrige o 9º dígito de celulares antigos) e o LID. Só leitura: não envia nada, não cria chat.
// Freio próprio: no máximo onWAPorMinuto consultas novas por minuto (consultas em massa podem chamar a atenção
// do WhatsApp) e cache de 10 minutos por número.

import (
	"context"
	"net/http"
	"regexp"
	"sync"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/types"
)

const (
	onWAPorMinuto = 20
	onWACacheTTL  = 10 * time.Minute
)

var (
	onWAMu     sync.Mutex
	onWACache  = map[string]onWACacheItem{}
	onWAJanela []time.Time
	onWAFoneRe = regexp.MustCompile(`^[1-9][0-9]{9,14}$`)
)

type onWACacheItem struct {
	out map[string]interface{}
	at  time.Time
}

// onWAPermitir aplica o freio de consultas por minuto (só para consultas que vão ao WhatsApp).
func onWAPermitir() bool {
	onWAMu.Lock()
	defer onWAMu.Unlock()
	agora := time.Now()
	k := 0
	for _, t := range onWAJanela {
		if agora.Sub(t) < time.Minute {
			onWAJanela[k] = t
			k++
		}
	}
	onWAJanela = onWAJanela[:k]
	if len(onWAJanela) >= onWAPorMinuto {
		return false
	}
	onWAJanela = append(onWAJanela, agora)
	return true
}

func registerOnWhatsApp(client *whatsmeow.Client) {
	http.HandleFunc("/api/onwhatsapp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			fail(w, http.StatusMethodNotAllowed, "GET only")
			return
		}
		phone := r.URL.Query().Get("phone")
		if !onWAFoneRe.MatchString(phone) {
			fail(w, 400, "phone must be 10-15 digits with country code, no +")
			return
		}
		onWAMu.Lock()
		if c, ok := onWACache[phone]; ok && time.Since(c.at) < onWACacheTTL {
			onWAMu.Unlock()
			writeJSON(w, 200, c.out)
			return
		}
		for k, c := range onWACache {
			if time.Since(c.at) >= onWACacheTTL {
				delete(onWACache, k)
			}
		}
		onWAMu.Unlock()
		if !client.IsConnected() {
			fail(w, 503, "not connected to WhatsApp")
			return
		}
		if !onWAPermitir() {
			fail(w, 429, "too many lookups, try again in a minute")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		res, err := client.IsOnWhatsApp(ctx, []string{"+" + phone})
		if err != nil && len(res) == 0 {
			fail(w, 502, "lookup failed: "+err.Error())
			return
		}
		out := map[string]interface{}{"success": true, "phone": phone, "exists": false}
		for _, info := range res {
			if !info.IsIn {
				continue
			}
			pn, lid := info.PhoneNumber, types.EmptyJID
			if info.JID.Server == types.HiddenUserServer {
				lid = info.JID
			} else if pn.IsEmpty() && info.JID.Server == types.DefaultUserServer {
				pn = info.JID
			}
			if pn.IsEmpty() && !lid.IsEmpty() {
				if p, e := client.Store.LIDs.GetPNForLID(ctx, lid); e == nil && !p.IsEmpty() {
					pn = p
				}
			}
			if lid.IsEmpty() && !pn.IsEmpty() {
				if l, e := client.Store.LIDs.GetLIDForPN(ctx, pn); e == nil && !l.IsEmpty() {
					lid = l
				}
			}
			if pn.IsEmpty() {
				continue // sem número de telefone não dá para conferir com o que foi pedido
			}
			out["exists"] = true
			out["jid"] = pn.ToNonAD().String()
			if !lid.IsEmpty() {
				out["lid"] = lid.ToNonAD().String()
			}
			if info.VerifiedName != nil && info.VerifiedName.Details != nil {
				out["verified_name"] = info.VerifiedName.Details.GetVerifiedName()
			}
			for _, cj := range []types.JID{pn, lid} {
				if cj.IsEmpty() {
					continue
				}
				if c, e := client.Store.Contacts.GetContact(ctx, cj); e == nil && c.Found {
					for _, n := range []string{c.FullName, c.FirstName, c.PushName, c.BusinessName} {
						if n != "" {
							out["name"] = n
							break
						}
					}
				}
				if out["name"] != nil {
					break
				}
			}
			break
		}
		onWAMu.Lock()
		onWACache[phone] = onWACacheItem{out: out, at: time.Now()}
		onWAMu.Unlock()
		writeJSON(w, 200, out)
	})
}
