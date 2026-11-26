package main

// More diagnostics for edits that do not reach the recipient:
//  - a logger that shows whatsmeow DEBUG lines only about sending/retries/sessions (keeps the log readable)
//  - GET /api/devices?jid=... : the contact's devices and whether we have a Signal session with each one

import (
	"context"
	"net/http"
	"strings"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

type filteredLogger struct {
	waLog.Logger
	module string
}

var debugKeywords = []string{"Sending", "sending", "retry", "Retry", "session", "Session", "encrypt", "Encrypt", "migrat", "Migrat", "prekey", "pkmsg", "edit"}

func newFilteredLogger(module string) waLog.Logger {
	return &filteredLogger{Logger: waLog.Stdout(module, "DEBUG", true), module: module}
}

func (l *filteredLogger) Debugf(msg string, args ...interface{}) {
	for _, k := range debugKeywords {
		if strings.Contains(msg, k) {
			l.Logger.Debugf(msg, args...)
			return
		}
	}
}

func (l *filteredLogger) Sub(module string) waLog.Logger {
	return &filteredLogger{Logger: l.Logger.Sub(module), module: l.module + "/" + module}
}

func registerDeviceDiag(client *whatsmeow.Client) {
	http.HandleFunc("/api/devices", func(w http.ResponseWriter, r *http.Request) {
		j, err := types.ParseJID(r.URL.Query().Get("jid"))
		if err != nil || j.User == "" {
			fail(w, 400, "invalid jid")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		targets := []types.JID{j}
		switch j.Server {
		case types.HiddenUserServer:
			if pn, err := client.Store.LIDs.GetPNForLID(ctx, j); err == nil && !pn.IsEmpty() {
				targets = append(targets, pn)
			}
		case types.DefaultUserServer:
			if lid, err := client.Store.LIDs.GetLIDForPN(ctx, j); err == nil && !lid.IsEmpty() {
				targets = append(targets, lid)
			}
		}
		out := map[string]interface{}{"success": true}
		for _, t := range targets {
			devs, err := client.GetUserDevices(ctx, []types.JID{t})
			list := []map[string]interface{}{}
			if err != nil {
				out[t.String()+"_error"] = err.Error()
			}
			for _, d := range devs {
				has, _ := client.Store.Sessions.HasSession(ctx, d.SignalAddress().String())
				list = append(list, map[string]interface{}{"device": d.String(), "session": has})
			}
			out[t.String()] = list
		}
		writeJSON(w, 200, out)
	})
}
