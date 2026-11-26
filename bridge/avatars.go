package main

// Profile pictures for the panel: GET /api/avatar?jid=...  -> image/jpeg (200) or 404 when there is no picture.
// Cached on disk in store/avatars/<user>.jpg (24h TTL; "no picture" remembered in <user>.none for 24h,
// transient errors for 10 min). Network lookups are serialized with a small delay to avoid hammering WhatsApp.
// GET /api/avatar?jid=...&info=1 keeps the old JSON response {success,url,id}.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/types"
)

const avatarTTL = 24 * time.Hour

var (
	avatarNetMu   sync.Mutex // one WhatsApp lookup at a time
	avatarKeyMu   sync.Mutex
	avatarKeyLock = map[string]*sync.Mutex{}
	avatarSafe    = regexp.MustCompile(`[^0-9A-Za-z._-]`)
)

func avatarDir() string { return filepath.Join(storeDir, "avatars") }

func avatarLockFor(key string) *sync.Mutex {
	avatarKeyMu.Lock()
	defer avatarKeyMu.Unlock()
	m := avatarKeyLock[key]
	if m == nil {
		m = &sync.Mutex{}
		avatarKeyLock[key] = m
	}
	return m
}

func fresh(path string, ttl time.Duration) bool {
	st, err := os.Stat(path)
	return err == nil && time.Since(st.ModTime()) < ttl
}

// avatarCandidates: for @lid try the lid then the phone JID; for phone JIDs try the phone then the lid.
func avatarCandidates(ctx context.Context, client *whatsmeow.Client, j types.JID) []types.JID {
	out := []types.JID{j}
	switch j.Server {
	case types.HiddenUserServer:
		if pn, err := client.Store.LIDs.GetPNForLID(ctx, j); err == nil && !pn.IsEmpty() {
			out = append(out, pn)
		}
	case types.DefaultUserServer:
		if lid, err := client.Store.LIDs.GetLIDForPN(ctx, j); err == nil && !lid.IsEmpty() {
			out = append(out, lid)
		}
	}
	return out
}

// fetchAvatar returns the jpeg bytes, or (nil, nil) when there is no visible picture.
func fetchAvatar(ctx context.Context, client *whatsmeow.Client, j types.JID) ([]byte, error) {
	avatarNetMu.Lock()
	defer func() {
		time.Sleep(250 * time.Millisecond)
		avatarNetMu.Unlock()
	}()
	var lastErr error
	for _, c := range avatarCandidates(ctx, client, j) {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		info, err := client.GetProfilePictureInfo(cctx, c, &whatsmeow.GetProfilePictureParams{Preview: true})
		cancel()
		if err != nil {
			if errors.Is(err, whatsmeow.ErrProfilePictureNotSet) || errors.Is(err, whatsmeow.ErrProfilePictureUnauthorized) {
				continue
			}
			lastErr = err
			continue
		}
		if info == nil || info.URL == "" {
			continue
		}
		req, _ := http.NewRequestWithContext(ctx, "GET", info.URL, nil)
		hc := &http.Client{Timeout: 20 * time.Second}
		resp, err := hc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || len(data) == 0 {
			if err == nil {
				err = errors.New("download status " + resp.Status)
			}
			lastErr = err
			continue
		}
		return data, nil
	}
	return nil, lastErr
}

func registerAvatarEndpoint(client *whatsmeow.Client) {
	http.HandleFunc("/api/avatar", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		j, err := types.ParseJID(r.URL.Query().Get("jid"))
		if err != nil || j.User == "" {
			fail(w, 400, "invalid jid")
			return
		}
		if r.URL.Query().Get("info") == "1" { // legacy JSON form
			info, err := client.GetProfilePictureInfo(ctx, j, &whatsmeow.GetProfilePictureParams{Preview: r.URL.Query().Get("preview") == "1"})
			if err != nil || info == nil {
				msg := "no picture"
				if err != nil && !errors.Is(err, whatsmeow.ErrProfilePictureNotSet) {
					msg = err.Error()
				}
				writeJSON(w, 200, map[string]interface{}{"success": false, "message": msg})
				return
			}
			writeJSON(w, 200, map[string]interface{}{"success": true, "url": info.URL, "id": info.ID})
			return
		}
		key := avatarSafe.ReplaceAllString(j.User+"_"+j.Server, "_")
		if strings.HasSuffix(j.Server, "s.whatsapp.net") {
			key = avatarSafe.ReplaceAllString(j.User, "_")
		}
		_ = os.MkdirAll(avatarDir(), 0755)
		jpg := filepath.Join(avatarDir(), key+".jpg")
		none := filepath.Join(avatarDir(), key+".none")
		lk := avatarLockFor(key)
		lk.Lock()
		defer lk.Unlock()
		refresh := r.URL.Query().Get("refresh") == "1"
		serve := func() bool {
			data, err := os.ReadFile(jpg)
			if err != nil {
				return false
			}
			w.Header().Set("Content-Type", "image/jpeg")
			w.Header().Set("Cache-Control", "private, max-age=3600")
			w.Write(data)
			return true
		}
		notFound := func() {
			w.Header().Set("Cache-Control", "private, max-age=3600")
			fail(w, 404, "no picture")
		}
		if !refresh {
			if fresh(jpg, avatarTTL) && serve() {
				return
			}
			if fresh(none, avatarTTL) {
				notFound()
				return
			}
		}
		if client == nil || !client.IsConnected() {
			if serve() { // stale is better than nothing
				return
			}
			fail(w, 503, "not connected")
			return
		}
		data, err := fetchAvatar(ctx, client, j)
		if err != nil {
			if serve() {
				return
			}
			// transient error: remember for 10 minutes only (backdate the marker)
			os.WriteFile(none, []byte(err.Error()), 0644)
			t := time.Now().Add(-avatarTTL + 10*time.Minute)
			os.Chtimes(none, t, t)
			fail(w, 502, err.Error())
			return
		}
		if data == nil {
			os.Remove(jpg)
			os.WriteFile(none, nil, 0644)
			notFound()
			return
		}
		os.Remove(none)
		tmp := jpg + ".tmp"
		if os.WriteFile(tmp, data, 0644) == nil {
			os.Rename(tmp, jpg)
		}
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Cache-Control", "private, max-age=3600")
		w.Write(data)
	})
}
