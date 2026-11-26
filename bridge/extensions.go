package main

// Extensions used by the local WhatsApp panel (http://localhost:8780).
// Everything here is additive: existing endpoints keep their request/response format.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.mau.fi/whatsmeow"
	waProto "go.mau.fi/whatsmeow/binary/proto"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"
)

// ---------- schema ----------

// migrateSchema adds the optional columns/tables used by the panel. Errors (column exists) are ignored.
func migrateSchema(db *sql.DB) {
	cols := []string{
		"quoted_id TEXT", "quoted_sender TEXT", "quoted_text TEXT", "mentions TEXT",
		"forwarded INTEGER DEFAULT 0", "edited INTEGER DEFAULT 0", "revoked INTEGER DEFAULT 0",
		"status INTEGER DEFAULT 0", "extra TEXT", "raw BLOB",
	}
	for _, c := range cols {
		_, _ = db.Exec("ALTER TABLE messages ADD COLUMN " + c)
	}
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS reactions (
		message_id TEXT, chat_jid TEXT, sender TEXT, emoji TEXT, from_me INTEGER DEFAULT 0, timestamp TIMESTAMP,
		PRIMARY KEY (message_id, chat_jid, sender))`)
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_messages_chat_ts ON messages(chat_jid, timestamp)")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_messages_id ON messages(id)")
}

// ---------- message metadata ----------

type msgMeta struct {
	QuotedID, QuotedSender, QuotedText string
	Mentions                           []string
	Forwarded                          bool
	Extra                              string
	Raw                                []byte
}

func contextInfoOf(m *waProto.Message) *waProto.ContextInfo {
	if m == nil {
		return nil
	}
	switch {
	case m.ExtendedTextMessage != nil:
		return m.ExtendedTextMessage.GetContextInfo()
	case m.ImageMessage != nil:
		return m.ImageMessage.GetContextInfo()
	case m.VideoMessage != nil:
		return m.VideoMessage.GetContextInfo()
	case m.AudioMessage != nil:
		return m.AudioMessage.GetContextInfo()
	case m.DocumentMessage != nil:
		return m.DocumentMessage.GetContextInfo()
	case m.StickerMessage != nil:
		return m.StickerMessage.GetContextInfo()
	case m.LocationMessage != nil:
		return m.LocationMessage.GetContextInfo()
	case m.LiveLocationMessage != nil:
		return m.LiveLocationMessage.GetContextInfo()
	case m.ContactMessage != nil:
		return m.ContactMessage.GetContextInfo()
	case m.ContactsArrayMessage != nil:
		return m.ContactsArrayMessage.GetContextInfo()
	}
	return nil
}

// setContextInfo attaches ci to the message (plain text is upgraded to ExtendedTextMessage).
func setContextInfo(m *waProto.Message, ci *waProto.ContextInfo) {
	if m.Conversation != nil {
		m.ExtendedTextMessage = &waProto.ExtendedTextMessage{Text: m.Conversation}
		m.Conversation = nil
	}
	switch {
	case m.ExtendedTextMessage != nil:
		m.ExtendedTextMessage.ContextInfo = ci
	case m.ImageMessage != nil:
		m.ImageMessage.ContextInfo = ci
	case m.VideoMessage != nil:
		m.VideoMessage.ContextInfo = ci
	case m.AudioMessage != nil:
		m.AudioMessage.ContextInfo = ci
	case m.DocumentMessage != nil:
		m.DocumentMessage.ContextInfo = ci
	case m.StickerMessage != nil:
		m.StickerMessage.ContextInfo = ci
	case m.LocationMessage != nil:
		m.LocationMessage.ContextInfo = ci
	case m.ContactMessage != nil:
		m.ContactMessage.ContextInfo = ci
	case m.ContactsArrayMessage != nil:
		m.ContactsArrayMessage.ContextInfo = ci
	}
}

// previewText is a short human text for any message (used for quotes).
func previewText(m *waProto.Message) string {
	if t := extractTextContent(m); t != "" {
		return t
	}
	switch {
	case m == nil:
		return ""
	case m.ImageMessage != nil:
		return "📷 Foto"
	case m.VideoMessage != nil:
		return "🎥 Vídeo"
	case m.AudioMessage != nil:
		if m.AudioMessage.GetPTT() {
			return "🎤 Mensagem de voz"
		}
		return "🎵 Áudio"
	case m.DocumentMessage != nil:
		return "📄 " + m.DocumentMessage.GetFileName()
	case m.StickerMessage != nil:
		return "Figurinha"
	}
	return ""
}

func extractMeta(m *waProto.Message) msgMeta {
	var mt msgMeta
	if m == nil {
		return mt
	}
	if ci := contextInfoOf(m); ci != nil {
		mt.QuotedID = ci.GetStanzaID()
		if mt.QuotedID != "" {
			mt.QuotedSender = ci.GetParticipant()
			mt.QuotedText = previewText(ci.GetQuotedMessage())
		}
		mt.Mentions = ci.GetMentionedJID()
		mt.Forwarded = ci.GetIsForwarded()
	}
	extra := map[string]interface{}{}
	if loc := m.GetLocationMessage(); loc != nil {
		extra = map[string]interface{}{"tipo": "local", "lat": loc.GetDegreesLatitude(), "lng": loc.GetDegreesLongitude(),
			"nome": loc.GetName(), "endereco": loc.GetAddress(), "url": loc.GetURL()}
	} else if loc := m.GetLiveLocationMessage(); loc != nil {
		extra = map[string]interface{}{"tipo": "local", "aovivo": true, "lat": loc.GetDegreesLatitude(), "lng": loc.GetDegreesLongitude(),
			"nome": loc.GetCaption()}
	} else if c := m.GetContactMessage(); c != nil {
		extra = map[string]interface{}{"tipo": "contato", "contatos": []map[string]string{{"nome": c.GetDisplayName(), "vcard": c.GetVcard()}}}
	} else if ca := m.GetContactsArrayMessage(); ca != nil {
		var cs []map[string]string
		for _, c := range ca.GetContacts() {
			cs = append(cs, map[string]string{"nome": c.GetDisplayName(), "vcard": c.GetVcard()})
		}
		extra = map[string]interface{}{"tipo": "contato", "contatos": cs}
	} else if a := m.GetAudioMessage(); a != nil {
		extra = map[string]interface{}{"tipo": "audio", "ptt": a.GetPTT(), "segundos": a.GetSeconds()}
	} else if s := m.GetStickerMessage(); s != nil {
		extra = map[string]interface{}{"tipo": "figurinha", "animada": s.GetIsAnimated()}
	} else if d := m.GetDocumentMessage(); d != nil {
		extra = map[string]interface{}{"tipo": "documento", "mime": d.GetMimetype(), "paginas": d.GetPageCount(), "bytes": d.GetFileLength()}
	} else if v := m.GetVideoMessage(); v != nil {
		extra = map[string]interface{}{"tipo": "video", "segundos": v.GetSeconds(), "gif": v.GetGifPlayback()}
	}
	if len(extra) > 0 {
		if b, err := json.Marshal(extra); err == nil {
			mt.Extra = string(b)
		}
	}
	mt.Raw, _ = proto.Marshal(m)
	return mt
}

func (store *MessageStore) StoreMeta(id, chatJID string, mt msgMeta) {
	var mentions interface{}
	if len(mt.Mentions) > 0 {
		b, _ := json.Marshal(mt.Mentions)
		mentions = string(b)
	}
	_, err := store.db.Exec(`UPDATE messages SET quoted_id=?, quoted_sender=?, quoted_text=?, mentions=?, forwarded=?, extra=?, raw=?
		WHERE id=? AND chat_jid=?`, nullIfEmpty(mt.QuotedID), nullIfEmpty(mt.QuotedSender), nullIfEmpty(mt.QuotedText), mentions,
		mt.Forwarded, nullIfEmpty(mt.Extra), mt.Raw, id, chatJID)
	if err != nil {
		fmt.Printf("Warning: could not store message meta: %v\n", err)
	}
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// handleSpecialMessage processes reactions, edits and revokes. Returns true when the event was fully handled.
func handleSpecialMessage(client *whatsmeow.Client, store *MessageStore, evt *events.Message) bool {
	m := evt.Message
	if m == nil {
		return false
	}
	if r := m.GetReactionMessage(); r != nil {
		target := r.GetKey().GetID()
		sender := evt.Info.Sender.User
		if evt.Info.IsFromMe {
			sender = "me"
		}
		if r.GetText() == "" {
			_, _ = store.db.Exec("DELETE FROM reactions WHERE message_id=? AND chat_jid=? AND sender=?", target, evt.Info.Chat.String(), sender)
		} else {
			_, _ = store.db.Exec(`INSERT INTO reactions (message_id, chat_jid, sender, emoji, from_me, timestamp) VALUES (?,?,?,?,?,?)
				ON CONFLICT(message_id, chat_jid, sender) DO UPDATE SET emoji=excluded.emoji, timestamp=excluded.timestamp`,
				target, evt.Info.Chat.String(), sender, r.GetText(), evt.Info.IsFromMe, evt.Info.Timestamp)
		}
		touchChat(store, evt.Info.Chat.String())
		fmt.Printf("[%s] reaction %q by %s on %s\n", evt.Info.Timestamp.Format("2006-01-02 15:04:05"), r.GetText(), sender, target)
		return true
	}
	if m.GetSecretEncryptedMessage() != nil {
		handleSecretEncrypted(client, store, evt)
		return true
	}
	if pm := m.GetProtocolMessage(); pm != nil {
		if pm.GetType() == waProto.ProtocolMessage_REVOKE || pm.GetType() == waProto.ProtocolMessage_MESSAGE_EDIT {
			diagProtocolMessage(evt)
		}
		target := pm.GetKey().GetID()
		switch pm.GetType() {
		case waProto.ProtocolMessage_REVOKE:
			_, _ = store.db.Exec("UPDATE messages SET revoked=1 WHERE id=?", target)
			touchChat(store, evt.Info.Chat.String())
			fmt.Printf("[%s] message %s revoked\n", evt.Info.Timestamp.Format("2006-01-02 15:04:05"), target)
		case waProto.ProtocolMessage_MESSAGE_EDIT:
			txt := extractTextContent(pm.GetEditedMessage())
			_, _ = store.db.Exec("UPDATE messages SET content=?, edited=1 WHERE id=?", txt, target)
			touchChat(store, evt.Info.Chat.String())
			fmt.Printf("[%s] message %s edited: %s\n", evt.Info.Timestamp.Format("2006-01-02 15:04:05"), target, txt)
		}
		return true
	}
	return false
}

// touchChat bumps a counter the panel watches (it polls max(rowid)/count; edits and reactions need a signal too).
var changeSeq int64
var changeMu sync.Mutex

func touchChat(store *MessageStore, chat string) {
	changeMu.Lock()
	changeSeq++
	changeMu.Unlock()
	_, _ = store.db.Exec("CREATE TABLE IF NOT EXISTS panel_changes (id INTEGER PRIMARY KEY CHECK (id = 1), seq INTEGER, chat_jid TEXT, at TIMESTAMP)")
	_, _ = store.db.Exec(`INSERT INTO panel_changes (id, seq, chat_jid, at) VALUES (1, 1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET seq = seq + 1, chat_jid = excluded.chat_jid, at = excluded.at`, chat, time.Now())
}

// ---------- receipts and presence ----------

func handleReceipt(client *whatsmeow.Client, store *MessageStore, v *events.Receipt) {
	diagReceipt(v)
	st := 0
	switch v.Type {
	case types.ReceiptTypeDelivered:
		st = 3
	case types.ReceiptTypeRead:
		st = 4
	case types.ReceiptTypePlayed:
		st = 5
	}
	if st == 0 || len(v.MessageIDs) == 0 {
		return
	}
	if v.IsFromMe && !isOwnJID(client, v.Chat) {
		return // receipts from my other devices for chats with other people
	}
	q := "UPDATE messages SET status = ? WHERE is_from_me = 1 AND COALESCE(status,0) < ? AND id IN (?" + strings.Repeat(",?", len(v.MessageIDs)-1) + ")"
	args := []interface{}{st, st}
	for _, id := range v.MessageIDs {
		args = append(args, id)
	}
	if res, err := store.db.Exec(q, args...); err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			touchChat(store, v.Chat.String())
		}
	}
}

func isOwnJID(client *whatsmeow.Client, j types.JID) bool {
	if client.Store.ID != nil && j.User == client.Store.ID.User {
		return true
	}
	lid := client.Store.GetLID()
	return !lid.IsEmpty() && j.User == lid.User
}

type typingInfo struct {
	Sender string    `json:"sender"`
	State  string    `json:"state"`
	Media  string    `json:"media"`
	At     time.Time `json:"at"`
}
type presenceInfo struct {
	Online   bool      `json:"online"`
	LastSeen time.Time `json:"last_seen"`
	At       time.Time `json:"at"`
}

var (
	liveMu      sync.Mutex
	typingMap   = map[string]typingInfo{}
	presenceMap = map[string]presenceInfo{}
	onlineUntil time.Time
)

func handleChatPresence(v *events.ChatPresence) {
	liveMu.Lock()
	defer liveMu.Unlock()
	typingMap[v.Chat.String()] = typingInfo{Sender: v.Sender.User, State: string(v.State), Media: string(v.Media), At: time.Now()}
}

func handlePresence(v *events.Presence) {
	liveMu.Lock()
	defer liveMu.Unlock()
	presenceMap[v.From.ToNonAD().String()] = presenceInfo{Online: !v.Unavailable, LastSeen: v.LastSeen, At: time.Now()}
}

// ---------- helpers ----------

// senderJIDFor rebuilds the full JID of a stored sender (the DB only keeps the user part).
func senderJIDFor(client *whatsmeow.Client, chat types.JID, sender string) types.JID {
	if strings.Contains(sender, "@") {
		if j, err := types.ParseJID(sender); err == nil {
			return j
		}
	}
	if chat.Server != types.GroupServer {
		return chat
	}
	lid := types.NewJID(sender, types.HiddenUserServer)
	if pn, err := client.Store.LIDs.GetPNForLID(context.Background(), lid); err == nil && !pn.IsEmpty() {
		return lid
	}
	return types.NewJID(sender, types.DefaultUserServer)
}

type storedMsg struct {
	ID, Chat, Sender, Content, MediaType, Filename string
	FromMe                                         bool
	Raw                                            []byte
}

func loadStored(store *MessageStore, chat, id string) (*storedMsg, error) {
	var s storedMsg
	var sender, content, mt, fn sql.NullString
	err := store.db.QueryRow(`SELECT id, chat_jid, sender, content, is_from_me, media_type, filename, raw FROM messages
		WHERE id=? AND chat_jid=?`, id, chat).Scan(&s.ID, &s.Chat, &sender, &content, &s.FromMe, &mt, &fn, &s.Raw)
	if err != nil {
		return nil, fmt.Errorf("message %s not found in %s", id, chat)
	}
	s.Sender, s.Content, s.MediaType, s.Filename = sender.String, content.String, mt.String, fn.String
	return &s, nil
}

func ownJID(client *whatsmeow.Client) types.JID {
	if client.Store.ID == nil {
		return types.EmptyJID
	}
	return client.Store.ID.ToNonAD()
}

// replyContext builds the ContextInfo for quoting a stored message.
func replyContext(client *whatsmeow.Client, store *MessageStore, chat types.JID, replyTo string) (*waProto.ContextInfo, error) {
	s, err := loadStored(store, chat.String(), replyTo)
	if err != nil {
		// the same conversation can be stored under the @lid and the phone-number chat
		var other string
		if store.db.QueryRow("SELECT chat_jid FROM messages WHERE id=? LIMIT 1", replyTo).Scan(&other) == nil {
			s, err = loadStored(store, other, replyTo)
		}
	}
	if err != nil {
		return nil, err
	}
	var quoted *waProto.Message
	if len(s.Raw) > 0 {
		quoted = &waProto.Message{}
		if proto.Unmarshal(s.Raw, quoted) != nil {
			quoted = nil
		}
	}
	if quoted == nil {
		txt := s.Content
		if txt == "" && s.MediaType != "" {
			txt = map[string]string{"image": "📷 Foto", "video": "🎥 Vídeo", "audio": "🎤 Áudio", "document": "📄 " + s.Filename, "sticker": "Figurinha"}[s.MediaType]
		}
		quoted = &waProto.Message{Conversation: proto.String(txt)}
	} else if ci := contextInfoOf(quoted); ci != nil {
		// do not nest quotes
		setContextInfo(quoted, nil)
	}
	part := ownJID(client)
	if !s.FromMe {
		part = senderJIDFor(client, chat, s.Sender)
	}
	return &waProto.ContextInfo{StanzaID: proto.String(s.ID), Participant: proto.String(part.String()), QuotedMessage: quoted}, nil
}

func parseRecipient(recipient string) (types.JID, error) {
	if strings.Contains(recipient, "@") {
		return types.ParseJID(recipient)
	}
	return types.JID{User: recipient, Server: types.DefaultUserServer}, nil
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]interface{}{"success": false, "message": msg})
}

func decodePost(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "invalid request format")
		return false
	}
	return true
}

// guardLocal refuses requests that come from a web page (CSRF / DNS rebinding). Local tools send no Origin header.
func guardLocal(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if hh, _, err := net.SplitHostPort(host); err == nil {
			host = hh
		}
		host = strings.Trim(host, "[]")
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "browser requests are not allowed", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// ---------- REST endpoints ----------

func registerExtensions(client *whatsmeow.Client, store *MessageStore) {
	ctx := context.Background()

	http.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		out := map[string]interface{}{"success": true, "connected": client.IsConnected(), "push_name": client.Store.PushName}
		if client.Store.ID != nil {
			out["jid"] = client.Store.ID.ToNonAD().String()
		}
		if lid := client.Store.GetLID(); !lid.IsEmpty() {
			out["lid"] = lid.ToNonAD().String()
		}
		// additive fields: why the bridge is offline (replaced / banned / failed / disconnected)
		state, reason, since := connStatus()
		out["state"], out["state_since"] = state, since.Unix()
		out["pair_state"], out["logged_in"] = pairState(), client.Store.ID != nil
		if reason != "" {
			out["state_reason"] = reason
		}
		writeJSON(w, 200, out)
	})

	http.HandleFunc("/api/react", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ChatJID   string `json:"chat_jid"`
			MessageID string `json:"message_id"`
			Emoji     string `json:"emoji"`
		}
		if !decodePost(w, r, &req) {
			return
		}
		chat, err := types.ParseJID(req.ChatJID)
		if err != nil || req.MessageID == "" {
			fail(w, 400, "chat_jid and message_id are required")
			return
		}
		s, err := loadStored(store, req.ChatJID, req.MessageID)
		if err != nil {
			fail(w, 404, err.Error())
			return
		}
		sender := types.EmptyJID
		if !s.FromMe {
			sender = senderJIDFor(client, chat, s.Sender)
		}
		resp, err := client.SendMessage(ctx, chat, client.BuildReaction(chat, sender, req.MessageID, req.Emoji))
		if err != nil {
			fail(w, 500, "error sending reaction: "+err.Error())
			return
		}
		if req.Emoji == "" {
			_, _ = store.db.Exec("DELETE FROM reactions WHERE message_id=? AND chat_jid=? AND sender='me'", req.MessageID, req.ChatJID)
		} else {
			_, _ = store.db.Exec(`INSERT INTO reactions (message_id, chat_jid, sender, emoji, from_me, timestamp) VALUES (?,?,'me',?,1,?)
				ON CONFLICT(message_id, chat_jid, sender) DO UPDATE SET emoji=excluded.emoji, timestamp=excluded.timestamp`,
				req.MessageID, req.ChatJID, req.Emoji, resp.Timestamp)
		}
		touchChat(store, req.ChatJID)
		writeJSON(w, 200, map[string]interface{}{"success": true, "id": resp.ID})
	})

	http.HandleFunc("/api/edit", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ChatJID   string `json:"chat_jid"`
			MessageID string `json:"message_id"`
			Message   string `json:"message"`
			Test      bool   `json:"test"`
		}
		if !decodePost(w, r, &req) {
			return
		}
		chat, err := types.ParseJID(req.ChatJID)
		if err != nil || req.MessageID == "" || strings.TrimSpace(req.Message) == "" {
			fail(w, 400, "chat_jid, message_id and message are required")
			return
		}
		// Edits were reported as not reaching the recipient (2026-11-19). Until verified, refuse instead of
		// pretending: only explicit tests in the own chat / "Arquivos" group go through.
		if !(req.Test && editTestChat(isOwnJID(client, chat), chat)) {
			fail(w, 409, "edit is disabled until it is verified to reach the recipient; send a correction or revoke+resend instead")
			return
		}
		s, err := loadStored(store, req.ChatJID, req.MessageID)
		if err != nil {
			fail(w, 404, err.Error())
			return
		}
		if !s.FromMe {
			fail(w, 400, "only your own messages can be edited")
			return
		}
		// WhatsApp only applies edits made up to 15 minutes after sending; later ones are silently ignored by the phones.
		var sentAt time.Time
		if err := store.db.QueryRow("SELECT timestamp FROM messages WHERE id=? AND chat_jid=?", req.MessageID, req.ChatJID).Scan(&sentAt); err == nil {
			if age := time.Since(sentAt); age > 15*time.Minute {
				fail(w, 409, fmt.Sprintf("message was sent %d minutes ago; WhatsApp only allows edits within 15 minutes, use delete for everyone + resend", int(age.Minutes())))
				return
			}
		}
		var content *waProto.Message
		if s.MediaType == "image" || s.MediaType == "video" || s.MediaType == "document" {
			// caption edit: WhatsApp expects the media message type with the new caption
			orig := &waProto.Message{}
			if len(s.Raw) == 0 || proto.Unmarshal(s.Raw, orig) != nil {
				fail(w, 400, "caption of this message cannot be edited (original not stored)")
				return
			}
			switch {
			case orig.ImageMessage != nil:
				orig.ImageMessage.Caption = proto.String(req.Message)
			case orig.VideoMessage != nil:
				orig.VideoMessage.Caption = proto.String(req.Message)
			case orig.DocumentMessage != nil:
				orig.DocumentMessage.Caption = proto.String(req.Message)
			}
			content = orig
		} else if s.MediaType == "" {
			content = &waProto.Message{Conversation: proto.String(req.Message)}
		} else {
			fail(w, 400, "this kind of message cannot be edited")
			return
		}
		editMsg := client.BuildEdit(chat, req.MessageID, content)
		resp, err := client.SendMessage(ctx, chat, editMsg)
		if err != nil {
			fail(w, 500, "error editing message: "+err.Error())
			return
		}
		watchEdit(resp.ID, req.ChatJID, req.MessageID)
		fmt.Printf("[edit-diag] sent edit stanza %s for %s in %s: %s\n", resp.ID, req.MessageID, req.ChatJID, protoJSON(editMsg))
		_, _ = store.db.Exec("UPDATE messages SET content=?, edited=1 WHERE id=? AND chat_jid=?", req.Message, req.MessageID, req.ChatJID)
		touchChat(store, req.ChatJID)
		writeJSON(w, 200, map[string]interface{}{"success": true, "edit_id": resp.ID})
	})

	http.HandleFunc("/api/edit-status", func(w http.ResponseWriter, r *http.Request) {
		editWatchMu.Lock()
		out := map[string]interface{}{"success": true, "watch": editWatch, "receipts": lastEditReceipts}
		writeJSON(w, 200, out)
		editWatchMu.Unlock()
	})

	http.HandleFunc("/api/revoke", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ChatJID   string `json:"chat_jid"`
			MessageID string `json:"message_id"`
		}
		if !decodePost(w, r, &req) {
			return
		}
		chat, err := types.ParseJID(req.ChatJID)
		if err != nil || req.MessageID == "" {
			fail(w, 400, "chat_jid and message_id are required")
			return
		}
		s, err := loadStored(store, req.ChatJID, req.MessageID)
		if err != nil {
			fail(w, 404, err.Error())
			return
		}
		if !s.FromMe {
			fail(w, 400, "only your own messages can be deleted for everyone")
			return
		}
		if _, err := client.SendMessage(ctx, chat, client.BuildRevoke(chat, types.EmptyJID, req.MessageID)); err != nil {
			fail(w, 500, "error deleting message: "+err.Error())
			return
		}
		_, _ = store.db.Exec("UPDATE messages SET revoked=1 WHERE id=? AND chat_jid=?", req.MessageID, req.ChatJID)
		touchChat(store, req.ChatJID)
		writeJSON(w, 200, map[string]interface{}{"success": true})
	})

	http.HandleFunc("/api/forward", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ChatJID   string `json:"chat_jid"`
			MessageID string `json:"message_id"`
			Recipient string `json:"recipient"`
		}
		if !decodePost(w, r, &req) {
			return
		}
		to, err := parseRecipient(req.Recipient)
		if err != nil || req.ChatJID == "" || req.MessageID == "" {
			fail(w, 400, "chat_jid, message_id and recipient are required")
			return
		}
		s, err := loadStored(store, req.ChatJID, req.MessageID)
		if err != nil {
			fail(w, 404, err.Error())
			return
		}
		var msg *waProto.Message
		if len(s.Raw) > 0 {
			msg = &waProto.Message{}
			if proto.Unmarshal(s.Raw, msg) != nil {
				msg = nil
			}
		}
		var localPath string
		if msg == nil && s.MediaType != "" {
			// no original proto stored (old message): download and send again
			ok, _, _, path, derr := downloadMedia(client, store, req.MessageID, req.ChatJID)
			if !ok || derr != nil {
				fail(w, 500, fmt.Sprintf("could not download media to forward: %v", derr))
				return
			}
			res := sendWhatsAppMessageEx(client, SendMessageRequest{Recipient: to.String(), Message: s.Content, MediaPath: path, Filename: s.Filename, Forwarded: true})
			writeJSON(w, map[bool]int{true: 200, false: 500}[res.Success], res)
			return
		}
		if msg == nil {
			msg = &waProto.Message{Conversation: proto.String(s.Content)}
		}
		msg.MessageContextInfo = nil
		setContextInfo(msg, &waProto.ContextInfo{IsForwarded: proto.Bool(true), ForwardingScore: proto.Uint32(1)})
		withMessageSecret(msg)
		resp, err := client.SendMessage(ctx, to, msg)
		if err != nil {
			fail(w, 500, "error forwarding: "+err.Error())
			return
		}
		if s.MediaType != "" {
			// reuse the local copy so the panel can show it
			src := fmt.Sprintf("%s/%s/%s%s", storeDir, strings.ReplaceAll(req.ChatJID, ":", "_"), req.MessageID, filepath.Ext(s.Filename))
			if _, err := os.Stat(src); err == nil {
				localPath = src
			}
		}
		storeSent(client, to, resp, msg, nil, localPath, s.Filename)
		_, _ = store.db.Exec(`UPDATE messages SET media_type=?, filename=?,
			url=(SELECT url FROM messages WHERE id=? AND chat_jid=?), media_key=(SELECT media_key FROM messages WHERE id=? AND chat_jid=?),
			file_sha256=(SELECT file_sha256 FROM messages WHERE id=? AND chat_jid=?), file_enc_sha256=(SELECT file_enc_sha256 FROM messages WHERE id=? AND chat_jid=?),
			file_length=(SELECT file_length FROM messages WHERE id=? AND chat_jid=?) WHERE id=? AND chat_jid=?`,
			nullIfEmpty(s.MediaType), nullIfEmpty(s.Filename), req.MessageID, req.ChatJID, req.MessageID, req.ChatJID, req.MessageID, req.ChatJID,
			req.MessageID, req.ChatJID, req.MessageID, req.ChatJID, resp.ID, to.String())
		writeJSON(w, 200, SendMessageResponse{Success: true, Message: "Message forwarded to " + to.String(), ID: resp.ID, Timestamp: resp.Timestamp.Unix()})
	})

	http.HandleFunc("/api/presence", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ChatJID string `json:"chat_jid"`
			State   string `json:"state"` // composing | recording | paused | available | unavailable
		}
		if !decodePost(w, r, &req) {
			return
		}
		var err error
		switch req.State {
		case "available", "unavailable":
			liveMu.Lock()
			if req.State == "available" {
				onlineUntil = time.Now().Add(70 * time.Second)
			} else {
				onlineUntil = time.Time{}
			}
			liveMu.Unlock()
			err = client.SendPresence(ctx, types.Presence(req.State))
		case "composing", "recording", "paused":
			chat, perr := types.ParseJID(req.ChatJID)
			if perr != nil {
				fail(w, 400, "invalid chat_jid")
				return
			}
			state, media := types.ChatPresenceComposing, types.ChatPresenceMediaText
			if req.State == "paused" {
				state = types.ChatPresencePaused
			} else if req.State == "recording" {
				media = types.ChatPresenceMediaAudio
			}
			err = client.SendChatPresence(ctx, chat, state, media)
		default:
			fail(w, 400, "unknown state")
			return
		}
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]interface{}{"success": true})
	})

	http.HandleFunc("/api/subscribe", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			JID string `json:"jid"`
		}
		if !decodePost(w, r, &req) {
			return
		}
		j, err := types.ParseJID(req.JID)
		if err != nil || j.Server == types.GroupServer {
			fail(w, 400, "invalid jid")
			return
		}
		if err := client.SubscribePresence(ctx, j); err != nil {
			fail(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]interface{}{"success": true})
	})

	http.HandleFunc("/api/live", func(w http.ResponseWriter, r *http.Request) {
		liveMu.Lock()
		typing := map[string]typingInfo{}
		for k, v := range typingMap {
			if time.Since(v.At) < 25*time.Second && v.State == "composing" {
				typing[k] = v
			}
		}
		pres := map[string]presenceInfo{}
		for k, v := range presenceMap {
			pres[k] = v
		}
		liveMu.Unlock()
		writeJSON(w, 200, map[string]interface{}{"success": true, "typing": typing, "presence": pres, "calls": ringingCalls()})
	})

	registerAvatarEndpoint(client)

	http.HandleFunc("/api/contact", func(w http.ResponseWriter, r *http.Request) {
		j, err := types.ParseJID(r.URL.Query().Get("jid"))
		if err != nil || j.User == "" {
			fail(w, 400, "invalid jid")
			return
		}
		out := map[string]interface{}{"success": true, "jid": j.String()}
		if c, err := client.Store.Contacts.GetContact(ctx, j); err == nil {
			out["first_name"], out["full_name"], out["push_name"], out["business_name"] = c.FirstName, c.FullName, c.PushName, c.BusinessName
		}
		if j.Server == types.HiddenUserServer {
			if pn, err := client.Store.LIDs.GetPNForLID(ctx, j); err == nil && !pn.IsEmpty() {
				out["phone"] = pn.User
			}
		} else if j.Server == types.DefaultUserServer {
			out["phone"] = j.User
			if lid, err := client.Store.LIDs.GetLIDForPN(ctx, j); err == nil && !lid.IsEmpty() {
				out["lid"] = lid.String()
			}
		}
		if infos, err := client.GetUserInfo(ctx, []types.JID{j}); err == nil {
			for _, ui := range infos {
				out["about"] = ui.Status
				if ui.VerifiedName != nil && ui.VerifiedName.Details != nil {
					out["verified_name"] = ui.VerifiedName.Details.GetVerifiedName()
				}
				out["devices"] = len(ui.Devices)
			}
		}
		if bp, err := client.GetBusinessProfile(ctx, j); err == nil && bp != nil {
			out["business"] = map[string]interface{}{"email": bp.Email, "address": bp.Address, "categories": bp.Categories}
		}
		writeJSON(w, 200, out)
	})

	http.HandleFunc("/api/group", func(w http.ResponseWriter, r *http.Request) {
		j, err := types.ParseJID(r.URL.Query().Get("jid"))
		if err != nil || j.Server != types.GroupServer {
			fail(w, 400, "invalid group jid")
			return
		}
		g, err := client.GetGroupInfo(ctx, j)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		var parts []map[string]interface{}
		for _, p := range g.Participants {
			name := ""
			for _, cj := range []types.JID{p.JID, p.PhoneNumber, p.LID} {
				if cj.IsEmpty() {
					continue
				}
				if c, err := client.Store.Contacts.GetContact(ctx, cj); err == nil && c.Found {
					for _, n := range []string{c.FullName, c.FirstName, c.PushName, c.BusinessName} {
						if n != "" {
							name = n
							break
						}
					}
				}
				if name != "" {
					break
				}
			}
			if name == "" {
				name = p.DisplayName
			}
			parts = append(parts, map[string]interface{}{"jid": p.JID.String(), "phone": p.PhoneNumber.User, "lid": p.LID.String(),
				"admin": p.IsAdmin, "super_admin": p.IsSuperAdmin, "name": name, "me": isOwnJID(client, p.JID)})
		}
		writeJSON(w, 200, map[string]interface{}{"success": true, "jid": g.JID.String(), "name": g.Name, "topic": g.Topic,
			"owner": g.OwnerJID.String(), "created": g.GroupCreated, "announce": g.IsAnnounce, "locked": g.IsLocked,
			"addressing": string(g.AddressingMode), "participants": parts})
	})

	// keep "online" presence only while the panel sends heartbeats (so the phone keeps getting notifications otherwise)
	go func() {
		for range time.Tick(15 * time.Second) {
			liveMu.Lock()
			expired := !onlineUntil.IsZero() && time.Now().After(onlineUntil)
			if expired {
				onlineUntil = time.Time{}
			}
			// typing entries only matter for 25s (see /api/live); drop old ones so the map does not grow forever
			for k, v := range typingMap {
				if time.Since(v.At) > 2*time.Minute {
					delete(typingMap, k)
				}
			}
			liveMu.Unlock()
			if expired && client.IsConnected() {
				_ = client.SendPresence(ctx, types.PresenceUnavailable)
			}
		}
	}()
}

// unwrapStored removes ephemeral/view-once/document-with-caption wrappers from a history message.
func unwrapStored(m *waProto.Message) *waProto.Message {
	for i := 0; i < 4 && m != nil; i++ {
		switch {
		case m.GetEphemeralMessage().GetMessage() != nil:
			m = m.GetEphemeralMessage().GetMessage()
		case m.GetViewOnceMessage().GetMessage() != nil:
			m = m.GetViewOnceMessage().GetMessage()
		case m.GetViewOnceMessageV2().GetMessage() != nil:
			m = m.GetViewOnceMessageV2().GetMessage()
		case m.GetDocumentWithCaptionMessage().GetMessage() != nil:
			m = m.GetDocumentWithCaptionMessage().GetMessage()
		case m.GetEditedMessage().GetMessage() != nil:
			m = m.GetEditedMessage().GetMessage()
		default:
			return m
		}
	}
	return m
}

// storeHistoryExtras saves quote/mention/location data, delivery status and reactions that come with history sync.
func storeHistoryExtras(client *whatsmeow.Client, store *MessageStore, chatJID, msgID string, isFromMe bool, wmi *waProto.WebMessageInfo) {
	if msgID == "" || wmi == nil {
		return
	}
	store.StoreMeta(msgID, chatJID, extractMeta(unwrapStored(wmi.GetMessage())))
	if isFromMe {
		if st := int(wmi.GetStatus()); st >= 2 {
			_, _ = store.db.Exec("UPDATE messages SET status = ? WHERE id = ? AND chat_jid = ? AND COALESCE(status,0) < ?", st, msgID, chatJID, st)
		}
	}
	if wmi.GetMessageStubType() == waProto.WebMessageInfo_REVOKE {
		_, _ = store.db.Exec("UPDATE messages SET revoked = 1 WHERE id = ? AND chat_jid = ?", msgID, chatJID)
	}
	for _, r := range wmi.GetReactions() {
		if r.GetText() == "" {
			continue
		}
		k := r.GetKey()
		sender := "me"
		if !k.GetFromMe() {
			p := k.GetParticipant()
			if p == "" {
				p = k.GetRemoteJID()
			}
			sender = strings.SplitN(strings.SplitN(p, "@", 2)[0], ":", 2)[0]
		}
		ts := time.UnixMilli(r.GetSenderTimestampMS())
		_, _ = store.db.Exec(`INSERT INTO reactions (message_id, chat_jid, sender, emoji, from_me, timestamp) VALUES (?,?,?,?,?,?)
			ON CONFLICT(message_id, chat_jid, sender) DO UPDATE SET emoji=excluded.emoji, timestamp=excluded.timestamp`,
			msgID, chatJID, sender, r.GetText(), k.GetFromMe(), ts)
	}
}
