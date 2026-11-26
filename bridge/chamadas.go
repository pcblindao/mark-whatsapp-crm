package main

// Chamadas (2026-11-19): voice/video call events shown in the panel like WhatsApp Web.
//
// Each call becomes one row in messages: id "call-<call id>", media_type "call", content = readable text
// ("Chamada de voz perdida") so search/export/MCP tools show something sensible, and extra = JSON
// {"tipo":"chamada","video":bool,"status":"ringing|missed|accepted|rejected","duration":secs,"group":bool,"reason":"..."}.
// The row is upserted as the call changes state (offer -> accept -> terminate). The DB work runs on the ordered
// workQueue; the in-memory "ringing" list is updated right away and exposed in /api/live as "calls" so the panel
// can toast "Ligação de Fulano — atenda no celular" (the panel/bridge cannot answer calls).
//
// Sources: live call nodes (CallOffer / CallOfferNotice / CallAccept / CallTerminate / CallReject), call-log
// messages (CallLogMesssage) and history-sync stubs (CALL_MISSED_VOICE/VIDEO, group variants). Rows for the same
// call that arrive by different paths are merged when they are within 2 minutes of each other in the same chat.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.mau.fi/whatsmeow"
	waBinary "go.mau.fi/whatsmeow/binary"
	waProto "go.mau.fi/whatsmeow/binary/proto"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
)

const (
	callRingTimeout = 2 * time.Minute // a call still "ringing" after this is closed as missed
	callMergeWindow = 2 * time.Minute // rows of the same call from different sources are merged within this window
)

// callInfo is what we know about a call while it is in progress.
type callInfo struct {
	ID         string    `json:"id"`
	Chat       string    `json:"chat"`
	From       string    `json:"from"` // caller (user@server)
	Video      bool      `json:"video"`
	Group      bool      `json:"group"`
	FromMe     bool      `json:"from_me"`
	Since      time.Time `json:"since"`
	Status     string    `json:"status"`
	acceptedAt time.Time
	rowID      string // messages.id of the stored row
	src        string // "live" (call signalling) or "log" (call-log message / history stub)
}

var (
	callMu     sync.Mutex
	callsByID  = map[string]*callInfo{}
	callOnce   sync.Once
	callQueue  *eventQueue
	callStore  *MessageStore
	callClient *whatsmeow.Client
	callLogger waLog.Logger
)

// ringingCalls returns the calls that are ringing now (for /api/live).
func ringingCalls() []callInfo {
	callMu.Lock()
	defer callMu.Unlock()
	out := []callInfo{}
	for _, c := range callsByID {
		if c.Status == "ringing" && time.Since(c.Since) < callRingTimeout {
			out = append(out, *c)
		}
	}
	return out
}

// handleCallEvent handles call events. Returns true when the event was a call event.
func handleCallEvent(evt interface{}, client *whatsmeow.Client, store *MessageStore, q *eventQueue, logger waLog.Logger) bool {
	callOnce.Do(func() {
		callQueue, callStore, callLogger, callClient = q, store, logger, client
		go callSweeper()
	})
	switch v := evt.(type) {
	case *events.CallOffer:
		logCallNode("offer", v.BasicCallMeta, v.Data)
		callStarted(client, v.BasicCallMeta, nodeHasChild(v.Data, "video"), !v.GroupJID.IsEmpty())
	case *events.CallOfferNotice:
		logCallNode("offer_notice", v.BasicCallMeta, v.Data)
		callStarted(client, v.BasicCallMeta, v.Media == "video" || nodeHasChild(v.Data, "video"), v.Type == "group" || !v.GroupJID.IsEmpty())
	case *events.CallAccept:
		logCallNode("accept", v.BasicCallMeta, v.Data)
		callMu.Lock()
		if c := callsByID[v.CallID]; c != nil {
			c.Status, c.acceptedAt = "accepted", time.Now()
			cc := *c
			callMu.Unlock()
			q.enqueue(func() { saveCall(client, store, cc, 0, "") })
		} else {
			callMu.Unlock()
		}
	case *events.CallTerminate:
		logCallNode("terminate", v.BasicCallMeta, v.Data)
		dur := 0
		if v.Data != nil {
			ag := v.Data.AttrGetter()
			dur = ag.OptionalInt("duration")
			if dur == 0 {
				dur = ag.OptionalInt("audio_duration")
			}
		}
		callEnded(client, v.BasicCallMeta, "", v.Reason, dur)
	case *events.CallReject:
		logCallNode("reject", v.BasicCallMeta, v.Data)
		callEnded(client, v.BasicCallMeta, "rejected", "", 0)
	case *events.CallPreAccept, *events.CallTransport, *events.CallRelayLatency:
		// signalling only
	case *events.UnknownCallEvent:
		if v.Node != nil {
			fmt.Printf("[chamadas] unknown call node: %s\n", v.Node.String())
		}
	default:
		return false
	}
	return true
}

// logCallNode prints the call node tag and attributes (no media/keys), to check the semantics with real calls.
func logCallNode(tag string, m types.BasicCallMeta, n *waBinary.Node) {
	attrs := ""
	if n != nil {
		parts := []string{}
		for k, v := range n.Attrs {
			if k == "call-id" || k == "call-creator" || k == "caller_pn" || k == "caller_lid" || k == "group-jid" {
				continue
			}
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
		kids := []string{}
		for _, c := range n.GetChildren() {
			kids = append(kids, c.Tag)
		}
		attrs = strings.Join(parts, " ") + " children=[" + strings.Join(kids, ",") + "]"
	}
	fmt.Printf("[chamadas] %s id=%s from=%s creator=%s alt=%s group=%s %s\n", tag, m.CallID, m.From, m.CallCreator, m.CallCreatorAlt, m.GroupJID, attrs)
}

func nodeHasChild(n *waBinary.Node, tag string) bool {
	if n == nil {
		return false
	}
	for _, c := range n.GetChildren() {
		if c.Tag == tag {
			return true
		}
	}
	return false
}

// callChat picks the chat the call belongs to: the group, or the other person (using the chat that already exists,
// @lid or phone number, so the call lands in the same conversation as the messages).
func callChat(client *whatsmeow.Client, store *MessageStore, m types.BasicCallMeta) (chat string, caller types.JID, fromMe bool) {
	caller = m.CallCreator.ToNonAD()
	if caller.IsEmpty() {
		caller = m.From.ToNonAD()
	}
	fromMe = isOwnJID(client, caller)
	if !m.GroupJID.IsEmpty() {
		return m.GroupJID.ToNonAD().String(), caller, fromMe
	}
	peers := []types.JID{}
	if fromMe {
		if f := m.From.ToNonAD(); !f.IsEmpty() && !isOwnJID(client, f) {
			peers = append(peers, f)
		}
	} else {
		peers = append(peers, caller)
		if alt := m.CallCreatorAlt.ToNonAD(); !alt.IsEmpty() {
			peers = append(peers, alt)
		}
		if f := m.From.ToNonAD(); !f.IsEmpty() && !isOwnJID(client, f) {
			peers = append(peers, f)
		}
	}
	if len(peers) == 0 {
		return "", caller, fromMe
	}
	return pickChatJID(client, store, peers), caller, fromMe
}

// pickChatJID returns the first candidate (with its @lid / phone-number twin) that already has a chat row,
// preferring @lid (most direct chats in this store are @lid); otherwise the @lid form if known, else the first one.
func pickChatJID(client *whatsmeow.Client, store *MessageStore, peers []types.JID) string {
	ctx := context.Background()
	cands := []types.JID{}
	add := func(j types.JID) {
		if j.IsEmpty() {
			return
		}
		for _, c := range cands {
			if c == j {
				return
			}
		}
		cands = append(cands, j)
	}
	for _, p := range peers {
		switch p.Server {
		case types.HiddenUserServer:
			add(p)
			if pn, err := client.Store.LIDs.GetPNForLID(ctx, p); err == nil {
				add(pn.ToNonAD())
			}
		case types.DefaultUserServer:
			if lid, err := client.Store.LIDs.GetLIDForPN(ctx, p); err == nil {
				add(lid.ToNonAD())
			}
			add(p)
		default:
			add(p)
		}
	}
	for _, c := range cands {
		var x int
		if store.db.QueryRow("SELECT 1 FROM chats WHERE jid = ?", c.String()).Scan(&x) == nil {
			return c.String()
		}
	}
	for _, c := range cands {
		if c.Server == types.HiddenUserServer {
			return c.String()
		}
	}
	return cands[0].String()
}

func callStarted(client *whatsmeow.Client, m types.BasicCallMeta, video, group bool) {
	callMu.Lock()
	if c := callsByID[m.CallID]; c != nil { // offer + offer_notice for the same call
		c.Video = c.Video || video
		c.Group = c.Group || group
		callMu.Unlock()
		return
	}
	callMu.Unlock()
	chat, caller, fromMe := callChat(client, callStore, m)
	if chat == "" || m.CallID == "" {
		return
	}
	ts := m.Timestamp
	if ts.IsZero() || ts.Year() < 2000 {
		ts = time.Now()
	}
	c := &callInfo{ID: m.CallID, Chat: chat, From: caller.String(), Video: video, Group: group, FromMe: fromMe, Since: ts,
		Status: "ringing", rowID: "call-" + m.CallID}
	callMu.Lock()
	callsByID[m.CallID] = c
	cc := *c
	callMu.Unlock()
	callQueue.enqueue(func() { saveCall(client, callStore, cc, 0, "") })
}

// callEnded closes a call. status "" means: accepted if it was answered, missed otherwise.
func callEnded(client *whatsmeow.Client, m types.BasicCallMeta, status, reason string, dur int) {
	callMu.Lock()
	c := callsByID[m.CallID]
	if c == nil {
		callMu.Unlock()
		// we never saw the offer (bridge restarted mid-call): store what we can
		chat, caller, fromMe := callChat(client, callStore, m)
		if chat == "" || m.CallID == "" {
			return
		}
		ts := m.Timestamp
		if ts.IsZero() || ts.Year() < 2000 {
			ts = time.Now()
		}
		if status == "" {
			status = "missed"
			if dur > 0 || strings.Contains(reason, "accept") {
				status = "accepted"
			}
		}
		cc := callInfo{ID: m.CallID, Chat: chat, From: caller.String(), FromMe: fromMe, Group: !m.GroupJID.IsEmpty(), Since: ts,
			Status: status, rowID: "call-" + m.CallID}
		callQueue.enqueue(func() { saveCall(client, callStore, cc, dur, reason) })
		return
	}
	if status == "" {
		switch {
		case c.Status == "accepted" || dur > 0 || strings.Contains(reason, "accept"):
			status = "accepted"
			if dur == 0 && !c.acceptedAt.IsZero() {
				dur = int(time.Since(c.acceptedAt).Seconds())
			}
		case c.Status == "rejected":
			status = "rejected"
		default:
			status = "missed"
		}
	}
	if status == "rejected" && c.Status == "accepted" { // a late reject after accept does not undo the call
		status = "accepted"
	}
	c.Status = status
	cc := *c
	delete(callsByID, m.CallID)
	callMu.Unlock()
	callQueue.enqueue(func() { saveCall(client, callStore, cc, dur, reason) })
}

// callText is the readable text stored in content (and shown as the chat-list preview).
func callText(video bool, status string, fromMe bool, dur int) string {
	kind := "voz"
	if video {
		kind = "vídeo"
	}
	switch status {
	case "ringing":
		if fromMe {
			return "Chamada de " + kind + " (chamando…)"
		}
		return "Chamada de " + kind + " recebida (tocando…)"
	case "missed":
		if fromMe {
			return "Chamada de " + kind + " não atendida"
		}
		return "Chamada de " + kind + " perdida"
	case "rejected":
		return "Chamada de " + kind + " recusada"
	}
	if dur > 0 {
		return "Chamada de " + kind + " · " + fmtCallDur(dur)
	}
	return "Chamada de " + kind
}

func fmtCallDur(s int) string {
	if s < 60 {
		return fmt.Sprintf("%d s", s)
	}
	if s < 3600 {
		return fmt.Sprintf("%d min", (s+30)/60)
	}
	return fmt.Sprintf("%d h %d min", s/3600, (s%3600)/60)
}

// findCallRow returns the id of an existing call row in chat within callMergeWindow of ts that came from the other
// source (the same call seen as signalling and as a call log). Rows from the same source are never merged: two calls
// in a row are two rows.
func findCallRow(store *MessageStore, chat string, ts time.Time, src string) string {
	rows, err := store.db.Query(`SELECT id, timestamp, COALESCE(json_extract(extra, '$.src'), 'live') FROM messages
		WHERE chat_jid = ? AND media_type = 'call' ORDER BY timestamp DESC LIMIT 20`, chat)
	if err != nil {
		return ""
	}
	defer rows.Close()
	for rows.Next() {
		var id, rsrc string
		var t time.Time
		if rows.Scan(&id, &t, &rsrc) != nil || strings.Contains(rsrc, src) {
			continue
		}
		d := t.Sub(ts)
		if d < 0 {
			d = -d
		}
		if d <= callMergeWindow {
			return id
		}
	}
	return ""
}

// saveCall upserts the call row (runs on the event worker).
func saveCall(client *whatsmeow.Client, store *MessageStore, c callInfo, dur int, reason string) {
	if store == nil || c.Chat == "" {
		return
	}
	id := c.rowID
	if id == "" {
		id = "call-" + c.ID
	}
	src := c.src
	if src == "" {
		src = "live"
	}
	var exists int
	isNew := store.db.QueryRow("SELECT 1 FROM messages WHERE id = ? AND chat_jid = ?", id, c.Chat).Scan(&exists) == sql.ErrNoRows
	merged := false
	if isNew {
		if other := findCallRow(store, c.Chat, c.Since, src); other != "" {
			id, isNew, merged = other, false, true
		}
	}
	extra := map[string]interface{}{"tipo": "chamada", "video": c.Video, "status": c.Status, "duration": dur, "group": c.Group}
	if merged {
		extra["src"] = "live+log"
	} else if isNew {
		extra["src"] = src
	}
	if reason != "" {
		extra["reason"] = reason
	}
	if !isNew && dur == 0 && c.Status == "accepted" { // keep a duration another source already stored
		var old sql.NullString
		if store.db.QueryRow("SELECT extra FROM messages WHERE id = ? AND chat_jid = ?", id, c.Chat).Scan(&old) == nil && old.Valid {
			var o map[string]interface{}
			if json.Unmarshal([]byte(old.String), &o) == nil {
				if d, ok := o["duration"].(float64); ok && d > 0 {
					dur = int(d)
					extra["duration"] = dur
				}
			}
		}
	}
	b, _ := json.Marshal(extra)
	sender := c.From
	if j, err := types.ParseJID(c.From); err == nil {
		sender = j.User
	}
	if isNew {
		// create the chat if needed, and move its last-message time forward only (history calls are older)
		var last sql.NullTime
		err := store.db.QueryRow("SELECT last_message_time FROM chats WHERE jid = ?", c.Chat).Scan(&last)
		if err == sql.ErrNoRows || (err == nil && (!last.Valid || c.Since.After(last.Time))) {
			chatJID, _ := types.ParseJID(c.Chat)
			name := ""
			if client != nil {
				name = GetChatName(client, store, chatJID, c.Chat, nil, sender, callLogger)
			}
			if err := store.StoreChat(c.Chat, name, c.Since); err != nil {
				fmt.Printf("[chamadas] could not store chat %s: %v\n", c.Chat, err)
			}
		}
	}
	_, err := store.db.Exec(`INSERT INTO messages (id, chat_jid, sender, content, timestamp, is_from_me, media_type, extra)
		VALUES (?, ?, ?, ?, ?, ?, 'call', ?)
		ON CONFLICT(id, chat_jid) DO UPDATE SET content = excluded.content, media_type = 'call',
			extra = json_patch(COALESCE(messages.extra, '{}'), excluded.extra)`,
		id, c.Chat, sender, callText(c.Video, c.Status, c.FromMe, dur), c.Since, c.FromMe, string(b))
	if err != nil {
		fmt.Printf("[chamadas] could not store call %s: %v\n", id, err)
		return
	}
	touchChat(store, c.Chat)
	fmt.Printf("[chamadas] %s %s -> %s (video=%v group=%v dur=%ds)\n", id, c.Chat, c.Status, c.Video, c.Group, dur)
}

// callSweeper closes calls that never got a terminate (connection lost, bridge restarted) as missed.
func callSweeper() {
	for range time.Tick(30 * time.Second) {
		callMu.Lock()
		stale := []callInfo{}
		for k, c := range callsByID {
			if time.Since(c.Since) > callRingTimeout && c.Status == "ringing" {
				c.Status = "missed"
				stale = append(stale, *c)
				delete(callsByID, k)
			} else if time.Since(c.Since) > 6*time.Hour { // accepted call whose terminate we never saw
				delete(callsByID, k)
			}
		}
		live := map[string]bool{}
		for _, c := range callsByID {
			live[c.rowID] = true
		}
		callMu.Unlock()
		for _, c := range stale {
			cc := c
			callQueue.enqueue(func() { saveCall(callClient, callStore, cc, 0, "timeout") })
		}
		callQueue.enqueue(func() { closeStaleRingingRows(live) })
	}
}

// closeStaleRingingRows fixes rows left "ringing" in the DB (e.g. by a previous bridge run).
func closeStaleRingingRows(live map[string]bool) {
	rows, err := callStore.db.Query(`SELECT id, chat_jid, timestamp, is_from_me, extra FROM messages
		WHERE media_type = 'call' AND extra LIKE '%"status":"ringing"%'`)
	if err != nil {
		return
	}
	type row struct {
		id, chat, extra string
		ts              time.Time
		me              bool
	}
	list := []row{}
	for rows.Next() {
		var r row
		var ex sql.NullString
		if rows.Scan(&r.id, &r.chat, &r.ts, &r.me, &ex) == nil {
			r.extra = ex.String
			list = append(list, r)
		}
	}
	rows.Close()
	for _, r := range list {
		if live[r.id] || time.Since(r.ts) < callRingTimeout {
			continue
		}
		var x map[string]interface{}
		_ = json.Unmarshal([]byte(r.extra), &x)
		video, _ := x["video"].(bool)
		_, err := callStore.db.Exec(`UPDATE messages SET content = ?, extra = json_set(COALESCE(extra, '{}'), '$.status', 'missed')
			WHERE id = ? AND chat_jid = ?`, callText(video, "missed", r.me, 0), r.id, r.chat)
		if err == nil {
			touchChat(callStore, r.chat)
		}
	}
}

// ---------- call logs that arrive as messages / history ----------

func callLogStatus(o waProto.CallLogMessage_CallOutcome) string {
	switch o {
	case waProto.CallLogMessage_CONNECTED, waProto.CallLogMessage_ACCEPTED_ELSEWHERE:
		return "accepted"
	case waProto.CallLogMessage_REJECTED:
		return "rejected"
	case waProto.CallLogMessage_ONGOING:
		return "accepted"
	default: // MISSED, FAILED, SILENCED_*
		return "missed"
	}
}

// storeCallLogMessage stores a live CallLogMesssage (call summary sent as a message). Returns true if it was one.
func storeCallLogMessage(client *whatsmeow.Client, store *MessageStore, msg *events.Message) bool {
	cl := unwrapStored(msg.Message).GetCallLogMesssage()
	if cl == nil {
		return false
	}
	c := callInfo{ID: msg.Info.ID, Chat: msg.Info.Chat.String(), From: msg.Info.Sender.ToNonAD().String(), Video: cl.GetIsVideo(),
		Group: msg.Info.IsGroup || len(cl.GetParticipants()) > 1, FromMe: msg.Info.IsFromMe, Since: msg.Info.Timestamp,
		Status: callLogStatus(cl.GetCallOutcome()), rowID: "call-" + msg.Info.ID, src: "log"}
	saveCall(client, store, c, int(cl.GetDurationSecs()), "")
	return true
}

// storeHistoryCall stores a call found in history sync: a CallLogMesssage or a missed-call stub. Returns true if stored.
func storeHistoryCall(client *whatsmeow.Client, store *MessageStore, chat types.JID, chatJID string, wmi *waProto.WebMessageInfo) bool {
	if wmi == nil || wmi.GetKey().GetID() == "" || wmi.GetMessageTimestamp() == 0 {
		return false
	}
	ts := time.Unix(int64(wmi.GetMessageTimestamp()), 0)
	fromMe := wmi.GetKey().GetFromMe()
	from := chat.String()
	if p := wmi.GetKey().GetParticipant(); p != "" {
		from = p
	} else if p := wmi.GetParticipant(); p != "" && chat.Server == types.GroupServer {
		from = p
	}
	if fromMe && client.Store.ID != nil {
		from = client.Store.ID.ToNonAD().String()
	}
	c := callInfo{ID: wmi.GetKey().GetID(), Chat: chatJID, From: from, FromMe: fromMe, Since: ts, Group: chat.Server == types.GroupServer,
		rowID: "call-" + wmi.GetKey().GetID(), src: "log"}
	dur := 0
	if cl := unwrapStored(wmi.GetMessage()).GetCallLogMesssage(); cl != nil {
		c.Video, c.Status, dur = cl.GetIsVideo(), callLogStatus(cl.GetCallOutcome()), int(cl.GetDurationSecs())
		c.Group = c.Group || len(cl.GetParticipants()) > 1
	} else {
		switch wmi.GetMessageStubType() {
		case waProto.WebMessageInfo_CALL_MISSED_VOICE:
		case waProto.WebMessageInfo_CALL_MISSED_VIDEO:
			c.Video = true
		case waProto.WebMessageInfo_CALL_MISSED_GROUP_VOICE:
			c.Group = true
		case waProto.WebMessageInfo_CALL_MISSED_GROUP_VIDEO:
			c.Video, c.Group = true, true
		default:
			return false
		}
		c.Status = "missed"
	}
	saveCall(client, store, c, dur, "")
	return true
}
