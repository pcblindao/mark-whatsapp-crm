package main

// Diagnostics for edits / deletions (investigation of edits that never reached the recipient, 2026-11-19).
// - every edit we send is remembered; receipts for that edit stanza are logged ([edit-diag])
// - protocol messages (edit/revoke) that arrive from our own phone are logged raw
// - "delete for me" done on the phone (app-state) is recorded

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var (
	editWatchMu sync.Mutex
	editWatch   = map[string]string{} // edit stanza id -> "chat|original id"
)

func watchEdit(stanzaID, chat, original string) {
	editWatchMu.Lock()
	editWatch[stanzaID] = chat + "|" + original
	editWatchMu.Unlock()
}

// lastEditReceipts keeps the receipts seen for each watched edit stanza (exposed by /api/edit-status).
var lastEditReceipts = map[string][]string{}

func diagReceipt(v *events.Receipt) {
	editWatchMu.Lock()
	defer editWatchMu.Unlock()
	for _, id := range v.MessageIDs {
		if info, ok := editWatch[id]; ok {
			line := fmt.Sprintf("%s type=%q from=%s chat=%s", v.Timestamp.Format("15:04:05"), string(v.Type), v.Sender.String(), v.Chat.String())
			lastEditReceipts[id] = append(lastEditReceipts[id], line)
			fmt.Printf("[edit-diag] receipt for edit %s (%s): %s\n", id, info, line)
		}
	}
}

func protoJSON(m proto.Message) string {
	b, err := protojson.MarshalOptions{EmitUnpopulated: false}.Marshal(m)
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(b)
}

func diagProtocolMessage(evt *events.Message) {
	fmt.Printf("[edit-diag] protocol message chat=%s sender=%s fromMe=%v isEdit=%v id=%s raw=%s\n",
		evt.Info.Chat.String(), evt.Info.Sender.String(), evt.Info.IsFromMe, evt.IsEdit, evt.Info.ID, protoJSON(evt.RawMessage))
}

func handleDeleteForMe(store *MessageStore, v *events.DeleteForMe) {
	fmt.Printf("[%s] message %s deleted for me (chat %s, fromMe=%v, fullSync=%v)\n",
		time.Now().Format("2006-01-02 15:04:05"), v.MessageID, v.ChatJID.String(), v.IsFromMe, v.FromFullSync)
	if v.FromFullSync {
		return
	}
	chat := v.ChatJID.String()
	// revoked=2 means "apagada só no celular" (the other side may still see it)
	res, _ := store.db.Exec("UPDATE messages SET revoked=2 WHERE id=? AND COALESCE(revoked,0)=0", v.MessageID)
	if res != nil {
		if n, _ := res.RowsAffected(); n > 0 {
			touchChat(store, chat)
		}
	}
}

// editTestChat: while edits are not verified, they are only allowed in Marcos's own chat and the "Arquivos" group.
func editTestChat(own bool, j types.JID) bool {
	return own
}

// withMessageSecret adds a random messageSecret (official clients always send one; whatsmeow stores it on send).
func withMessageSecret(m *waE2E.Message) {
	if m == nil {
		return
	}
	if m.MessageContextInfo == nil {
		m.MessageContextInfo = &waE2E.MessageContextInfo{}
	}
	if len(m.MessageContextInfo.MessageSecret) == 0 {
		sec := make([]byte, 32)
		if _, err := rand.Read(sec); err == nil {
			m.MessageContextInfo.MessageSecret = sec
		}
	}
}

// handleSecretEncrypted applies encrypted edits (newer WhatsApp clients send edits as SecretEncryptedMessage).
func handleSecretEncrypted(client *whatsmeow.Client, store *MessageStore, evt *events.Message) {
	enc := evt.Message.GetSecretEncryptedMessage()
	target := enc.GetTargetMessageKey().GetID()
	fmt.Printf("[edit-diag] secret-encrypted %s chat=%s sender=%s fromMe=%v target=%s\n",
		enc.GetSecretEncType().String(), evt.Info.Chat, evt.Info.Sender, evt.Info.IsFromMe, target)
	if enc.GetSecretEncType() != waE2E.SecretEncryptedMessage_MESSAGE_EDIT {
		return
	}
	dec, err := client.DecryptSecretEncryptedMessage(context.Background(), evt)
	if err != nil {
		fmt.Printf("[edit-diag] could not decrypt edit of %s: %v\n", target, err)
		return
	}
	newContent := dec
	if pm := dec.GetProtocolMessage(); pm != nil && pm.GetEditedMessage() != nil {
		newContent = pm.GetEditedMessage()
	}
	txt := extractTextContent(newContent)
	fmt.Printf("[edit-diag] decrypted edit of %s: %s (raw %s)\n", target, txt, protoJSON(dec))
	if txt == "" {
		return
	}
	if _, err := store.db.Exec("UPDATE messages SET content=?, edited=1 WHERE id=?", txt, target); err == nil {
		touchChat(store, evt.Info.Chat.String())
		fmt.Printf("[%s] message %s edited: %s\n", evt.Info.Timestamp.Format("2006-01-02 15:04:05"), target, txt)
	}
}

// diagUnhandled logs our own messages that carry no text/media (unknown formats are no longer dropped silently).
func diagUnhandled(evt *events.Message) {
	j := protoJSON(evt.RawMessage)
	if len(j) > 800 {
		j = j[:800] + "..."
	}
	fmt.Printf("[edit-diag] unhandled own message %s chat=%s: %s\n", evt.Info.ID, evt.Info.Chat, j)
}
