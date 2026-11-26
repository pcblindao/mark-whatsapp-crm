package main

// Sincronização de histórico (2026-11-22).
//
// 1) configurarHistoricoCompleto(): antes de qualquer pareamento, pede ao celular o MÁXIMO de histórico
//    (RequireFullSync + limites altos em HistorySyncConfig). Só vale para o PRÓXIMO pareamento (QR);
//    não muda nada numa sessão já pareada.
// 2) handleHistorySync(): grava todos os tipos de HistorySync (INITIAL_BOOTSTRAP, RECENT, FULL, ON_DEMAND...)
//    sem duplicar: conversa por PN é gravada no JID que a ponte já usa (LID quando existe mapeamento),
//    remetente no mesmo formato das mensagens ao vivo (só o "user"), chats.last_message_time nunca regride
//    e o nome existente nunca é apagado. PUSH_NAME e mapeamentos LID<->PN o whatsmeow já grava sozinho
//    no whatsapp.db; aqui só contamos.
// 3) GET /api/history/sync-status: progresso da sincronização (para o painel e para conferência).

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waCompanionReg"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"
)

// Limites pedidos ao celular no pareamento. Podem ser trocados por variável de ambiente sem recompilar.
func envU32(name string, def uint32) uint32 {
	if v, err := strconv.ParseUint(strings.TrimSpace(os.Getenv(name)), 10, 32); err == nil && v > 0 {
		return uint32(v)
	}
	return def
}

func configurarHistoricoCompleto() {
	store.DeviceProps.RequireFullSync = proto.Bool(true)
	// Aparece como "Chrome (Mark WhatsApp CRM)" em Aparelhos conectados.
	store.DeviceProps.Os = proto.String("Mark WhatsApp CRM")
	store.DeviceProps.PlatformType = waCompanionReg.DeviceProps_CHROME.Enum()
	hc := store.DeviceProps.HistorySyncConfig
	if hc == nil {
		hc = &waCompanionReg.DeviceProps_HistorySyncConfig{}
		store.DeviceProps.HistorySyncConfig = hc
	}
	hc.FullSyncDaysLimit = proto.Uint32(envU32("HIST_FULL_DAYS", 3650))   // até ~10 anos
	hc.FullSyncSizeMbLimit = proto.Uint32(envU32("HIST_FULL_MB", 20480))  // 20 GB (só texto/metadados vêm no sync)
	hc.StorageQuotaMb = proto.Uint32(envU32("HIST_QUOTA_MB", 20480))
	hc.RecentSyncDaysLimit = proto.Uint32(envU32("HIST_RECENT_DAYS", 3650))
	hc.ThumbnailSyncDaysLimit = proto.Uint32(envU32("HIST_THUMB_DAYS", 3650))
}

// ---- progresso ----

type histStatus struct {
	Events        int            `json:"events"`
	ByType        map[string]int `json:"by_type"`
	LastType      string         `json:"last_type"`
	LastChunk     uint32         `json:"last_chunk"`
	Progress      uint32         `json:"progress"`
	Conversations int            `json:"conversations"`
	Stored        int            `json:"messages_stored"`
	Pushnames     int            `json:"pushnames"`
	LidMappings   int            `json:"lid_mappings"`
	Oldest        *time.Time     `json:"oldest_message,omitempty"`
	FirstAt       *time.Time     `json:"first_event_at,omitempty"`
	LastAt        *time.Time     `json:"last_event_at,omitempty"`
}

var (
	histMu sync.Mutex
	hist   = histStatus{ByType: map[string]int{}}
)

func registerHistorico() {
	http.HandleFunc("/api/history/sync-status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			fail(w, http.StatusMethodNotAllowed, "GET only")
			return
		}
		histMu.Lock()
		out := hist
		bt := map[string]int{}
		for k, v := range hist.ByType {
			bt[k] = v
		}
		out.ByType = bt
		histMu.Unlock()
		cfg := store.DeviceProps.GetHistorySyncConfig()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"status":  out,
			"pair_config": map[string]interface{}{
				"require_full_sync":    store.DeviceProps.GetRequireFullSync(),
				"platform":             store.DeviceProps.GetPlatformType().String(),
				"full_sync_days_limit": cfg.GetFullSyncDaysLimit(),
				"full_sync_size_mb":    cfg.GetFullSyncSizeMbLimit(),
				"storage_quota_mb":     cfg.GetStorageQuotaMb(),
				"recent_sync_days":     cfg.GetRecentSyncDaysLimit(),
			},
		})
	})
}

// ---- normalização de JIDs ----

// userPart: "5511...:12@s.whatsapp.net" -> "5511..." (mesmo formato de msg.Info.Sender.User nas mensagens ao vivo)
func userPart(j string) string {
	return strings.SplitN(strings.SplitN(j, "@", 2)[0], ":", 2)[0]
}

func chatExists(ms *MessageStore, jid string) bool {
	var n int
	_ = ms.db.QueryRow("SELECT COUNT(*) FROM chats WHERE jid = ?", jid).Scan(&n)
	return n > 0
}

// lidFor devolve o LID (string) de um PN usando o mapa do próprio lote ou o whatsapp.db.
func lidFor(client *whatsmeow.Client, pnToLid map[string]string, pn types.JID) string {
	if l, ok := pnToLid[pn.User]; ok && l != "" {
		return l
	}
	if l, err := client.Store.LIDs.GetLIDForPN(context.Background(), pn.ToNonAD()); err == nil && !l.IsEmpty() {
		return l.ToNonAD().String()
	}
	return ""
}

// canonicalChat escolhe em qual chat_jid gravar a conversa, para não dividir a mesma conversa em duas
// (o celular pode mandar conversas antigas pelo número, enquanto as mensagens ao vivo chegam pelo LID).
func canonicalChat(client *whatsmeow.Client, ms *MessageStore, id, lidHint, pnHint string, pnToLid map[string]string) string {
	jid, err := types.ParseJID(id)
	if err != nil || jid.Server != types.DefaultUserServer {
		return id // grupos, LIDs, newsletters: como vieram
	}
	if chatExists(ms, id) {
		return id
	}
	lid := ""
	if lidHint != "" {
		if lj, err := types.ParseJID(lidHint); err == nil && lj.Server == types.HiddenUserServer {
			lid = lj.ToNonAD().String()
		}
	}
	if lid == "" {
		lid = lidFor(client, pnToLid, jid)
	}
	if lid != "" {
		return lid
	}
	_ = pnHint
	return id
}

// storeChatHistory: cria o chat se faltar, nunca regride last_message_time e nunca troca um nome bom.
func storeChatHistory(ms *MessageStore, jid, name string, ts time.Time) {
	_, _ = ms.db.Exec(`INSERT INTO chats (jid, name, last_message_time) VALUES (?, ?, ?)
		ON CONFLICT(jid) DO UPDATE SET
		  name = CASE WHEN chats.name IS NULL OR chats.name = '' OR chats.name = ? THEN excluded.name ELSE chats.name END,
		  last_message_time = CASE WHEN chats.last_message_time IS NULL OR excluded.last_message_time > chats.last_message_time
		                           THEN excluded.last_message_time ELSE chats.last_message_time END`,
		jid, name, ts, userPart(jid))
}

// ---- gravação ----

func handleHistorySync(client *whatsmeow.Client, messageStore *MessageStore, historySync *events.HistorySync, logger waLog.Logger) {
	data := historySync.Data
	syncType := data.GetSyncType().String()
	now := time.Now()

	pnToLid := map[string]string{}
	for _, m := range data.GetPhoneNumberToLidMappings() {
		pn, lid := m.GetPnJID(), m.GetLidJID()
		if pn == "" || lid == "" {
			continue
		}
		if lj, err := types.ParseJID(lid); err == nil {
			pnToLid[userPart(pn)] = lj.ToNonAD().String()
		}
	}

	syncedCount, convs := 0, 0
	var oldest time.Time
	for _, conversation := range data.GetConversations() {
		if conversation.ID == nil {
			continue
		}
		origJID := conversation.GetID()
		chatJID := canonicalChat(client, messageStore, origJID, conversation.GetLidJID(), conversation.GetPnJID(), pnToLid)
		jid, err := types.ParseJID(chatJID)
		if err != nil {
			logger.Warnf("Failed to parse JID %s: %v", chatJID, err)
			continue
		}
		convs++
		isGroup := jid.Server == types.GroupServer

		name := GetChatName(client, messageStore, jid, chatJID, conversation, "", logger)

		messages := conversation.GetMessages()
		var latest time.Time
		for _, msg := range messages {
			if ts := msg.GetMessage().GetMessageTimestamp(); ts != 0 {
				if t := time.Unix(int64(ts), 0); t.After(latest) {
					latest = t
				}
			}
		}
		if latest.IsZero() {
			if ts := conversation.GetConversationTimestamp(); ts != 0 {
				latest = time.Unix(int64(ts), 0)
			} else if ts := conversation.GetLastMsgTimestamp(); ts != 0 {
				latest = time.Unix(int64(ts), 0)
			}
		}
		if !latest.IsZero() {
			storeChatHistory(messageStore, chatJID, name, latest)
		}

		for _, msg := range messages {
			wmi := msg.GetMessage()
			if wmi == nil {
				continue
			}
			var content string
			var mediaType, filename, url string
			var mediaKey, fileSHA256, fileEncSHA256 []byte
			var fileLength uint64
			if wmi.Message != nil {
				m := unwrapStored(wmi.Message)
				content = extractTextContent(m)
				mediaType, filename, url, mediaKey, fileSHA256, fileEncSHA256, fileLength = extractMediaInfo(m)
			}
			if content == "" && mediaType == "" {
				// chamadas viram linhas de chamada (chamadas.go); stubs vazios são ignorados
				if storeHistoryCall(client, messageStore, jid, chatJID, wmi) {
					syncedCount++
				}
				continue
			}
			ts := wmi.GetMessageTimestamp()
			msgID := wmi.GetKey().GetID()
			if ts == 0 || msgID == "" {
				continue
			}
			timestamp := time.Unix(int64(ts), 0)

			isFromMe := wmi.GetKey().GetFromMe()
			var sender string
			switch {
			case isFromMe:
				sender = client.Store.ID.User
			case isGroup:
				p := wmi.GetKey().GetParticipant()
				if p == "" {
					p = wmi.GetParticipant()
				}
				if pj, err := types.ParseJID(p); err == nil && pj.Server == types.DefaultUserServer {
					if l := lidFor(client, pnToLid, pj); l != "" {
						p = l // ao vivo, grupos chegam com o remetente em LID
					}
				}
				sender = userPart(p)
				if sender == "" {
					sender = jid.User
				}
			default:
				sender = jid.User
			}

			if err := messageStore.StoreMessage(msgID, chatJID, sender, content, timestamp, isFromMe,
				mediaType, filename, url, mediaKey, fileSHA256, fileEncSHA256, fileLength); err != nil {
				logger.Warnf("Failed to store history message %s in %s: %v", msgID, chatJID, err)
				continue
			}
			syncedCount++
			storeHistoryExtras(client, messageStore, chatJID, msgID, isFromMe, wmi)
			if oldest.IsZero() || timestamp.Before(oldest) {
				oldest = timestamp
			}
		}
	}

	histMu.Lock()
	hist.Events++
	hist.ByType[syncType]++
	hist.LastType = syncType
	hist.LastChunk = data.GetChunkOrder()
	hist.Progress = data.GetProgress()
	hist.Conversations += convs
	hist.Stored += syncedCount
	hist.Pushnames += len(data.GetPushnames())
	hist.LidMappings += len(pnToLid)
	if !oldest.IsZero() && (hist.Oldest == nil || oldest.Before(*hist.Oldest)) {
		o := oldest
		hist.Oldest = &o
	}
	if hist.FirstAt == nil {
		hist.FirstAt = &now
	}
	hist.LastAt = &now
	total := hist.Stored
	histMu.Unlock()

	oldestTxt := "-"
	if !oldest.IsZero() {
		oldestTxt = oldest.Format("2006-01-02")
	}
	logger.Infof("[historico] %s chunk=%d progresso=%d%%: %d conversas, %d mensagens gravadas (mais antiga %s), %d pushnames, %d LID/PN; total na sessão %d",
		syncType, data.GetChunkOrder(), data.GetProgress(), convs, syncedCount, oldestTxt, len(data.GetPushnames()), len(pnToLid), total)
}
