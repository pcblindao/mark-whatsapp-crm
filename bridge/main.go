package main

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"bytes"

	"errors"
	"sync"

	"go.mau.fi/whatsmeow"
	waProto "go.mau.fi/whatsmeow/binary/proto"
	"go.mau.fi/whatsmeow/proto/waMmsRetry"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"
)

// Message represents a chat message for our client
type Message struct {
	Time      time.Time
	Sender    string
	Content   string
	IsFromMe  bool
	MediaType string
	Filename  string
}

// Database handler for storing message history
type MessageStore struct {
	db *sql.DB
}

// Initialize message store
func NewMessageStore() (*MessageStore, error) {
	// Create directory for database if it doesn't exist
	if err := os.MkdirAll(storeDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create store directory: %v", err)
	}

	// Open SQLite database for messages
	db, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(storeDir)+"/messages.db?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open message database: %v", err)
	}

	// Create tables if they don't exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS chats (
			jid TEXT PRIMARY KEY,
			name TEXT,
			last_message_time TIMESTAMP
		);
		
		CREATE TABLE IF NOT EXISTS messages (
			id TEXT,
			chat_jid TEXT,
			sender TEXT,
			content TEXT,
			timestamp TIMESTAMP,
			is_from_me BOOLEAN,
			media_type TEXT,
			filename TEXT,
			url TEXT,
			media_key BLOB,
			file_sha256 BLOB,
			file_enc_sha256 BLOB,
			file_length INTEGER,
			PRIMARY KEY (id, chat_jid),
			FOREIGN KEY (chat_jid) REFERENCES chats(jid)
		);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create tables: %v", err)
	}
	migrateSchema(db)

	return &MessageStore{db: db}, nil
}

// Close the database connection
func (store *MessageStore) Close() error {
	return store.db.Close()
}

// Store a chat in the database
func (store *MessageStore) StoreChat(jid, name string, lastMessageTime time.Time) error {
	_, err := store.db.Exec(
		"INSERT OR REPLACE INTO chats (jid, name, last_message_time) VALUES (?, ?, ?)",
		jid, name, lastMessageTime,
	)
	return err
}

// Store a message in the database
func (store *MessageStore) StoreMessage(id, chatJID, sender, content string, timestamp time.Time, isFromMe bool,
	mediaType, filename, url string, mediaKey, fileSHA256, fileEncSHA256 []byte, fileLength uint64) error {
	// Only store if there's actual content or media
	if content == "" && mediaType == "" {
		return nil
	}

	// Upsert (not REPLACE) so panel columns like status/edited/revoked survive a re-delivery
	_, err := store.db.Exec(
		`INSERT INTO messages
		(id, chat_jid, sender, content, timestamp, is_from_me, media_type, filename, url, media_key, file_sha256, file_enc_sha256, file_length)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id, chat_jid) DO UPDATE SET sender=excluded.sender,
			content=CASE WHEN COALESCE(messages.edited,0)=1 THEN messages.content ELSE excluded.content END,
			timestamp=excluded.timestamp, is_from_me=excluded.is_from_me, media_type=excluded.media_type, filename=excluded.filename,
			url=excluded.url, media_key=excluded.media_key, file_sha256=excluded.file_sha256, file_enc_sha256=excluded.file_enc_sha256,
			file_length=excluded.file_length`,
		id, chatJID, sender, content, timestamp, isFromMe, mediaType, filename, url, mediaKey, fileSHA256, fileEncSHA256, fileLength,
	)
	return err
}

// Get messages from a chat
func (store *MessageStore) GetMessages(chatJID string, limit int) ([]Message, error) {
	rows, err := store.db.Query(
		"SELECT sender, content, timestamp, is_from_me, media_type, filename FROM messages WHERE chat_jid = ? ORDER BY timestamp DESC LIMIT ?",
		chatJID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var msg Message
		var timestamp time.Time
		err := rows.Scan(&msg.Sender, &msg.Content, &timestamp, &msg.IsFromMe, &msg.MediaType, &msg.Filename)
		if err != nil {
			return nil, err
		}
		msg.Time = timestamp
		messages = append(messages, msg)
	}

	return messages, nil
}

// Get all chats
func (store *MessageStore) GetChats() (map[string]time.Time, error) {
	rows, err := store.db.Query("SELECT jid, last_message_time FROM chats ORDER BY last_message_time DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	chats := make(map[string]time.Time)
	for rows.Next() {
		var jid string
		var lastMessageTime time.Time
		err := rows.Scan(&jid, &lastMessageTime)
		if err != nil {
			return nil, err
		}
		chats[jid] = lastMessageTime
	}

	return chats, nil
}

// Extract text content from a message
func extractTextContent(msg *waProto.Message) string {
	if msg == nil {
		return ""
	}

	// Try to get text content
	if text := msg.GetConversation(); text != "" {
		return text
	} else if extendedText := msg.GetExtendedTextMessage(); extendedText != nil {
		return extendedText.GetText()
	}

	// Captions and other message kinds that carry readable text
	switch {
	case msg.GetImageMessage() != nil:
		return msg.GetImageMessage().GetCaption()
	case msg.GetVideoMessage() != nil:
		return msg.GetVideoMessage().GetCaption()
	case msg.GetDocumentMessage() != nil:
		return msg.GetDocumentMessage().GetCaption()
	case msg.GetLocationMessage() != nil:
		l := msg.GetLocationMessage()
		t := strings.TrimSpace(l.GetName() + " " + l.GetAddress())
		if t == "" {
			t = fmt.Sprintf("%.6f, %.6f", l.GetDegreesLatitude(), l.GetDegreesLongitude())
		}
		return "📍 " + t
	case msg.GetLiveLocationMessage() != nil:
		return "📍 Localização em tempo real"
	case msg.GetContactMessage() != nil:
		return "👤 " + msg.GetContactMessage().GetDisplayName()
	case msg.GetContactsArrayMessage() != nil:
		return fmt.Sprintf("👤 %d contatos", len(msg.GetContactsArrayMessage().GetContacts()))
	case msg.GetPollCreationMessage() != nil:
		return "📊 " + msg.GetPollCreationMessage().GetName()
	case msg.GetPollCreationMessageV3() != nil:
		return "📊 " + msg.GetPollCreationMessageV3().GetName()
	}
	return ""
}

// SendMessageResponse represents the response for the send message API
type SendMessageResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	ID        string `json:"id,omitempty"`        // id of the sent message (new, optional)
	Timestamp int64  `json:"timestamp,omitempty"` // unix seconds (new, optional)
}

// SendLocation / SendContact are optional payloads of /api/send
type SendLocation struct {
	Lat     float64 `json:"lat"`
	Lng     float64 `json:"lng"`
	Name    string  `json:"name,omitempty"`
	Address string  `json:"address,omitempty"`
}
type SendContact struct {
	Name  string `json:"name"`
	VCard string `json:"vcard"`
}

// SendMessageRequest represents the request body for the send message API.
// Only recipient/message/media_path are required by old clients; everything else is optional.
type SendMessageRequest struct {
	Recipient string `json:"recipient"`
	Message   string `json:"message"`
	MediaPath string `json:"media_path,omitempty"`

	Filename  string        `json:"filename,omitempty"`  // name shown to the recipient for documents
	Seconds   uint32        `json:"seconds,omitempty"`   // audio/video duration
	Waveform  []byte        `json:"waveform,omitempty"`  // voice note waveform (64 values 0-100, base64 in JSON)
	PTT       *bool         `json:"ptt,omitempty"`       // force voice note on/off (default: .ogg/.opus = voice note)
	Thumbnail []byte        `json:"thumbnail,omitempty"` // small JPEG preview (base64 in JSON)
	Width     uint32        `json:"width,omitempty"`
	Height    uint32        `json:"height,omitempty"`
	ReplyTo   string        `json:"reply_to,omitempty"` // id of a message in the same chat to quote
	Mentions  []string      `json:"mentions,omitempty"` // JIDs mentioned with @ in the text
	Forwarded bool          `json:"forwarded,omitempty"`
	Location  *SendLocation `json:"location,omitempty"`
	Contact   *SendContact  `json:"contact,omitempty"`
}

// Function to send a WhatsApp message (kept for compatibility)
func sendWhatsAppMessage(client *whatsmeow.Client, recipient string, message string, mediaPath string) (bool, string) {
	r := sendWhatsAppMessageEx(client, SendMessageRequest{Recipient: recipient, Message: message, MediaPath: mediaPath})
	return r.Success, r.Message
}

func sendWhatsAppMessageEx(client *whatsmeow.Client, req SendMessageRequest) SendMessageResponse {
	failed := func(format string, a ...interface{}) SendMessageResponse {
		return SendMessageResponse{Success: false, Message: fmt.Sprintf(format, a...)}
	}
	if !client.IsConnected() {
		return failed("Not connected to WhatsApp")
	}
	recipient, message, mediaPath := req.Recipient, req.Message, req.MediaPath

	recipientJID, err := parseRecipient(recipient)
	if err != nil {
		return failed("Error parsing JID: %v", err)
	}

	msg := &waProto.Message{}
	var sentMedia *sentMediaInfo
	displayName := filepath.Base(mediaPath)
	if req.Filename != "" {
		displayName = filepath.Base(req.Filename)
	}

	switch {
	case mediaPath != "":
		// Read media file
		mediaData, err := os.ReadFile(mediaPath)
		if err != nil {
			return failed("Error reading media file: %v", err)
		}

		// Determine media type and mime type based on file extension
		fileExt := strings.ToLower(mediaPath[strings.LastIndex(mediaPath, ".")+1:])
		var mediaType whatsmeow.MediaType
		var mimeType string

		// Handle different media types
		switch fileExt {
		// Image types
		case "jpg", "jpeg":
			mediaType = whatsmeow.MediaImage
			mimeType = "image/jpeg"
		case "png":
			mediaType = whatsmeow.MediaImage
			mimeType = "image/png"
		case "gif":
			mediaType = whatsmeow.MediaImage
			mimeType = "image/gif"
		case "webp":
			mediaType = whatsmeow.MediaImage
			mimeType = "image/webp"

		// Audio types
		case "ogg", "opus":
			mediaType = whatsmeow.MediaAudio
			mimeType = "audio/ogg; codecs=opus"
		case "mp3":
			mediaType = whatsmeow.MediaAudio
			mimeType = "audio/mpeg"
		case "m4a":
			mediaType = whatsmeow.MediaAudio
			mimeType = "audio/mp4"
		case "webm":
			mediaType = whatsmeow.MediaVideo
			mimeType = "video/webm"

		// Video types
		case "mp4":
			mediaType = whatsmeow.MediaVideo
			mimeType = "video/mp4"
		case "avi":
			mediaType = whatsmeow.MediaVideo
			mimeType = "video/avi"
		case "mov":
			mediaType = whatsmeow.MediaVideo
			mimeType = "video/quicktime"

		// Document types (for any other file type)
		default:
			mediaType = whatsmeow.MediaDocument
			mimeType = "application/octet-stream"
			if mt := mime.TypeByExtension("." + fileExt); mt != "" {
				mimeType = mt
			}
		}
		// Stickers: files named *.sticker.webp are sent as WhatsApp stickers
		isSticker := strings.HasSuffix(strings.ToLower(mediaPath), ".sticker.webp")
		if isSticker {
			mediaType = whatsmeow.MediaImage
		}

		// Upload media to WhatsApp servers
		resp, err := client.Upload(context.Background(), mediaData, mediaType)
		if err != nil {
			return failed("Error uploading media: %v", err)
		}

		fmt.Println("Media uploaded", resp)

		sentMedia = &sentMediaInfo{url: resp.URL, mediaKey: resp.MediaKey, sha: resp.FileSHA256, encSha: resp.FileEncSHA256, length: resp.FileLength}
		optU32 := func(v uint32) *uint32 {
			if v == 0 {
				return nil
			}
			return proto.Uint32(v)
		}

		// Create the appropriate message type based on media type
		switch {
		case isSticker:
			msg.StickerMessage = &waProto.StickerMessage{
				Mimetype:      proto.String("image/webp"),
				URL:           &resp.URL,
				DirectPath:    &resp.DirectPath,
				MediaKey:      resp.MediaKey,
				FileEncSHA256: resp.FileEncSHA256,
				FileSHA256:    resp.FileSHA256,
				FileLength:    &resp.FileLength,
				MediaKeyTimestamp: proto.Int64(time.Now().Unix()), // obrigatório para o iPhone conseguir baixar a mídia
				Width:         proto.Uint32(512),
				Height:        proto.Uint32(512),
			}
			if webpAnimado(mediaData) { // [figurinhas] sem isso o WhatsApp mostra só o 1º quadro
				msg.StickerMessage.IsAnimated = proto.Bool(true)
			}
			sentMedia.kind = "sticker"
		case mediaType == whatsmeow.MediaImage:
			msg.ImageMessage = &waProto.ImageMessage{
				Caption:       proto.String(message),
				Mimetype:      proto.String(mimeType),
				URL:           &resp.URL,
				DirectPath:    &resp.DirectPath,
				MediaKey:      resp.MediaKey,
				FileEncSHA256: resp.FileEncSHA256,
				FileSHA256:    resp.FileSHA256,
				FileLength:    &resp.FileLength,
				MediaKeyTimestamp: proto.Int64(time.Now().Unix()), // obrigatório para o iPhone conseguir baixar a mídia
				JPEGThumbnail: req.Thumbnail,
				Width:         optU32(req.Width),
				Height:        optU32(req.Height),
			}
			sentMedia.kind = "image"
		case mediaType == whatsmeow.MediaAudio:
			// Handle ogg audio files
			var seconds uint32 = 30 // Default fallback
			var waveform []byte = nil
			isPTT := strings.Contains(mimeType, "ogg")
			if req.PTT != nil {
				isPTT = *req.PTT && strings.Contains(mimeType, "ogg")
			}
			sentMedia.kind = "audio"

			// Try to analyze the ogg file
			if strings.Contains(mimeType, "ogg") {
				analyzedSeconds, analyzedWaveform, err := analyzeOggOpus(mediaData)
				if err == nil {
					seconds = analyzedSeconds
					waveform = analyzedWaveform
				} else {
					return failed("Failed to analyze Ogg Opus file: %v", err)
				}
			} else {
				fmt.Printf("Not an Ogg Opus file: %s\n", mimeType)
			}
			if req.Seconds > 0 {
				seconds = req.Seconds
			}
			if len(req.Waveform) == 64 {
				waveform = req.Waveform
			}
			if !isPTT {
				waveform = nil
			}

			msg.AudioMessage = &waProto.AudioMessage{
				Mimetype:      proto.String(mimeType),
				URL:           &resp.URL,
				DirectPath:    &resp.DirectPath,
				MediaKey:      resp.MediaKey,
				FileEncSHA256: resp.FileEncSHA256,
				FileSHA256:    resp.FileSHA256,
				FileLength:    &resp.FileLength,
				MediaKeyTimestamp: proto.Int64(time.Now().Unix()), // obrigatório para o iPhone conseguir baixar a mídia
				Seconds:       proto.Uint32(seconds),
				PTT:           proto.Bool(isPTT),
				Waveform:      waveform,
			}
		case mediaType == whatsmeow.MediaVideo:
			sentMedia.kind = "video"
			msg.VideoMessage = &waProto.VideoMessage{
				Caption:       proto.String(message),
				Mimetype:      proto.String(mimeType),
				URL:           &resp.URL,
				DirectPath:    &resp.DirectPath,
				MediaKey:      resp.MediaKey,
				FileEncSHA256: resp.FileEncSHA256,
				FileSHA256:    resp.FileSHA256,
				FileLength:    &resp.FileLength,
				MediaKeyTimestamp: proto.Int64(time.Now().Unix()), // obrigatório para o iPhone conseguir baixar a mídia
				JPEGThumbnail: req.Thumbnail,
				Width:         optU32(req.Width),
				Height:        optU32(req.Height),
				Seconds:       optU32(req.Seconds),
			}
		case mediaType == whatsmeow.MediaDocument:
			sentMedia.kind = "document"
			if req.Filename != "" {
				if mt := mime.TypeByExtension(strings.ToLower(filepath.Ext(displayName))); mt != "" {
					mimeType = mt
				}
			}
			msg.DocumentMessage = &waProto.DocumentMessage{
				Title:         proto.String(displayName),
				FileName:      proto.String(displayName),
				Caption:       proto.String(message),
				Mimetype:      proto.String(mimeType),
				URL:           &resp.URL,
				DirectPath:    &resp.DirectPath,
				MediaKey:      resp.MediaKey,
				FileEncSHA256: resp.FileEncSHA256,
				FileSHA256:    resp.FileSHA256,
				FileLength:    &resp.FileLength,
				MediaKeyTimestamp: proto.Int64(time.Now().Unix()), // obrigatório para o iPhone conseguir baixar a mídia
				JPEGThumbnail: req.Thumbnail,
			}
		}
	case req.Location != nil:
		msg.LocationMessage = &waProto.LocationMessage{
			DegreesLatitude:  proto.Float64(req.Location.Lat),
			DegreesLongitude: proto.Float64(req.Location.Lng),
		}
		if req.Location.Name != "" {
			msg.LocationMessage.Name = proto.String(req.Location.Name)
		}
		if req.Location.Address != "" {
			msg.LocationMessage.Address = proto.String(req.Location.Address)
		}
	case req.Contact != nil:
		msg.ContactMessage = &waProto.ContactMessage{DisplayName: proto.String(req.Contact.Name), Vcard: proto.String(req.Contact.VCard)}
	default:
		msg.Conversation = proto.String(message)
	}

	// Reply / mentions / forwarded flag
	if req.ReplyTo != "" || len(req.Mentions) > 0 || req.Forwarded {
		ci := &waProto.ContextInfo{}
		if req.ReplyTo != "" && globalStore != nil {
			if rc, err := replyContext(client, globalStore, recipientJID, req.ReplyTo); err == nil {
				ci = rc
			} else {
				return failed("Cannot reply: %v", err)
			}
		}
		if len(req.Mentions) > 0 {
			ci.MentionedJID = req.Mentions
		}
		if req.Forwarded {
			ci.IsForwarded = proto.Bool(true)
			ci.ForwardingScore = proto.Uint32(1)
		}
		setContextInfo(msg, ci)
	}

	// Send message (with a messageSecret, like the official apps, so edits/replies can be authenticated)
	withMessageSecret(msg)
	sendResp, err := client.SendMessage(context.Background(), recipientJID, msg)

	if err != nil {
		return failed("Error sending message: %v", err)
	}

	// Save our own sent message so it shows up in the local history/panel
	storeSent(client, recipientJID, sendResp, msg, sentMedia, mediaPath, displayName)

	ts := sendResp.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	return SendMessageResponse{Success: true, Message: fmt.Sprintf("Message sent to %s", recipient), ID: sendResp.ID, Timestamp: ts.Unix()}
}

// storeSent saves a message we sent (with a local copy of its media) so the panel shows it immediately.
func storeSent(client *whatsmeow.Client, recipientJID types.JID, sendResp whatsmeow.SendResponse, msg *waProto.Message, sentMedia *sentMediaInfo, mediaPath, fname string) {
	if globalStore == nil {
		return
	}
	ts := sendResp.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	chatJID := recipientJID.String()
	sender := ""
	if client.Store.ID != nil {
		sender = client.Store.ID.User
	}
	kind, url := "", ""
	var key, sha, encSha []byte
	var length uint64
	if sentMedia != nil {
		kind, url, key, sha, encSha, length = sentMedia.kind, sentMedia.url, sentMedia.mediaKey, sentMedia.sha, sentMedia.encSha, sentMedia.length
	}
	if mediaPath != "" {
		// keep a local copy so the panel can show it without downloading
		ext := filepath.Ext(fname)
		if ext == "" {
			ext = filepath.Ext(mediaPath)
		}
		chatDir := fmt.Sprintf("%s/%s", storeDir, strings.ReplaceAll(chatJID, ":", "_"))
		if os.MkdirAll(chatDir, 0755) == nil {
			if data, rerr := os.ReadFile(mediaPath); rerr == nil {
				_ = os.WriteFile(fmt.Sprintf("%s/%s%s", chatDir, sendResp.ID, ext), data, 0644)
			}
		}
	}
	if kind == "" {
		fname = ""
	}
	content := extractTextContent(msg)
	// chat row must exist first (messages has a foreign key to chats)
	_, _ = globalStore.db.Exec(`INSERT OR IGNORE INTO chats (jid, name, last_message_time) VALUES (?, ?, ?)`, chatJID, recipientJID.User, ts)
	_, _ = globalStore.db.Exec(`UPDATE chats SET last_message_time = ? WHERE jid = ?`, ts, chatJID)
	if content == "" && kind == "" {
		content = " " // StoreMessage skips empty rows
	}
	if serr := globalStore.StoreMessage(sendResp.ID, chatJID, sender, content, ts, true, kind, fname, url, key, sha, encSha, length); serr != nil {
		fmt.Printf("Warning: could not store sent message: %v\n", serr)
		return
	}
	globalStore.StoreMeta(sendResp.ID, chatJID, extractMeta(msg))
	_, _ = globalStore.db.Exec("UPDATE messages SET status = 2 WHERE id = ? AND chat_jid = ? AND COALESCE(status,0) < 2", sendResp.ID, chatJID)
}

type sentMediaInfo struct {
	kind, url        string
	mediaKey, sha    []byte
	encSha           []byte
	length           uint64
}

var globalStore *MessageStore

// Extract media info from a message
func extractMediaInfo(msg *waProto.Message) (mediaType string, filename string, url string, mediaKey []byte, fileSHA256 []byte, fileEncSHA256 []byte, fileLength uint64) {
	if msg == nil {
		return "", "", "", nil, nil, nil, 0
	}

	// Check for image message
	if img := msg.GetImageMessage(); img != nil {
		return "image", "image_" + time.Now().Format("20060102_150405") + ".jpg",
			img.GetURL(), img.GetMediaKey(), img.GetFileSHA256(), img.GetFileEncSHA256(), img.GetFileLength()
	}

	// Check for video message
	if vid := msg.GetVideoMessage(); vid != nil {
		return "video", "video_" + time.Now().Format("20060102_150405") + ".mp4",
			vid.GetURL(), vid.GetMediaKey(), vid.GetFileSHA256(), vid.GetFileEncSHA256(), vid.GetFileLength()
	}

	// Check for audio message
	if aud := msg.GetAudioMessage(); aud != nil {
		return "audio", "audio_" + time.Now().Format("20060102_150405") + ".ogg",
			aud.GetURL(), aud.GetMediaKey(), aud.GetFileSHA256(), aud.GetFileEncSHA256(), aud.GetFileLength()
	}

	// Check for document message
	if doc := msg.GetDocumentMessage(); doc != nil {
		filename := doc.GetFileName()
		if filename == "" {
			filename = "document_" + time.Now().Format("20060102_150405")
		}
		return "document", filename,
			doc.GetURL(), doc.GetMediaKey(), doc.GetFileSHA256(), doc.GetFileEncSHA256(), doc.GetFileLength()
	}

	// Check for sticker message
	if st := msg.GetStickerMessage(); st != nil {
		return "sticker", "sticker_" + time.Now().Format("20060102_150405") + ".webp",
			st.GetURL(), st.GetMediaKey(), st.GetFileSHA256(), st.GetFileEncSHA256(), st.GetFileLength()
	}

	return "", "", "", nil, nil, nil, 0
}

// Handle regular incoming messages with media support
func handleMessage(client *whatsmeow.Client, messageStore *MessageStore, msg *events.Message, logger waLog.Logger) {
	// Save message to database
	chatJID := msg.Info.Chat.String()
	sender := msg.Info.Sender.User

	// Reactions, edits and "delete for everyone" update existing rows instead of creating messages
	if handleSpecialMessage(client, messageStore, msg) {
		return
	}

	// Extract text content
	content := extractTextContent(msg.Message)

	// Extract media info
	mediaType, filename, url, mediaKey, fileSHA256, fileEncSHA256, fileLength := extractMediaInfo(msg.Message)

	// Skip if there's no content and no media (sender-key distribution, protocol messages...).
	// Checked before the chat lookup/update: those cost DB time for events that store nothing.
	if content == "" && mediaType == "" {
		if storeCallLogMessage(client, messageStore, msg) { // call summary (chamadas.go)
			return
		}
		if msg.Info.IsFromMe {
			diagUnhandled(msg)
		}
		return
	}

	// Get appropriate chat name (pass nil for conversation since we don't have one for regular messages)
	name := GetChatName(client, messageStore, msg.Info.Chat, chatJID, nil, sender, logger)

	// Update chat in database with the message timestamp (keeps last message time updated)
	err := messageStore.StoreChat(chatJID, name, msg.Info.Timestamp)
	if err != nil {
		logger.Warnf("Failed to store chat: %v", err)
	}

	// Store message in database
	err = messageStore.StoreMessage(
		msg.Info.ID,
		chatJID,
		sender,
		content,
		msg.Info.Timestamp,
		msg.Info.IsFromMe,
		mediaType,
		filename,
		url,
		mediaKey,
		fileSHA256,
		fileEncSHA256,
		fileLength,
	)

	if err != nil {
		logger.Warnf("Failed to store message: %v", err)
	} else {
		messageStore.StoreMeta(msg.Info.ID, chatJID, extractMeta(msg.Message))
		// view-once / disappearing messages: keep the flag for the panel (the wrapper is removed on unwrap)
		if msg.IsViewOnce || msg.IsEphemeral {
			_, _ = messageStore.db.Exec(`UPDATE messages SET extra = json_set(COALESCE(extra, '{}'), '$.unica', json(?), '$.temporaria', json(?))
				WHERE id = ? AND chat_jid = ?`, fmt.Sprint(msg.IsViewOnce), fmt.Sprint(msg.IsEphemeral), msg.Info.ID, chatJID)
		}
		if msg.Info.IsFromMe {
			_, _ = messageStore.db.Exec("UPDATE messages SET status = 2 WHERE id = ? AND chat_jid = ? AND COALESCE(status,0) < 2", msg.Info.ID, chatJID)
		}
		// Log message reception
		timestamp := msg.Info.Timestamp.Format("2006-01-02 15:04:05")
		direction := "←"
		if msg.Info.IsFromMe {
			direction = "→"
		}

		// Log based on message type
		if mediaType != "" {
			fmt.Printf("[%s] %s %s: [%s: %s] %s\n", timestamp, direction, sender, mediaType, filename, content)
		} else if content != "" {
			fmt.Printf("[%s] %s %s: %s\n", timestamp, direction, sender, content)
		}
	}
}

// DownloadMediaRequest represents the request body for the download media API
type DownloadMediaRequest struct {
	MessageID string `json:"message_id"`
	ChatJID   string `json:"chat_jid"`
}

// DownloadMediaResponse represents the response for the download media API
type DownloadMediaResponse struct {
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	Filename string `json:"filename,omitempty"`
	Path     string `json:"path,omitempty"`
}

// Store additional media info in the database
func (store *MessageStore) StoreMediaInfo(id, chatJID, url string, mediaKey, fileSHA256, fileEncSHA256 []byte, fileLength uint64) error {
	_, err := store.db.Exec(
		"UPDATE messages SET url = ?, media_key = ?, file_sha256 = ?, file_enc_sha256 = ?, file_length = ? WHERE id = ? AND chat_jid = ?",
		url, mediaKey, fileSHA256, fileEncSHA256, fileLength, id, chatJID,
	)
	return err
}

// Get media info from the database
func (store *MessageStore) GetMediaInfo(id, chatJID string) (string, string, string, []byte, []byte, []byte, uint64, error) {
	var mediaType, filename, url string
	var mediaKey, fileSHA256, fileEncSHA256 []byte
	var fileLength uint64

	err := store.db.QueryRow(
		"SELECT media_type, filename, url, media_key, file_sha256, file_enc_sha256, file_length FROM messages WHERE id = ? AND chat_jid = ?",
		id, chatJID,
	).Scan(&mediaType, &filename, &url, &mediaKey, &fileSHA256, &fileEncSHA256, &fileLength)

	return mediaType, filename, url, mediaKey, fileSHA256, fileEncSHA256, fileLength, err
}

// MediaDownloader implements the whatsmeow.DownloadableMessage interface
type MediaDownloader struct {
	URL           string
	DirectPath    string
	MediaKey      []byte
	FileLength    uint64
	FileSHA256    []byte
	FileEncSHA256 []byte
	MediaType     whatsmeow.MediaType
}

// GetDirectPath implements the DownloadableMessage interface
func (d *MediaDownloader) GetDirectPath() string {
	return d.DirectPath
}

// GetURL implements the DownloadableMessage interface
func (d *MediaDownloader) GetURL() string {
	return d.URL
}

// GetMediaKey implements the DownloadableMessage interface
func (d *MediaDownloader) GetMediaKey() []byte {
	return d.MediaKey
}

// GetFileLength implements the DownloadableMessage interface
func (d *MediaDownloader) GetFileLength() uint64 {
	return d.FileLength
}

// GetFileSHA256 implements the DownloadableMessage interface
func (d *MediaDownloader) GetFileSHA256() []byte {
	return d.FileSHA256
}

// GetFileEncSHA256 implements the DownloadableMessage interface
func (d *MediaDownloader) GetFileEncSHA256() []byte {
	return d.FileEncSHA256
}

// GetMediaType implements the DownloadableMessage interface
func (d *MediaDownloader) GetMediaType() whatsmeow.MediaType {
	return d.MediaType
}

// Function to download media from a message
func downloadMedia(client *whatsmeow.Client, messageStore *MessageStore, messageID, chatJID string) (bool, string, string, string, error) {
	// Query the database for the message
	var mediaType, filename, url string
	var mediaKey, fileSHA256, fileEncSHA256 []byte
	var fileLength uint64
	var err error

	// First, check if we already have this file
	chatDir := fmt.Sprintf("%s/%s", storeDir, strings.ReplaceAll(chatJID, ":", "_"))
	localPath := ""

	// Get media info from the database
	mediaType, filename, url, mediaKey, fileSHA256, fileEncSHA256, fileLength, err = messageStore.GetMediaInfo(messageID, chatJID)

	if err != nil {
		// Try to get basic info if extended info isn't available
		err = messageStore.db.QueryRow(
			"SELECT media_type, filename FROM messages WHERE id = ? AND chat_jid = ?",
			messageID, chatJID,
		).Scan(&mediaType, &filename)

		if err != nil {
			return false, "", "", "", fmt.Errorf("failed to find message: %v", err)
		}
	}

	// Check if this is a media message
	if mediaType == "" {
		return false, "", "", "", fmt.Errorf("not a media message")
	}

	// Create directory for the chat if it doesn't exist
	if err := os.MkdirAll(chatDir, 0755); err != nil {
		return false, "", "", "", fmt.Errorf("failed to create chat directory: %v", err)
	}

	// Generate a local path for the file
	// Name by message ID: stored filenames use time.Now() and collide for history-synced media
	filename = messageID + filepath.Ext(filename)
	localPath = fmt.Sprintf("%s/%s", chatDir, filename)

	// Get absolute path
	absPath, err := filepath.Abs(localPath)
	if err != nil {
		return false, "", "", "", fmt.Errorf("failed to get absolute path: %v", err)
	}

	// Check if file already exists
	if _, err := os.Stat(localPath); err == nil {
		// File exists, return it
		return true, mediaType, filename, absPath, nil
	}

	// If we don't have all the media info we need, we can't download
	if url == "" || len(mediaKey) == 0 || len(fileSHA256) == 0 || len(fileEncSHA256) == 0 || fileLength == 0 {
		return false, "", "", "", fmt.Errorf("incomplete media information for download")
	}

	fmt.Printf("Attempting to download media for message %s in chat %s...\n", messageID, chatJID)

	// Extract direct path from URL
	directPath := extractDirectPathFromURL(url)

	// Create a downloader that implements DownloadableMessage
	var waMediaType whatsmeow.MediaType
	switch mediaType {
	case "image", "sticker":
		waMediaType = whatsmeow.MediaImage
	case "video":
		waMediaType = whatsmeow.MediaVideo
	case "audio":
		waMediaType = whatsmeow.MediaAudio
	case "document":
		waMediaType = whatsmeow.MediaDocument
	default:
		return false, "", "", "", fmt.Errorf("unsupported media type: %s", mediaType)
	}

	downloader := &MediaDownloader{
		URL:           url,
		DirectPath:    directPath,
		MediaKey:      mediaKey,
		FileLength:    fileLength,
		FileSHA256:    fileSHA256,
		FileEncSHA256: fileEncSHA256,
		MediaType:     waMediaType,
	}

	// Download the media using whatsmeow client
	mediaData, err := client.Download(context.Background(), downloader)
	if errors.Is(err, whatsmeow.ErrMediaDownloadFailedWith403) ||
		errors.Is(err, whatsmeow.ErrMediaDownloadFailedWith404) ||
		errors.Is(err, whatsmeow.ErrMediaDownloadFailedWith410) {
		var isFromMe bool
		var ts time.Time
		var sender string
		_ = messageStore.db.QueryRow("SELECT is_from_me, timestamp, sender FROM messages WHERE id = ? AND chat_jid = ?",
			messageID, chatJID).Scan(&isFromMe, &ts, &sender)
		chat, _ := types.ParseJID(chatJID)
		info := &types.MessageInfo{
			MessageSource: types.MessageSource{Chat: chat, IsFromMe: isFromMe, IsGroup: chat.Server == types.GroupServer},
			ID:            messageID,
			Timestamp:     ts,
		}
		if info.IsGroup {
			if isFromMe && client.Store.ID != nil {
				info.Sender = client.Store.ID.ToNonAD()
			} else if strings.Contains(sender, "@") {
				info.Sender, _ = types.ParseJID(sender)
			} else {
				info.Sender = types.NewJID(sender, types.DefaultUserServer)
			}
		}
		fmt.Printf("Download got %v, asking phone to re-upload media %s...\n", err, messageID)
		newPath, rerr := requestMediaRetry(client, info, mediaKey, 60*time.Second)
		if rerr != nil {
			return false, "", "", "", fmt.Errorf("download failed (%v); media retry failed: %v", err, rerr)
		}
		downloader.DirectPath = newPath
		mediaData, err = client.Download(context.Background(), downloader)
	}
	if err != nil {
		return false, "", "", "", fmt.Errorf("failed to download media: %v", err)
	}

	// Save the downloaded media to file (temp + rename: the "file exists" check above must never see a partial file)
	tmpPath := localPath + ".part"
	if err := os.WriteFile(tmpPath, mediaData, 0644); err != nil {
		return false, "", "", "", fmt.Errorf("failed to save media file: %v", err)
	}
	if err := os.Rename(tmpPath, localPath); err != nil {
		_ = os.Remove(tmpPath)
		return false, "", "", "", fmt.Errorf("failed to save media file: %v", err)
	}

	fmt.Printf("Successfully downloaded %s media to %s (%d bytes)\n", mediaType, absPath, len(mediaData))
	return true, mediaType, filename, absPath, nil
}

// Extract direct path from a WhatsApp media URL
func extractDirectPathFromURL(url string) string {
	// The direct path is typically in the URL, we need to extract it
	// Example URL: https://mmg.whatsapp.net/v/t62.7118-24/13812002_698058036224062_3424455886509161511_n.enc?ccb=11-4&oh=...

	// Find the path part after the domain
	parts := strings.SplitN(url, ".net/", 2)
	if len(parts) < 2 {
		return url // Return original URL if parsing fails
	}

	// KEEP the query (?ccb=..&oh=..&oe=..): it carries the signature; whatsmeow appends &hash=..
	return "/" + parts[1]
}

// ---- Media retry (ask the phone to re-upload expired media) ----
type mediaRetryResult struct {
	directPath string
	err        error
}
type pendingMediaRetry struct {
	mediaKey []byte
	ch       chan mediaRetryResult
}

var (
	mediaRetryMu      sync.Mutex
	mediaRetryPending = map[types.MessageID]*pendingMediaRetry{}
)

func handleMediaRetry(evt *events.MediaRetry) {
	mediaRetryMu.Lock()
	p := mediaRetryPending[evt.MessageID]
	mediaRetryMu.Unlock()
	if p == nil {
		return
	}
	notif, err := whatsmeow.DecryptMediaRetryNotification(evt, p.mediaKey)
	var res mediaRetryResult
	switch {
	case err != nil:
		res = mediaRetryResult{err: err}
	case notif.GetResult() != waMmsRetry.MediaRetryNotification_SUCCESS:
		res = mediaRetryResult{err: fmt.Errorf("media retry failed: %s", notif.GetResult())}
	default:
		res = mediaRetryResult{directPath: notif.GetDirectPath()}
	}
	// non-blocking: a duplicate notification (or one arriving after the requester gave up)
	// must never block whatsmeow's event loop
	select {
	case p.ch <- res:
	default:
	}
}

func requestMediaRetry(client *whatsmeow.Client, info *types.MessageInfo, mediaKey []byte, timeout time.Duration) (string, error) {
	p := &pendingMediaRetry{mediaKey: mediaKey, ch: make(chan mediaRetryResult, 1)}
	mediaRetryMu.Lock()
	mediaRetryPending[info.ID] = p
	mediaRetryMu.Unlock()
	defer func() {
		mediaRetryMu.Lock()
		delete(mediaRetryPending, info.ID)
		mediaRetryMu.Unlock()
	}()
	if err := client.SendMediaRetryReceipt(context.Background(), info, mediaKey); err != nil {
		return "", fmt.Errorf("send media retry receipt: %w", err)
	}
	select {
	case r := <-p.ch:
		return r.directPath, r.err
	case <-time.After(timeout):
		return "", fmt.Errorf("no media retry response from phone within %s (is the phone online?)", timeout)
	}
}

// ---- On-demand history for one chat (phone must be online) ----
func requestOlderHistory(client *whatsmeow.Client, store *MessageStore, chatJID string, count int) error {
	chat, err := types.ParseJID(chatJID)
	if err != nil {
		return err
	}
	var id string
	var fromMe bool
	var ts time.Time
	err = store.db.QueryRow(`SELECT id, is_from_me, timestamp FROM messages
		WHERE chat_jid = ? ORDER BY timestamp ASC LIMIT 1`, chatJID).Scan(&id, &fromMe, &ts)
	if err != nil {
		return fmt.Errorf("no anchor message stored for %s: %w", chatJID, err)
	}
	info := &types.MessageInfo{
		MessageSource: types.MessageSource{Chat: chat, IsFromMe: fromMe, IsGroup: chat.Server == types.GroupServer},
		ID:            id,
		Timestamp:     ts,
	}
	_, err = client.SendPeerMessage(context.Background(), client.BuildHistorySyncRequest(info, count))
	return err
}

// Start a REST API server to expose the WhatsApp client functionality
func startRESTServer(client *whatsmeow.Client, messageStore *MessageStore, ln net.Listener) {
	// Handler for sending messages
	http.HandleFunc("/api/send", func(w http.ResponseWriter, r *http.Request) {
		// Only allow POST requests
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse the request body
		var req SendMessageRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		// Validate request
		if req.Recipient == "" {
			http.Error(w, "Recipient is required", http.StatusBadRequest)
			return
		}

		if req.Message == "" && req.MediaPath == "" && req.Location == nil && req.Contact == nil {
			http.Error(w, "Message or media path is required", http.StatusBadRequest)
			return
		}

		fmt.Println("Received request to send message", req.Message, req.MediaPath)

		// Send the message
		res := sendWhatsAppMessageEx(client, req)
		fmt.Println("Message sent", res.Success, res.Message)
		// Set response headers
		w.Header().Set("Content-Type", "application/json")

		// Set appropriate status code
		if !res.Success {
			w.WriteHeader(http.StatusInternalServerError)
		}

		// Send response
		json.NewEncoder(w).Encode(res)
	})

	// Handler for downloading media
	http.HandleFunc("/api/download", func(w http.ResponseWriter, r *http.Request) {
		// Only allow POST requests
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse the request body
		var req DownloadMediaRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		// Validate request
		if req.MessageID == "" || req.ChatJID == "" {
			http.Error(w, "Message ID and Chat JID are required", http.StatusBadRequest)
			return
		}

		// Download the media
		success, mediaType, filename, path, err := downloadMedia(client, messageStore, req.MessageID, req.ChatJID)

		// Set response headers
		w.Header().Set("Content-Type", "application/json")

		// Handle download result
		if !success || err != nil {
			errMsg := "Unknown error"
			if err != nil {
				errMsg = err.Error()
			}

			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(DownloadMediaResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to download media: %s", errMsg),
			})
			return
		}

		// Send successful response
		json.NewEncoder(w).Encode(DownloadMediaResponse{
			Success:  true,
			Message:  fmt.Sprintf("Successfully downloaded %s media", mediaType),
			Filename: filename,
			Path:     path,
		})
	})

	// Handler for marking a chat's incoming messages as read (and audios as played)
	http.HandleFunc("/api/read", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ChatJID string `json:"chat_jid"`
			Limit   int    `json:"limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ChatJID == "" {
			http.Error(w, "chat_jid is required", http.StatusBadRequest)
			return
		}
		if req.Limit <= 0 {
			req.Limit = 100
		}
		chat, err := types.ParseJID(req.ChatJID)
		if err != nil {
			http.Error(w, "invalid chat_jid", http.StatusBadRequest)
			return
		}
		rows, err := messageStore.db.Query(`SELECT id, sender, timestamp, media_type FROM messages
			WHERE chat_jid = ? AND is_from_me = 0 ORDER BY timestamp DESC LIMIT ?`, req.ChatJID, req.Limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		type group struct {
			ids, audios []types.MessageID
			ts          time.Time
		}
		bySender := map[string]*group{}
		for rows.Next() {
			var id, sender string
			var mt sql.NullString
			var ts time.Time
			if rows.Scan(&id, &sender, &ts, &mt) != nil {
				continue
			}
			g := bySender[sender]
			if g == nil {
				g = &group{ts: ts}
				bySender[sender] = g
			}
			g.ids = append(g.ids, id)
			if mt.String == "audio" {
				g.audios = append(g.audios, id)
			}
		}
		rows.Close()
		marked, played := 0, 0
		var errs []string
		for sender, g := range bySender {
			senderJID := chat
			if chat.Server == types.GroupServer {
				if strings.Contains(sender, "@") {
					senderJID, _ = types.ParseJID(sender)
				} else {
					senderJID = types.NewJID(sender, types.DefaultUserServer)
				}
			}
			if err := client.MarkRead(context.Background(), g.ids, g.ts, chat, senderJID); err != nil {
				errs = append(errs, err.Error())
			} else {
				marked += len(g.ids)
			}
			if len(g.audios) > 0 {
				if err := client.MarkRead(context.Background(), g.audios, g.ts, chat, senderJID, types.ReceiptTypePlayed); err != nil {
					errs = append(errs, err.Error())
				} else {
					played += len(g.audios)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": len(errs) == 0, "marked_read": marked, "marked_played": played, "errors": errs})
	})

	// Handler for requesting older history of one chat from the phone
	http.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ChatJID string `json:"chat_jid"`
			Count   int    `json:"count"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ChatJID == "" {
			http.Error(w, "chat_jid is required", http.StatusBadRequest)
			return
		}
		if req.Count <= 0 || req.Count > 50 {
			req.Count = 50
		}
		w.Header().Set("Content-Type", "application/json")
		if err := requestOlderHistory(client, messageStore, req.ChatJID, req.Count); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "history request sent; messages arrive via history sync"})
	})

	// Panel extensions (reactions, edit, revoke, forward, presence, avatars, contact/group info)
	registerExtensions(client, messageStore)
	registerDeviceDiag(client)
	registerOnWhatsApp(client) // números clicáveis do painel (numeros.go)
	registerHistorico() // progresso da sincronização de histórico (historico.go)
	registerPareamento(client, messageStore) // pareamento QR sob demanda e retomar sessão (pareamento.go)

	// Start the server (127.0.0.1 only: nobody on the network can use /api/send). The port was bound in main()
	// before connecting to WhatsApp. Without the API the bridge is useless, so a fatal server error exits and
	// lets the panel watchdog start a fresh bridge.
	fmt.Printf("Starting REST API server on %s...\n", ln.Addr())
	serveAPI(ln, guardLocal(auditar(http.DefaultServeMux)), func() {
		client.Disconnect()
		os.Exit(5)
	})
}

func main() {
	// Set up logger
	logger := newFilteredLogger("Client") // INFO + only send/retry/session DEBUG lines (edit diagnostics)
	logger.Infof("Starting WhatsApp client...")

	// Create database connection for storing session data
	dbLog := waLog.Stdout("Database", "INFO", true)

	// Create directory for database if it doesn't exist
	if err := os.MkdirAll(storeDir, 0755); err != nil {
		logger.Errorf("Failed to create store directory: %v", err)
		return
	}

	// Single instance: bind the REST port before touching WhatsApp. A second bridge (e.g. started by the panel
	// watchdog while this one is alive) exits here with code 5 instead of kicking this session off.
	apiListener := listenAPI(bridgePort())

	// WAL: readers (the panel and the notifier read this file) no longer block whatsmeow's writes (Signal
	// sessions, sender keys) during message decryption; _txlock=immediate avoids SQLITE_BUSY on read->write
	// upgrades inside transactions. The journal mode switch is persistent and happens once, on first open.
	container, err := sqlstore.New(context.Background(), "sqlite3",
		"file:"+filepath.ToSlash(storeDir)+"/whatsapp.db?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=10000&_txlock=immediate", dbLog)
	if err != nil {
		logger.Errorf("Failed to connect to database: %v", err)
		return
	}

	// Get device store - This contains session information
	deviceStore, err := container.GetFirstDevice(context.Background())
	if err != nil {
		if err == sql.ErrNoRows {
			// No device exists, create one
			deviceStore = container.NewDevice()
			logger.Infof("Created new device")
		} else {
			logger.Errorf("Failed to get device: %v", err)
			return
		}
	}

	// Create client instance
	configurarHistoricoCompleto() // pede histórico máximo no próximo pareamento (historico.go)
	client := whatsmeow.NewClient(deviceStore, logger)
	if client == nil {
		logger.Errorf("Failed to create WhatsApp client")
		return
	}

	// Initialize message store
	messageStore, err := NewMessageStore()
	if err != nil {
		logger.Errorf("Failed to initialize message store: %v", err)
		return
	}
	defer messageStore.Close()
	globalStore = messageStore

	// DB work for messages/receipts runs on one ordered worker so it does not hold up whatsmeow's node loop
	// (the log showed "Node handling took 5-20s"). Order is preserved: an edit/receipt is applied after its message.
	workQueue := newEventQueue(4096)

	// Setup event handling for messages and history sync
	client.AddEventHandler(func(evt interface{}) {
		if handleConnectionEvent(evt, logger) {
			return
		}
		if handleCallEvent(evt, client, messageStore, workQueue, logger) { // chamadas.go
			return
		}
		switch v := evt.(type) {
		case *events.Message:
			// Process regular messages
			workQueue.enqueue(func() { handleMessage(client, messageStore, v, logger) })

		case *events.HistorySync:
			// Process history sync events (whatsmeow already runs these on their own goroutine)
			handleHistorySync(client, messageStore, v, logger)

		case *events.MediaRetry:
			handleMediaRetry(v)

		case *events.Receipt:
			workQueue.enqueue(func() { handleReceipt(client, messageStore, v) })

		case *events.DeleteForMe:
			workQueue.enqueue(func() { handleDeleteForMe(messageStore, v) })

		case *events.ChatPresence:
			handleChatPresence(v)

		case *events.Presence:
			handlePresence(v)

		case *events.LoggedOut:
			handleLoggedOut(client, workQueue, logger) // pareamento.go: keeps the process alive, no automatic QR
		}
	})

	waContainer = container // pareamento.go: recreates the device after a logout
	paired := client.Store.ID != nil

	if !paired {
		// Unpaired: never block main and never exit. The REST API comes up right away and pairing (QR) starts
		// once in the background; afterwards it is on demand (POST /api/pair/start).
		setConnState("unpaired", "aguardando pareamento (QR)")
		logger.Infof("Device not paired: starting QR pairing in the background")
	} else {
		// Already logged in, just connect. Right after boot the network may not be up yet: keep retrying
		// instead of exiting.
		connectWithRetry(client, logger)

		// Wait a moment for connection to stabilize
		time.Sleep(2 * time.Second)
		if !client.IsConnected() {
			// whatsmeow's auto-reconnect (and the supervisor below) keep trying; /api/me reports connected=false meanwhile
			logger.Warnf("Connection not stable yet; continuing, auto-reconnect will retry")
		}
		fmt.Println("\n✓ Connected to WhatsApp! Type 'help' for commands.")
	}

	// Reconnect when whatsmeow gives up by itself (connect failure without auto-reconnect, expired temp ban)
	go superviseConnection(client, logger)

	// Start REST API server
	startRESTServer(client, messageStore, apiListener)
	if !paired {
		go iniciarPareamento(false)
	}

	// Create a channel to keep the main goroutine alive
	exitChan := make(chan os.Signal, 1)
	signal.Notify(exitChan, os.Interrupt, syscall.SIGTERM)

	fmt.Println("REST server is running. Press Ctrl+C to disconnect and exit.")

	// Wait for termination signal
	sig := <-exitChan

	fmt.Printf("Got %v, shutting down...\n", sig)
	shutdownAPI(10 * time.Second) // let in-flight requests (sends) finish
	fmt.Println("Disconnecting...")
	// Disconnect client
	client.Disconnect()
	if !workQueue.drain(10 * time.Second) {
		fmt.Println("Warning: event queue did not drain in time")
	}
	// messageStore.Close() runs via defer
}

// GetChatName determines the appropriate name for a chat based on JID and other info
func GetChatName(client *whatsmeow.Client, messageStore *MessageStore, jid types.JID, chatJID string, conversation interface{}, sender string, logger waLog.Logger) string {
	// First, check if chat already exists in database with a name
	var existingName string
	err := messageStore.db.QueryRow("SELECT name FROM chats WHERE jid = ?", chatJID).Scan(&existingName)
	if err == nil && existingName != "" {
		// Chat exists with a name, use that
		logger.Infof("Using existing chat name for %s: %s", chatJID, existingName)
		return existingName
	}

	// Need to determine chat name
	var name string

	if jid.Server == "g.us" {
		// This is a group chat
		logger.Infof("Getting name for group: %s", chatJID)

		// Use conversation data if provided (from history sync)
		if conversation != nil {
			// Extract name from conversation if available
			// This uses type assertions to handle different possible types
			var displayName, convName *string
			// Try to extract the fields we care about regardless of the exact type
			v := reflect.ValueOf(conversation)
			if v.Kind() == reflect.Ptr && !v.IsNil() {
				v = v.Elem()

				// Try to find DisplayName field
				if displayNameField := v.FieldByName("DisplayName"); displayNameField.IsValid() && displayNameField.Kind() == reflect.Ptr && !displayNameField.IsNil() {
					dn := displayNameField.Elem().String()
					displayName = &dn
				}

				// Try to find Name field
				if nameField := v.FieldByName("Name"); nameField.IsValid() && nameField.Kind() == reflect.Ptr && !nameField.IsNil() {
					n := nameField.Elem().String()
					convName = &n
				}
			}

			// Use the name we found
			if displayName != nil && *displayName != "" {
				name = *displayName
			} else if convName != nil && *convName != "" {
				name = *convName
			}
		}

		// If we didn't get a name, try group info
		if name == "" {
			// network round-trip: bounded so a slow answer cannot stall message processing
			gctx, gcancel := context.WithTimeout(context.Background(), 15*time.Second)
			groupInfo, err := client.GetGroupInfo(gctx, jid)
			gcancel()
			if err == nil && groupInfo.Name != "" {
				name = groupInfo.Name
			} else {
				// Fallback name for groups
				name = fmt.Sprintf("Group %s", jid.User)
			}
		}

		logger.Infof("Using group name: %s", name)
	} else {
		// This is an individual contact
		logger.Infof("Getting name for contact: %s", chatJID)

		// Just use contact info (full name)
		contact, err := client.Store.Contacts.GetContact(context.Background(), jid)
		if err == nil && contact.FullName != "" {
			name = contact.FullName
		} else if sender != "" {
			// Fallback to sender
			name = sender
		} else {
			// Last fallback to JID
			name = jid.User
		}

		logger.Infof("Using contact name: %s", name)
	}

	return name
}

// handleHistorySync: ver historico.go

// Request history sync from the server
func requestHistorySync(client *whatsmeow.Client) {
	if client == nil {
		fmt.Println("Client is not initialized. Cannot request history sync.")
		return
	}

	if !client.IsConnected() {
		fmt.Println("Client is not connected. Please ensure you are connected to WhatsApp first.")
		return
	}

	if client.Store.ID == nil {
		fmt.Println("Client is not logged in. Please scan the QR code first.")
		return
	}

	// Build and send a history sync request
	historyMsg := client.BuildHistorySyncRequest(nil, 100)
	if historyMsg == nil {
		fmt.Println("Failed to build history sync request.")
		return
	}

	_, err := client.SendMessage(context.Background(), types.JID{
		Server: "s.whatsapp.net",
		User:   "status",
	}, historyMsg)

	if err != nil {
		fmt.Printf("Failed to request history sync: %v\n", err)
	} else {
		fmt.Println("History sync requested. Waiting for server response...")
	}
}

// analyzeOggOpus tries to extract duration and generate a simple waveform from an Ogg Opus file
func analyzeOggOpus(data []byte) (duration uint32, waveform []byte, err error) {
	// Try to detect if this is a valid Ogg file by checking for the "OggS" signature
	// at the beginning of the file
	if len(data) < 4 || string(data[0:4]) != "OggS" {
		return 0, nil, fmt.Errorf("not a valid Ogg file (missing OggS signature)")
	}

	// Parse Ogg pages to find the last page with a valid granule position
	var lastGranule uint64
	var sampleRate uint32 = 48000 // Default Opus sample rate
	var preSkip uint16 = 0
	var foundOpusHead bool

	// Scan through the file looking for Ogg pages
	for i := 0; i < len(data); {
		// Check if we have enough data to read Ogg page header
		if i+27 >= len(data) {
			break
		}

		// Verify Ogg page signature
		if string(data[i:i+4]) != "OggS" {
			// Skip until next potential page
			i++
			continue
		}

		// Extract header fields
		granulePos := binary.LittleEndian.Uint64(data[i+6 : i+14])
		pageSeqNum := binary.LittleEndian.Uint32(data[i+18 : i+22])
		numSegments := int(data[i+26])

		// Extract segment table
		if i+27+numSegments >= len(data) {
			break
		}
		segmentTable := data[i+27 : i+27+numSegments]

		// Calculate page size
		pageSize := 27 + numSegments
		for _, segLen := range segmentTable {
			pageSize += int(segLen)
		}

		// Check if we're looking at an OpusHead packet (should be in first few pages)
		if !foundOpusHead && pageSeqNum <= 1 {
			// Look for "OpusHead" marker in this page
			pageData := data[i : i+pageSize]
			headPos := bytes.Index(pageData, []byte("OpusHead"))
			if headPos >= 0 && headPos+12 < len(pageData) {
				// Found OpusHead, extract sample rate and pre-skip
				// OpusHead format: Magic(8) + Version(1) + Channels(1) + PreSkip(2) + SampleRate(4) + ...
				headPos += 8 // Skip "OpusHead" marker
				// PreSkip is 2 bytes at offset 10
				if headPos+12 <= len(pageData) {
					preSkip = binary.LittleEndian.Uint16(pageData[headPos+10 : headPos+12])
					sampleRate = binary.LittleEndian.Uint32(pageData[headPos+12 : headPos+16])
					foundOpusHead = true
					fmt.Printf("Found OpusHead: sampleRate=%d, preSkip=%d\n", sampleRate, preSkip)
				}
			}
		}

		// Keep track of last valid granule position
		if granulePos != 0 {
			lastGranule = granulePos
		}

		// Move to next page
		i += pageSize
	}

	if !foundOpusHead {
		fmt.Println("Warning: OpusHead not found, using default values")
	}

	// Calculate duration based on granule position
	if lastGranule > 0 {
		// Formula for duration: (lastGranule - preSkip) / sampleRate
		durationSeconds := float64(lastGranule-uint64(preSkip)) / float64(sampleRate)
		duration = uint32(math.Ceil(durationSeconds))
		fmt.Printf("Calculated Opus duration from granule: %f seconds (lastGranule=%d)\n",
			durationSeconds, lastGranule)
	} else {
		// Fallback to rough estimation if granule position not found
		fmt.Println("Warning: No valid granule position found, using estimation")
		durationEstimate := float64(len(data)) / 2000.0 // Very rough approximation
		duration = uint32(durationEstimate)
	}

	// Make sure we have a reasonable duration (at least 1 second, at most 300 seconds)
	if duration < 1 {
		duration = 1
	} else if duration > 300 {
		duration = 300
	}

	// Generate waveform
	waveform = placeholderWaveform(duration)

	fmt.Printf("Ogg Opus analysis: size=%d bytes, calculated duration=%d sec, waveform=%d bytes\n",
		len(data), duration, len(waveform))

	return duration, waveform, nil
}

// min returns the smaller of x or y
func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// placeholderWaveform generates a synthetic waveform for WhatsApp voice messages
// that appears natural with some variability based on the duration
func placeholderWaveform(duration uint32) []byte {
	// WhatsApp expects a 64-byte waveform for voice messages
	const waveformLength = 64
	waveform := make([]byte, waveformLength)

	// Seed the random number generator for consistent results with the same duration
	rand.Seed(int64(duration))

	// Create a more natural looking waveform with some patterns and variability
	// rather than completely random values

	// Base amplitude and frequency - longer messages get faster frequency
	baseAmplitude := 35.0
	frequencyFactor := float64(min(int(duration), 120)) / 30.0

	for i := range waveform {
		// Position in the waveform (normalized 0-1)
		pos := float64(i) / float64(waveformLength)

		// Create a wave pattern with some randomness
		// Use multiple sine waves of different frequencies for more natural look
		val := baseAmplitude * math.Sin(pos*math.Pi*frequencyFactor*8)
		val += (baseAmplitude / 2) * math.Sin(pos*math.Pi*frequencyFactor*16)

		// Add some randomness to make it look more natural
		val += (rand.Float64() - 0.5) * 15

		// Add some fade-in and fade-out effects
		fadeInOut := math.Sin(pos * math.Pi)
		val = val * (0.7 + 0.3*fadeInOut)

		// Center around 50 (typical voice baseline)
		val = val + 50

		// Ensure values stay within WhatsApp's expected range (0-100)
		if val < 0 {
			val = 0
		} else if val > 100 {
			val = 100
		}

		waveform[i] = byte(val)
	}

	return waveform
}
