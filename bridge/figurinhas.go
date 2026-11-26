package main

// [figurinhas] Figurinhas animadas: o WhatsApp só anima a figurinha quando StickerMessage.IsAnimated = true.
// webpAnimado lê os blocos RIFF do arquivo (VP8X com a flag de animação, ou blocos ANIM/ANMF).
// /api/recursos deixa o painel saber que esta versão da ponte envia figurinhas animadas.

import (
	"encoding/binary"
	"net/http"
)

func webpAnimado(b []byte) bool {
	if len(b) < 12 || string(b[0:4]) != "RIFF" || string(b[8:12]) != "WEBP" {
		return false
	}
	for p := 12; p+8 <= len(b); {
		id := string(b[p : p+4])
		tam := int(binary.LittleEndian.Uint32(b[p+4 : p+8]))
		if id == "ANIM" || id == "ANMF" {
			return true
		}
		if id == "VP8X" && p+9 <= len(b) && b[p+8]&0x02 != 0 {
			return true
		}
		if tam < 0 || tam > len(b) {
			return false
		}
		p += 8 + tam + tam%2
	}
	return false
}

func init() {
	http.HandleFunc("/api/recursos", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]interface{}{"success": true, "sticker_animado": true})
	})
}
