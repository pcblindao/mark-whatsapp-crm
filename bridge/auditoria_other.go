//go:build !windows

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Linux: identifica o chamador via /proc/net/tcp{,6} (socket do cliente) + /proc/<pid>/fd.
// Sem permissão (outro usuário) ou sem /proc, devolve 0 / vazio e a origem fica "desconhecida".

func procAddrHex(hostport string) (string, bool) {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", false
	}
	ip := net.ParseIP(h)
	port, err := strconv.Atoi(p)
	if ip == nil || err != nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%02X%02X%02X%02X:%04X", v4[3], v4[2], v4[1], v4[0], port), true
	}
	b := ip.To16()
	var sb strings.Builder
	for g := 0; g < 4; g++ {
		for i := 3; i >= 0; i-- {
			fmt.Fprintf(&sb, "%02X", b[g*4+i])
		}
	}
	return fmt.Sprintf("%s:%04X", sb.String(), port), true
}

func pidDoCliente(remote string) int {
	want, ok := procAddrHex(remote)
	if !ok {
		return 0
	}
	inode := ""
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(data), "\n")[1:] {
			c := strings.Fields(ln)
			if len(c) >= 10 && strings.EqualFold(c[1], want) && c[9] != "0" {
				inode = c[9]
				break
			}
		}
		if inode != "" {
			break
		}
	}
	if inode == "" {
		return 0
	}
	target := "socket:[" + inode + "]"
	fds, _ := filepath.Glob("/proc/[0-9]*/fd/*")
	for _, fd := range fds {
		if l, err := os.Readlink(fd); err == nil && l == target {
			if pid, err := strconv.Atoi(strings.Split(fd, "/")[2]); err == nil {
				return pid
			}
		}
	}
	return 0
}

func infoProcesso(pid int) procInfo {
	if pid <= 0 {
		return procInfo{}
	}
	base := fmt.Sprintf("/proc/%d/", pid)
	var p procInfo
	if b, err := os.ReadFile(base + "comm"); err == nil {
		p.Nome = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(base + "cmdline"); err == nil {
		p.Cmd = strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
	}
	if b, err := os.ReadFile(base + "stat"); err == nil {
		s := string(b)
		if i := strings.LastIndex(s, ")"); i >= 0 {
			if f := strings.Fields(s[i+1:]); len(f) >= 2 {
				p.Pai, _ = strconv.Atoi(f[1])
			}
		}
	}
	if len(p.Cmd) > 400 {
		p.Cmd = p.Cmd[:400] + "…"
	}
	return p
}
