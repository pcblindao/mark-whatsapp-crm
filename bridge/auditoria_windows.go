//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// pidDoCliente acha o processo dono da ponta cliente da conexão (127.0.0.1:porta -> 127.0.0.1:8080).
func pidDoCliente(remote string) int {
	out, err := semJanela(exec.Command("netstat", "-ano", "-p", "TCP")).Output()
	if err != nil {
		return 0
	}
	for _, ln := range strings.Split(string(out), "\n") {
		f := strings.Fields(ln)
		if len(f) >= 5 && f[1] == remote {
			if pid, err := strconv.Atoi(f[len(f)-1]); err == nil {
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
	out, err := semJanela(exec.Command("wmic", "process", "where", fmt.Sprintf("processid=%d", pid),
		"get", "Name,ParentProcessId,CommandLine", "/format:list")).Output()
	if err != nil {
		return procInfo{}
	}
	var p procInfo
	for _, ln := range strings.Split(string(out), "\n") {
		ln = strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(ln, "CommandLine="):
			p.Cmd = strings.TrimPrefix(ln, "CommandLine=")
		case strings.HasPrefix(ln, "Name="):
			p.Nome = strings.TrimPrefix(ln, "Name=")
		case strings.HasPrefix(ln, "ParentProcessId="):
			p.Pai, _ = strconv.Atoi(strings.TrimPrefix(ln, "ParentProcessId="))
		}
	}
	if len(p.Cmd) > 400 {
		p.Cmd = p.Cmd[:400] + "…"
	}
	return p
}
