//go:build !windows

package main

import "os/exec"

// Fora do Windows não há janela de console para esconder.
func semJanela(c *exec.Cmd) *exec.Cmd { return c }
