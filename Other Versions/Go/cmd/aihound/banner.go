package main

import "fmt"

const asciiArt = `
╔══════════════════════════════════════════════════════════════╗
║          AIHound - AI Credential & Secrets Scanner           ║
╚══════════════════════════════════════════════════════════════╝
`

func printBanner(noColor bool) {
	if noColor {
		fmt.Print(asciiArt)
	} else {
		fmt.Printf("\033[1m%s\033[0m", asciiArt)
	}
}
