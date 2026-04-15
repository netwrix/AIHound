package main

import "fmt"

var netwrixArt = []string{
	"+-+-+-+-+-+-+-+",
	"|N|e|t|w|r|i|x|",
	"+-+-+-+-+-+-+-+",
}

var aihoundArt = []string{
	`    ___    ______  __                      __`,
	`   /   |  /  _/ / / /___  __  ______  ____/ /`,
	`  / /| |  / // /_/ / __ \/ / / / __ \/ __  / `,
	` / ___ |_/ // __  / /_/ / /_/ / / / / /_/ /  `,
	`/_/  |_/___/_/ /_/\____/\__,_/_/ /_/\__,_/   `,
}

var dogArt = []string{
	`    / \__`,
	`   (    @\___`,
	`   /         O`,
	`  /   (_____/`,
	` /_____/   U`,
}

const disclaimer = "For authorized use only. Use on systems you own or have permission to test."

func printBanner(noColor bool) {
	blue := "\033[94m"
	bold := "\033[1m"
	yellow := "\033[93m"
	white := "\033[97m"
	dim := "\033[2m"
	red := "\033[91m"
	reset := "\033[0m"

	if noColor {
		blue, bold, yellow, white, dim, red, reset = "", "", "", "", "", "", ""
	}

	for _, line := range netwrixArt {
		fmt.Printf("%s%s%s\n", blue, line, reset)
	}

	maxAH := 0
	for _, line := range aihoundArt {
		if len(line) > maxAH {
			maxAH = len(line)
		}
	}

	for i := 0; i < len(aihoundArt); i++ {
		dog := ""
		if i < len(dogArt) {
			dog = dogArt[i]
		}
		fmt.Printf("%s%-*s%s   %s%s%s\n", bold, maxAH, aihoundArt[i], reset, yellow, dog, reset)
	}

	fmt.Println()
	fmt.Printf("%s  AI Credential & Secrets Scanner%s      %sWritten by DFIRDeferred%s\n", white, reset, dim, reset)
	fmt.Printf("  %s%s%s\n", red, disclaimer, reset)
	fmt.Println()
}
