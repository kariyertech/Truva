package ui

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

func StartLogHandler() {
	logFile, err := os.OpenFile("app.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		fmt.Println("Failed to open log file:", err)
		return
	}
	defer logFile.Close()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Println("Failed to create file watcher:", err)
		return
	}
	defer watcher.Close()

	err = watcher.Add("app.log")
	if err != nil {
		fmt.Println("Failed to watch log file:", err)
		return
	}

	fmt.Println("Log handler started, sending logs to UI...")

	reader := bufio.NewReader(logFile)

	for {
		select {
		case event := <-watcher.Events:
			if event.Op&fsnotify.Write == fsnotify.Write {
				line, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println("Failed to read log file:", err)
					time.Sleep(2 * time.Second)
					continue
				}

				if strings.TrimSpace(line) != "" {
					err := sendLogToUI(line)
					if err != nil {
						fmt.Println("Failed to send log to UI:", err)
					}
				}
			}
		case err := <-watcher.Errors:
			fmt.Println("Watcher error:", err)
		}
	}
}

func sendLogToUI(log string) error {
	resp, err := http.Post("http://localhost:8080/api/logs", "text/plain", strings.NewReader(log))
	if err != nil {
		return fmt.Errorf("failed to send log to UI: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}
