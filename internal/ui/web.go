package ui

import (
	"fmt"
	"html/template"
	"net/http"
	"os/exec"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{}

func logWebSocketHandler(w http.ResponseWriter, r *http.Request, namespace, deployment string) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("WebSocket upgrade failed:", err)
		return
	}
	defer conn.Close()

	logChannel := make(chan string)
	var wg sync.WaitGroup

	pods, err := getPodNames(namespace, deployment)
	if err != nil {
		fmt.Println("Failed to get pod names:", err)
		return
	}

	for _, pod := range pods {
		wg.Add(1)
		go streamPodLogs(pod, namespace, logChannel, &wg)
	}

	for log := range logChannel {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(log)); err != nil {
			fmt.Println("Failed to send log:", err)
			break
		}
	}

	wg.Wait()
}

func streamPodLogs(podName, namespace string, logChannel chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	cmd := exec.Command("kubectl", "logs", "-f", podName, "-n", namespace)
	stdout, _ := cmd.StdoutPipe()
	cmd.Start()

	buffer := make([]byte, 1024)
	for {
		n, err := stdout.Read(buffer)
		if err != nil {
			close(logChannel)
			break
		}
		if n > 0 {
			logChannel <- fmt.Sprintf("[%s] %s", podName, string(buffer[:n]))
		}
	}
}

func getPodNames(namespace, deployment string) ([]string, error) {
	cmd := exec.Command("kubectl", "get", "pods", "-n", namespace, "-l", fmt.Sprintf("app=%s", deployment), "-o", "jsonpath={.items[*].metadata.name}")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get pods: %w", err)
	}
	podNames := strings.Fields(string(output))
	return podNames, nil
}

func homeHandler(w http.ResponseWriter, _ *http.Request, namespace, deployment string) {
	pods, err := getPodNames(namespace, deployment)
	if err != nil {
		fmt.Println("Failed to get pod names:", err)
		http.Error(w, "Failed to get pod names", http.StatusInternalServerError)
		return
	}

	tmpl := template.Must(template.ParseFiles("../templates/index.html"))
	err = tmpl.Execute(w, pods)
	if err != nil {
		fmt.Println("Failed to render template:", err)
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
	}
}

func StartWebServer(namespace, deployment string) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		homeHandler(w, r, namespace, deployment)
	})
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		logWebSocketHandler(w, r, namespace, deployment)
	})
	fmt.Println("UI Server started at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
