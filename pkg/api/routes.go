package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"

	"github.com/kariyertech/Truva.git/internal/k8s"
)

func syncHandler(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	deployment := r.URL.Query().Get("deployment")
	localPath := r.URL.Query().Get("local-path")
	containerPath := r.URL.Query().Get("container-path")

	if namespace == "" || deployment == "" || localPath == "" || containerPath == "" {
		http.Error(w, "Missing required query parameters", http.StatusBadRequest)
		return
	}

	err := k8s.ModifyDeployment(namespace, deployment)
	if err != nil {
		http.Error(w, "Failed to modify deployment: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]string{"message": "Deployment modified successfully"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func logHandler(w http.ResponseWriter, r *http.Request) {
	logFile, err := os.OpenFile("app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		http.Error(w, "Failed to open log file", http.StatusInternalServerError)
		return
	}
	defer logFile.Close()

	_, err = io.Copy(logFile, r.Body)
	if err != nil {
		http.Error(w, "Failed to write logs", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func InitRoutes() {
	http.HandleFunc("/api/sync", syncHandler)
	http.HandleFunc("/api/logs", logHandler)
}
