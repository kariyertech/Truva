package k8s

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/kariyertech/Truva.git/pkg/config"
	"github.com/kariyertech/Truva.git/pkg/credentials"
	"github.com/kariyertech/Truva.git/pkg/errors"
	"github.com/kariyertech/Truva.git/pkg/recovery"
	"github.com/kariyertech/Truva.git/pkg/retry"
	"github.com/kariyertech/Truva.git/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// CacheConfig holds configuration for API response caching
type CacheConfig struct {
	Enabled         bool          `yaml:"enabled"`
	TTL             time.Duration `yaml:"ttl"`
	MaxSize         int           `yaml:"max_size"`
	CleanupInterval time.Duration `yaml:"cleanup_interval"`
}

// DefaultCacheConfig returns default cache configuration
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		Enabled:         true,
		TTL:             5 * time.Minute,
		MaxSize:         1000,
		CleanupInterval: 10 * time.Minute,
	}
}

// CacheEntry represents a cached API response
type CacheEntry struct {
	Data      interface{}
	Timestamp time.Time
	TTL       time.Duration
}

// IsExpired checks if the cache entry has expired
func (e *CacheEntry) IsExpired() bool {
	return time.Since(e.Timestamp) > e.TTL
}

// APICache provides caching for Kubernetes API responses
type APICache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	config  *CacheConfig
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewAPICache creates a new API cache
func NewAPICache(config *CacheConfig) *APICache {
	ctx, cancel := context.WithCancel(context.Background())
	cache := &APICache{
		entries: make(map[string]*CacheEntry),
		config:  config,
		ctx:     ctx,
		cancel:  cancel,
	}

	if config.Enabled {
		go cache.startCleanup()
	}

	return cache
}

// Get retrieves a value from cache
func (c *APICache) Get(key string) (interface{}, bool) {
	if !c.config.Enabled {
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists || entry.IsExpired() {
		return nil, false
	}

	return entry.Data, true
}

// Set stores a value in cache
func (c *APICache) Set(key string, value interface{}, ttl time.Duration) {
	if !c.config.Enabled {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we need to evict entries
	if len(c.entries) >= c.config.MaxSize {
		c.evictOldest()
	}

	c.entries[key] = &CacheEntry{
		Data:      value,
		Timestamp: time.Now(),
		TTL:       ttl,
	}
}

// Delete removes a value from cache
func (c *APICache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Clear removes all entries from cache
func (c *APICache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CacheEntry)
}

// startCleanup starts the background cleanup routine
func (c *APICache) startCleanup() {
	ticker := time.NewTicker(c.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

// cleanup removes expired entries
func (c *APICache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, entry := range c.entries {
		if entry.IsExpired() {
			delete(c.entries, key)
		}
	}
}

// evictOldest removes the oldest entry
func (c *APICache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.entries {
		if oldestKey == "" || entry.Timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.Timestamp
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// Stop stops the cache cleanup routine
func (c *APICache) Stop() {
	c.cancel()
}

// GetStats returns cache statistics
func (c *APICache) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	expired := 0
	for _, entry := range c.entries {
		if entry.IsExpired() {
			expired++
		}
	}

	return map[string]interface{}{
		"total_entries":   len(c.entries),
		"expired_entries": expired,
		"max_size":        c.config.MaxSize,
		"enabled":         c.config.Enabled,
	}
}

// BatchRequest represents a batch API request
type BatchRequest struct {
	ID       string
	Type     string
	Params   map[string]interface{}
	Callback func(interface{}, error)
}

// BatchProcessor handles batch API requests
type BatchProcessor struct {
	mu           sync.Mutex
	requests     []*BatchRequest
	batchSize    int
	batchTimeout time.Duration
	processor    func([]*BatchRequest) error
	timer        *time.Timer
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(batchSize int, batchTimeout time.Duration, processor func([]*BatchRequest) error) *BatchProcessor {
	ctx, cancel := context.WithCancel(context.Background())
	return &BatchProcessor{
		requests:     make([]*BatchRequest, 0),
		batchSize:    batchSize,
		batchTimeout: batchTimeout,
		processor:    processor,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// AddRequest adds a request to the batch
func (bp *BatchProcessor) AddRequest(req *BatchRequest) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	bp.requests = append(bp.requests, req)

	// Process immediately if batch is full
	if len(bp.requests) >= bp.batchSize {
		bp.processBatch()
		return
	}

	// Set timer for batch timeout if this is the first request
	if len(bp.requests) == 1 {
		bp.timer = time.AfterFunc(bp.batchTimeout, func() {
			bp.mu.Lock()
			defer bp.mu.Unlock()
			if len(bp.requests) > 0 {
				bp.processBatch()
			}
		})
	}
}

// processBatch processes the current batch of requests
func (bp *BatchProcessor) processBatch() {
	if len(bp.requests) == 0 {
		return
	}

	// Stop the timer if it's running
	if bp.timer != nil {
		bp.timer.Stop()
		bp.timer = nil
	}

	// Process the batch
	batch := make([]*BatchRequest, len(bp.requests))
	copy(batch, bp.requests)
	bp.requests = bp.requests[:0] // Clear the slice

	// Process in background
	recovery.SafeGoWithContext(bp.ctx, func(ctx context.Context) {
		err := bp.processor(batch)
		if err != nil {
			// Call error callbacks
			for _, req := range batch {
				if req.Callback != nil {
					req.Callback(nil, err)
				}
			}
		}
	}, map[string]interface{}{
		"component":  "batch_processor",
		"batch_size": len(batch),
	})
}

// Stop stops the batch processor
func (bp *BatchProcessor) Stop() {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	// Process remaining requests
	if len(bp.requests) > 0 {
		bp.processBatch()
	}

	bp.cancel()
}

var (
	clientset      kubernetes.Interface
	secureClient   *credentials.SecureK8sClient
	credManager    *credentials.CredentialsManager
	apiCache       *APICache
	batchProcessor *BatchProcessor
	cacheConfig    *CacheConfig
)

type DeploymentLabels map[string]string

// DefaultKubernetesClient implements the KubernetesClient interface
type DefaultKubernetesClient struct {
	clientset kubernetes.Interface
	cache     *APICache
}

// NewKubernetesClient creates a new instance of DefaultKubernetesClient
func NewKubernetesClient() (KubernetesClient, error) {
	err := InitClient()
	if err != nil {
		return nil, err
	}
	return &DefaultKubernetesClient{
		clientset: clientset,
		cache:     apiCache,
	}, nil
}

// NewKubernetesClientWithContext creates a new instance with context
func NewKubernetesClientWithContext(ctx context.Context) (KubernetesClient, error) {
	err := InitClientWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return &DefaultKubernetesClient{
		clientset: clientset,
		cache:     apiCache,
	}, nil
}

func InitClient() error {
	return InitClientWithContext(context.Background())
}

func InitClientWithContext(ctx context.Context) error {
	// Initialize cache if not already done
	if apiCache == nil {
		cacheConfig = DefaultCacheConfig()
		apiCache = NewAPICache(cacheConfig)
	}

	// Initialize batch processor if not already done
	if batchProcessor == nil {
		batchProcessor = NewBatchProcessor(10, 100*time.Millisecond, processBatchRequests)
	}

	// Get configuration
	cfg := config.GetConfig()

	// Initialize credentials manager if enabled
	if cfg.Credentials.Enabled {
		// Get master password from environment variable
		masterPassword := os.Getenv("TRUVA_MASTER_PASSWORD")
		if masterPassword == "" {
			masterPassword = cfg.Credentials.MasterPassword
		}
		if masterPassword == "" {
			return fmt.Errorf("master password not set. Please set TRUVA_MASTER_PASSWORD environment variable")
		}

		// Initialize credentials manager
		var err error
		credManager, err = credentials.NewCredentialsManager(cfg.Credentials.StorePath, masterPassword)
		if err != nil {
			return fmt.Errorf("failed to initialize credentials manager: %w", err)
		}

		// Initialize secure client
		secureClient = credentials.NewSecureK8sClient(credManager)

		// Try to initialize from stored config first
		err = secureClient.InitializeFromStoredConfig()
		if err != nil {
			// If no stored config, try to load from kubeconfig file
			kubeconfigPath := os.Getenv("KUBECONFIG")
			if kubeconfigPath == "" {
				kubeconfigPath = clientcmd.RecommendedHomeFile
			}

			// Check if running in cluster
			if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
				// Running in cluster, use in-cluster config
				err = secureClient.InitializeInCluster()
				if err != nil {
					return fmt.Errorf("failed to initialize in-cluster client: %w", err)
				}
			} else {
				// Load and store kubeconfig
				err = secureClient.InitializeFromKubeconfig(kubeconfigPath)
				if err != nil {
					return fmt.Errorf("failed to initialize secure client from kubeconfig: %w", err)
				}
			}
		}

		// Get clientset from secure client
		clientset = secureClient.GetClientset()

		// Setup credential rotation if enabled
		if cfg.Credentials.RotationEnabled {
			recovery.SafeGoWithContext(ctx, func(ctx context.Context) {
				startCredentialRotation(ctx, cfg.Credentials.RotationHours)
			}, map[string]interface{}{})
		}
	} else {
		// Fallback to traditional method if credentials management is disabled
		return retry.KubernetesRetryWithCircuitBreaker(ctx, func() error {
			kubeconfig := os.Getenv("KUBECONFIG")
			if kubeconfig == "" {
				kubeconfig = clientcmd.RecommendedHomeFile
			}

			config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
			if err != nil {
				return fmt.Errorf("failed to build config from KUBECONFIG: %w", err)
			}

			clientset, err = kubernetes.NewForConfig(config)
			if err != nil {
				return fmt.Errorf("failed to create Kubernetes clientset: %w", err)
			}

			// Test the connection
			_, err = clientset.Discovery().ServerVersion()
			if err != nil {
				return fmt.Errorf("failed to connect to Kubernetes cluster: %w", err)
			}

			return nil
		})
	}

	return nil
}

func GetClientset() kubernetes.Interface {
	return clientset
}

// GetAPICache returns the API cache instance
func GetAPICache() *APICache {
	return apiCache
}

// GetBatchProcessor returns the batch processor instance
func GetBatchProcessor() *BatchProcessor {
	return batchProcessor
}

// GetSecureClient returns the secure Kubernetes client
func GetSecureClient() *credentials.SecureK8sClient {
	return secureClient
}

// GetCredentialsManager returns the credentials manager
func GetCredentialsManager() *credentials.CredentialsManager {
	return credManager
}

// processBatchRequests processes a batch of API requests
func processBatchRequests(requests []*BatchRequest) error {
	// Group requests by type for efficient processing
	requestGroups := make(map[string][]*BatchRequest)
	for _, req := range requests {
		requestGroups[req.Type] = append(requestGroups[req.Type], req)
	}

	// Process each group
	for requestType, group := range requestGroups {
		switch requestType {
		case "list_pods":
			err := processPodListBatch(group)
			if err != nil {
				return fmt.Errorf("failed to process pod list batch: %w", err)
			}
		case "list_services":
			err := processServiceListBatch(group)
			if err != nil {
				return fmt.Errorf("failed to process service list batch: %w", err)
			}
		case "list_deployments":
			err := processDeploymentListBatch(group)
			if err != nil {
				return fmt.Errorf("failed to process deployment list batch: %w", err)
			}
		default:
			// Process individually for unknown types
			for _, req := range group {
				if req.Callback != nil {
					req.Callback(nil, fmt.Errorf("unknown request type: %s", requestType))
				}
			}
		}
	}

	return nil
}

// processPodListBatch processes a batch of pod list requests
func processPodListBatch(requests []*BatchRequest) error {
	// Group by namespace for efficient API calls
	namespaceGroups := make(map[string][]*BatchRequest)
	for _, req := range requests {
		namespace := req.Params["namespace"].(string)
		namespaceGroups[namespace] = append(namespaceGroups[namespace], req)
	}

	// Process each namespace
	for namespace, group := range namespaceGroups {
		// Check cache first
		cacheKey := fmt.Sprintf("pods:%s", namespace)
		if cached, found := apiCache.Get(cacheKey); found {
			// Return cached result to all requests in this group
			for _, req := range group {
				if req.Callback != nil {
					req.Callback(cached, nil)
				}
			}
			continue
		}

		// Make API call
		pods, err := clientset.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			// Return error to all requests in this group
			for _, req := range group {
				if req.Callback != nil {
					req.Callback(nil, err)
				}
			}
			continue
		}

		// Cache the result
		apiCache.Set(cacheKey, pods, cacheConfig.TTL)

		// Return result to all requests in this group
		for _, req := range group {
			if req.Callback != nil {
				req.Callback(pods, nil)
			}
		}
	}

	return nil
}

// processServiceListBatch processes a batch of service list requests
func processServiceListBatch(requests []*BatchRequest) error {
	// Group by namespace for efficient API calls
	namespaceGroups := make(map[string][]*BatchRequest)
	for _, req := range requests {
		namespace := req.Params["namespace"].(string)
		namespaceGroups[namespace] = append(namespaceGroups[namespace], req)
	}

	// Process each namespace
	for namespace, group := range namespaceGroups {
		// Check cache first
		cacheKey := fmt.Sprintf("services:%s", namespace)
		if cached, found := apiCache.Get(cacheKey); found {
			// Return cached result to all requests in this group
			for _, req := range group {
				if req.Callback != nil {
					req.Callback(cached, nil)
				}
			}
			continue
		}

		// Make API call
		services, err := clientset.CoreV1().Services(namespace).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			// Return error to all requests in this group
			for _, req := range group {
				if req.Callback != nil {
					req.Callback(nil, err)
				}
			}
			continue
		}

		// Cache the result
		apiCache.Set(cacheKey, services, cacheConfig.TTL)

		// Return result to all requests in this group
		for _, req := range group {
			if req.Callback != nil {
				req.Callback(services, nil)
			}
		}
	}

	return nil
}

// processDeploymentListBatch processes a batch of deployment list requests
func processDeploymentListBatch(requests []*BatchRequest) error {
	// Group by namespace for efficient API calls
	namespaceGroups := make(map[string][]*BatchRequest)
	for _, req := range requests {
		namespace := req.Params["namespace"].(string)
		namespaceGroups[namespace] = append(namespaceGroups[namespace], req)
	}

	// Process each namespace
	for namespace, group := range namespaceGroups {
		// Check cache first
		cacheKey := fmt.Sprintf("deployments:%s", namespace)
		if cached, found := apiCache.Get(cacheKey); found {
			// Return cached result to all requests in this group
			for _, req := range group {
				if req.Callback != nil {
					req.Callback(cached, nil)
				}
			}
			continue
		}

		// Make API call
		deployments, err := clientset.AppsV1().Deployments(namespace).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			// Return error to all requests in this group
			for _, req := range group {
				if req.Callback != nil {
					req.Callback(nil, err)
				}
			}
			continue
		}

		// Cache the result
		apiCache.Set(cacheKey, deployments, cacheConfig.TTL)

		// Return result to all requests in this group
		for _, req := range group {
			if req.Callback != nil {
				req.Callback(deployments, nil)
			}
		}
	}

	return nil
}

// CachedListPods returns pods with caching support
func (c *DefaultKubernetesClient) CachedListPods(ctx context.Context, namespace string) (*corev1.PodList, error) {
	cacheKey := fmt.Sprintf("pods:%s", namespace)

	// Check cache first
	if cached, found := c.cache.Get(cacheKey); found {
		if pods, ok := cached.(*corev1.PodList); ok {
			return pods, nil
		}
	}

	// Make API call with retry
	var pods *corev1.PodList
	err := retry.KubernetesRetryWithCircuitBreaker(ctx, func() error {
		var err error
		pods, err = c.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
		return err
	})

	if err != nil {
		return nil, err
	}

	// Cache the result
	c.cache.Set(cacheKey, pods, cacheConfig.TTL)

	return pods, nil
}

// BatchListPods adds a pod list request to the batch processor
func (c *DefaultKubernetesClient) BatchListPods(namespace string, callback func(*corev1.PodList, error)) {
	req := &BatchRequest{
		ID:   fmt.Sprintf("pods_%s_%d", namespace, time.Now().UnixNano()),
		Type: "list_pods",
		Params: map[string]interface{}{
			"namespace": namespace,
		},
		Callback: func(data interface{}, err error) {
			if err != nil {
				callback(nil, err)
				return
			}
			if pods, ok := data.(*corev1.PodList); ok {
				callback(pods, nil)
			} else {
				callback(nil, fmt.Errorf("invalid data type for pod list"))
			}
		},
	}

	batchProcessor.AddRequest(req)
}

// InvalidateCache invalidates cache entries for a specific resource type
func (c *DefaultKubernetesClient) InvalidateCache(resourceType, namespace string) {
	cacheKey := fmt.Sprintf("%s:%s", resourceType, namespace)
	c.cache.Delete(cacheKey)
}

// GetCacheStats returns cache statistics
func (c *DefaultKubernetesClient) GetCacheStats() map[string]interface{} {
	return c.cache.GetStats()
}

// startCredentialRotation starts a background goroutine for credential rotation
func startCredentialRotation(ctx context.Context, rotationHours int) {
	ticker := time.NewTicker(time.Duration(rotationHours) * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if secureClient != nil {
				// Check if credential is expired
				expired, err := secureClient.IsCredentialExpired()
				if err != nil {
					errors.Warning("CREDENTIAL_EXPIRATION_CHECK_FAILED", "Error checking credential expiration: "+err.Error())
					continue
				}

				if expired {
					fmt.Println("Kubernetes credentials expired, attempting rotation...")
					// Try to reload from kubeconfig
					kubeconfigPath := os.Getenv("KUBECONFIG")
					if kubeconfigPath == "" {
						kubeconfigPath = clientcmd.RecommendedHomeFile
					}

					err = secureClient.RotateCredentials(kubeconfigPath)
					if err != nil {
						errors.Warning("CREDENTIAL_ROTATION_FAILED", "Failed to rotate credentials: "+err.Error())
					} else {
						errors.Info("CREDENTIAL_ROTATION_SUCCESS", "Credentials rotated successfully")
						// Update global clientset
						clientset = secureClient.GetClientset()
						// Clear cache after credential rotation
						if apiCache != nil {
							apiCache.Clear()
						}
					}
				}
			}
		}
	}
}

// ValidateCredentials validates the current stored credentials
func ValidateCredentials() error {
	if secureClient == nil {
		return fmt.Errorf("secure client not initialized")
	}
	return secureClient.ValidateStoredConfig()
}

// RotateCredentials manually rotates the Kubernetes credentials
func RotateCredentials(newKubeconfigPath string) error {
	if secureClient == nil {
		return fmt.Errorf("secure client not initialized")
	}

	err := secureClient.RotateCredentials(newKubeconfigPath)
	if err != nil {
		return err
	}

	// Update global clientset
	clientset = secureClient.GetClientset()
	return nil
}

func CopyToPod(localPath, namespace, podName, containerPath string) error {
	return CopyToPodWithContext(context.Background(), localPath, namespace, podName, containerPath)
}

// CopyToPod implements KubernetesClient interface
func (c *DefaultKubernetesClient) CopyToPod(localPath, namespace, podName, containerPath string) error {
	return c.CopyToPodWithContext(context.Background(), localPath, namespace, podName, containerPath)
}

func CopyToPodWithContext(ctx context.Context, localPath, namespace, podName, containerPath string) error {
	return copyToPodWithContext(ctx, localPath, namespace, podName, containerPath)
}

// CopyToPodWithContext implements KubernetesClient interface
func (c *DefaultKubernetesClient) CopyToPodWithContext(ctx context.Context, localPath, namespace, podName, containerPath string) error {
	return copyToPodWithContext(ctx, localPath, namespace, podName, containerPath)
}

// copyToPodWithContext copies files from local filesystem to a Kubernetes pod using kubectl.
// This function handles both file and directory copying with proper error handling and retry logic.
// It uses kubectl cp command which supports recursive directory copying and preserves file permissions.
//
// The function implements:
// 1. Retry mechanism with exponential backoff for transient failures
// 2. Context-aware cancellation for timeout control
// 3. Proper kubectl command construction with namespace and pod targeting
// 4. Error handling for various failure scenarios (network, permissions, etc.)
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - localPath: Source path on local filesystem (file or directory)
//   - namespace: Kubernetes namespace containing the target pod
//   - podName: Name of the target pod
//   - containerPath: Destination path inside the pod's container
//
// Returns:
//   - error: Any error encountered during the copy operation
func copyToPodWithContext(ctx context.Context, localPath, namespace, podName, containerPath string) error {
	return retry.KubernetesRetryWithCircuitBreaker(ctx, func() error {
		var cmd *exec.Cmd
		if isDirectory(localPath) {
			cmd = exec.Command("kubectl", "cp", fmt.Sprintf("%s/.", localPath), fmt.Sprintf("%s/%s:%s", namespace, podName, containerPath))
		} else {
			cmd = exec.Command("kubectl", "cp", localPath, fmt.Sprintf("%s/%s:%s", namespace, podName, containerPath))
		}

		// Set context for the command
		cmd = exec.CommandContext(ctx, cmd.Args[0], cmd.Args[1:]...)

		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to copy to pod %s: %s, output: %s", podName, err, output)
		}

		utils.Logger.Info("File(s) copied to pod:", podName)
		return nil
	})
}

func RestartDotnetProcess(namespace, podName string) error {
	return RestartDotnetProcessWithContext(context.Background(), namespace, podName)
}

// RestartDotnetProcess implements KubernetesClient interface
func (c *DefaultKubernetesClient) RestartDotnetProcess(namespace, podName string) error {
	return c.RestartDotnetProcessWithContext(context.Background(), namespace, podName)
}

func RestartDotnetProcessWithContext(ctx context.Context, namespace, podName string) error {
	return restartDotnetProcessWithContext(ctx, namespace, podName)
}

// RestartDotnetProcessWithContext implements KubernetesClient interface
func (c *DefaultKubernetesClient) RestartDotnetProcessWithContext(ctx context.Context, namespace, podName string) error {
	return restartDotnetProcessWithContext(ctx, namespace, podName)
}

func restartDotnetProcessWithContext(ctx context.Context, namespace, podName string) error {
	containerPath := "/app" // Default container path
	// Use the new generic RestartProcess function for .NET applications
	return restartProcessWithContext(ctx, namespace, podName, "dotnet", fmt.Sprintf("dotnet %s/api.dll", containerPath))
}

// RestartProcess restarts a generic process in a pod
func RestartProcess(namespace, podName, processName, startCommand string) error {
	return RestartProcessWithContext(context.Background(), namespace, podName, processName, startCommand)
}

// RestartProcess implements KubernetesClient interface
func (c *DefaultKubernetesClient) RestartProcess(namespace, podName, processName, startCommand string) error {
	return c.RestartProcessWithContext(context.Background(), namespace, podName, processName, startCommand)
}

// RestartProcessWithContext restarts a generic process in a pod with context
func RestartProcessWithContext(ctx context.Context, namespace, podName, processName, startCommand string) error {
	return restartProcessWithContext(ctx, namespace, podName, processName, startCommand)
}

// RestartProcessWithContext implements KubernetesClient interface
func (c *DefaultKubernetesClient) RestartProcessWithContext(ctx context.Context, namespace, podName, processName, startCommand string) error {
	return restartProcessWithContext(ctx, namespace, podName, processName, startCommand)
}

func restartProcessWithContext(ctx context.Context, namespace, podName, processName, startCommand string) error {
	return retry.KubernetesRetryWithCircuitBreaker(ctx, func() error {
		// Check if process is running
		checkCmd := exec.CommandContext(ctx, "kubectl", "exec", podName, "-n", namespace, "--", "pgrep", "-f", processName)
		if err := checkCmd.Run(); err != nil {
			fmt.Printf("%s process not found in pod %s, starting a new process...\n", processName, podName)
		} else {
			// Stop the existing process
			stopCmd := exec.CommandContext(ctx, "kubectl", "exec", podName, "-n", namespace, "--", "pkill", "-f", processName)
			stopOutput, err := stopCmd.CombinedOutput()
			if err != nil {
				if strings.Contains(string(stopOutput), "no process found") {
					fmt.Printf("%s process already stopped in pod %s\n", processName, podName)
				} else {
					return fmt.Errorf("failed to stop %s process in pod %s: %w\nOutput: %s", processName, podName, err, stopOutput)
				}
			} else {
				fmt.Printf("%s process stopped successfully in pod %s\n", processName, podName)
			}

			// Wait for process to stop
			for i := 0; i < 5; i++ {
				checkAgainCmd := exec.CommandContext(ctx, "kubectl", "exec", podName, "-n", namespace, "--", "pgrep", "-f", processName)
				if err := checkAgainCmd.Run(); err != nil {
					fmt.Printf("%s process confirmed stopped in pod %s\n", processName, podName)
					break
				}
				time.Sleep(1 * time.Second)
			}
		}

		// Start the process
		startCmd := exec.CommandContext(ctx, "kubectl", "exec", podName, "-n", namespace, "--", "sh", "-c", fmt.Sprintf("nohup %s > /dev/null 2>&1 &", startCommand))
		startOutput, err := startCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to start %s process in pod %s: %w\nOutput: %s", processName, podName, err, startOutput)
		}

		// Verify the process started
		for i := 0; i < 5; i++ {
			checkCmdAgain := exec.CommandContext(ctx, "kubectl", "exec", podName, "-n", namespace, "--", "pgrep", "-f", processName)
			if err := checkCmdAgain.Run(); err == nil {
				fmt.Printf("%s process started successfully in pod %s\n", processName, podName)
				return nil
			}
			time.Sleep(1 * time.Second)
		}

		return fmt.Errorf("failed to verify the start of %s process in pod %s", processName, podName)
	})
}

// Legacy function removed - now using generic RestartProcess implementation

func GetDeploymentSelector(namespace, deploymentName string) (string, error) {
	return GetDeploymentSelectorWithContext(context.Background(), namespace, deploymentName)
}

// GetDeploymentSelector implements KubernetesClient interface
func (c *DefaultKubernetesClient) GetDeploymentSelector(namespace, deployment string) (string, error) {
	return c.GetDeploymentSelectorWithContext(context.Background(), namespace, deployment)
}

func GetDeploymentSelectorWithContext(ctx context.Context, namespace, deploymentName string) (string, error) {
	return getDeploymentSelectorWithContext(ctx, namespace, deploymentName)
}

// GetDeploymentSelectorWithContext implements KubernetesClient interface
func (c *DefaultKubernetesClient) GetDeploymentSelectorWithContext(ctx context.Context, namespace, deployment string) (string, error) {
	return getDeploymentSelectorWithContext(ctx, namespace, deployment)
}

// getDeploymentSelectorWithContext retrieves the label selector for a Kubernetes deployment.
// This function queries the Kubernetes API to get a deployment's selector labels and converts
// them into a comma-separated string format suitable for kubectl and API queries. It implements:
//
// 1. Retry mechanism with exponential backoff for API resilience
// 2. Proper error handling for missing deployments or selectors
// 3. Label sorting with 'app' label prioritized for consistency
// 4. Context-aware cancellation for timeout control
//
// The returned selector string can be used with kubectl commands or Kubernetes API calls
// to filter pods belonging to the deployment.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - namespace: Kubernetes namespace containing the deployment
//   - deploymentName: Name of the deployment to query
//
// Returns:
//   - string: Comma-separated label selector (e.g., "app=myapp,version=v1")
//   - error: Any error encountered during API communication or processing
func getDeploymentSelectorWithContext(ctx context.Context, namespace, deploymentName string) (string, error) {
	return retry.KubernetesRetryWithCircuitBreakerResult(ctx, func() (string, error) {
		client := GetClientset()
		if client == nil {
			return "", fmt.Errorf("kubernetes client not initialized")
		}

		deployment, err := client.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
		if err != nil {
			return "", fmt.Errorf("failed to get deployment %s: %w", deploymentName, err)
		}

		if deployment.Spec.Selector == nil || deployment.Spec.Selector.MatchLabels == nil {
			return "", fmt.Errorf("deployment %s has no selector labels", deploymentName)
		}

		labels := deployment.Spec.Selector.MatchLabels

		// Convert labels to key=value pairs
		var labelPairs []string
		for key, value := range labels {
			labelPairs = append(labelPairs, fmt.Sprintf("%s=%s", key, value))
		}

		// Sort for consistent output
		var sortedPairs []string
		for _, pair := range labelPairs {
			sortedPairs = append(sortedPairs, pair)
		}
		// Simple sort by putting app first if it exists, then alphabetical
		var appPair string
		var otherPairs []string
		for _, pair := range sortedPairs {
			if strings.HasPrefix(pair, "app=") {
				appPair = pair
			} else {
				otherPairs = append(otherPairs, pair)
			}
		}

		var result []string
		if appPair != "" {
			result = append(result, appPair)
		}
		result = append(result, otherPairs...)

		return strings.Join(result, ","), nil
	})
}

func GetPodNames(namespace, labelSelector string) ([]string, error) {
	return GetPodNamesWithContext(context.Background(), namespace, labelSelector)
}

// GetPodNames implements KubernetesClient interface
func (c *DefaultKubernetesClient) GetPodNames(namespace, labelSelector string) ([]string, error) {
	return c.GetPodNamesWithContext(context.Background(), namespace, labelSelector)
}

func GetPodNamesWithContext(ctx context.Context, namespace, labelSelector string) ([]string, error) {
	return getClientPodNamesWithContext(ctx, namespace, labelSelector)
}

// GetPodNamesWithContext implements KubernetesClient interface
func (c *DefaultKubernetesClient) GetPodNamesWithContext(ctx context.Context, namespace, labelSelector string) ([]string, error) {
	return getClientPodNamesWithContext(ctx, namespace, labelSelector)
}

func getClientPodNamesWithContext(ctx context.Context, namespace, labelSelector string) ([]string, error) {
	return retry.KubernetesRetryWithCircuitBreakerResult(ctx, func() ([]string, error) {
		cmd := exec.CommandContext(ctx, "kubectl", "get", "pods", "-n", namespace, "-l", labelSelector, "-o", "jsonpath={.items[*].metadata.name}")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("failed to get pod names with label selector %s: %w", labelSelector, err)
		}

		podNames := strings.Fields(string(output))
		if len(podNames) == 0 {
			return nil, fmt.Errorf("no pods found with label selector %s", labelSelector)
		}
		return podNames, nil
	})
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// PodContainer represents a container within a pod
type PodContainer struct {
	PodName       string
	ContainerName string
	Namespace     string
}

// GetPodContainers returns all containers for all pods matching the label selector
func GetPodContainers(namespace, labelSelector string) ([]PodContainer, error) {
	return GetPodContainersWithContext(context.Background(), namespace, labelSelector)
}

// GetPodContainers implements KubernetesClient interface
func (c *DefaultKubernetesClient) GetPodContainers(namespace, deployment string) ([]PodContainer, error) {
	return GetPodContainersWithContext(context.Background(), namespace, deployment)
}

// GetPodContainersWithContext returns all containers for all pods matching the label selector with context
func GetPodContainersWithContext(ctx context.Context, namespace, labelSelector string) ([]PodContainer, error) {
	return retry.KubernetesRetryWithCircuitBreakerResult(ctx, func() ([]PodContainer, error) {
		if clientset == nil {
			return nil, fmt.Errorf("kubernetes client not initialized")
		}

		pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
			LabelSelector: labelSelector,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list pods: %w", err)
		}

		var containers []PodContainer
		for _, pod := range pods.Items {
			for _, container := range pod.Spec.Containers {
				containers = append(containers, PodContainer{
					PodName:       pod.Name,
					ContainerName: container.Name,
					Namespace:     namespace,
				})
			}
		}

		if len(containers) == 0 {
			return nil, fmt.Errorf("no containers found for label selector %s", labelSelector)
		}

		return containers, nil
	})
}

// GetContainersForPod returns all container names for a specific pod
func GetContainersForPod(namespace, podName string) ([]string, error) {
	return getContainersForPod(namespace, podName)
}

// GetContainersForPod implements KubernetesClient interface
func (c *DefaultKubernetesClient) GetContainersForPod(namespace, podName string) ([]string, error) {
	return getContainersForPod(namespace, podName)
}

func getContainersForPod(namespace, podName string) ([]string, error) {
	return GetContainersForPodWithContext(context.Background(), namespace, podName)
}

// GetContainersForPodWithContext returns all containers for a specific pod with context
func GetContainersForPodWithContext(ctx context.Context, namespace, podName string) ([]string, error) {
	return retry.KubernetesRetryWithCircuitBreakerResult(ctx, func() ([]string, error) {
		if clientset == nil {
			return nil, fmt.Errorf("kubernetes client not initialized")
		}

		pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get pod %s: %w", podName, err)
		}

		var containerNames []string
		for _, container := range pod.Spec.Containers {
			containerNames = append(containerNames, container.Name)
		}

		if len(containerNames) == 0 {
			return nil, fmt.Errorf("no containers found in pod %s", podName)
		}

		return containerNames, nil
	})
}

// CopyToPodContainer copies a file to a specific container in a pod
func CopyToPodContainer(localPath, namespace, podName, containerName, containerPath string) error {
	return copyToPodContainer(localPath, namespace, podName, containerName, containerPath)
}

// CopyToPodContainer implements KubernetesClient interface
func (c *DefaultKubernetesClient) CopyToPodContainer(localPath, namespace, podName, containerName, containerPath string) error {
	return copyToPodContainer(localPath, namespace, podName, containerName, containerPath)
}

func copyToPodContainer(localPath, namespace, podName, containerName, containerPath string) error {
	return CopyToPodContainerWithContext(context.Background(), namespace, podName, containerName, localPath, containerPath)
}

// StreamPodLogs streams logs from a pod to the provided writer
func StreamPodLogs(namespace, podName string, output io.Writer) error {
	return StreamPodLogsWithContext(context.Background(), namespace, podName, output)
}

// StreamPodLogs implements KubernetesClient interface
func (c *DefaultKubernetesClient) StreamPodLogs(namespace, podName string, output io.Writer) error {
	return c.StreamPodLogsWithContext(context.Background(), namespace, podName, output)
}

// StreamPodLogsWithContext streams logs from a pod to the provided writer with context
func StreamPodLogsWithContext(ctx context.Context, namespace, podName string, output io.Writer) error {
	return streamPodLogsWithContext(ctx, namespace, podName, output)
}

// StreamPodLogsWithContext implements KubernetesClient interface
func (c *DefaultKubernetesClient) StreamPodLogsWithContext(ctx context.Context, namespace, podName string, output io.Writer) error {
	return streamPodLogsWithContext(ctx, namespace, podName, output)
}

// StreamContainerLogsWithContext streams logs from a specific container to the provided writer with context
func (c *DefaultKubernetesClient) StreamContainerLogsWithContext(ctx context.Context, namespace, podName, containerName string, output io.Writer) error {
	return streamContainerLogsWithContext(ctx, namespace, podName, containerName, output)
}

func streamPodLogsWithContext(ctx context.Context, namespace, podName string, output io.Writer) error {
	if clientset == nil {
		return fmt.Errorf("kubernetes client not initialized")
	}

	req := clientset.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
		Follow: true,
	})

	logs, err := req.Stream(ctx)
	if err != nil {
		return fmt.Errorf("failed to stream logs for pod %s: %w", podName, err)
	}
	defer logs.Close()

	_, err = io.Copy(output, logs)
	return err
}

func streamContainerLogsWithContext(ctx context.Context, namespace, podName, containerName string, output io.Writer) error {
	if clientset == nil {
		return fmt.Errorf("kubernetes client not initialized")
	}

	req := clientset.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
		Follow:    true,
		Container: containerName,
	})

	logs, err := req.Stream(ctx)
	if err != nil {
		return fmt.Errorf("failed to stream logs for container %s in pod %s: %w", containerName, podName, err)
	}
	defer logs.Close()

	_, err = io.Copy(output, logs)
	return err
}

// CopyToPodContainerWithContext copies a file to a specific container in a pod with context support
func CopyToPodContainerWithContext(ctx context.Context, namespace, podName, containerName, srcPath, destPath string) error {
	cmd := exec.CommandContext(ctx, "kubectl", "cp", srcPath, fmt.Sprintf("%s/%s:%s", namespace, podName, destPath), "-c", containerName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
