package k8s

import (
	"os"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestInitClient(t *testing.T) {
	tests := []struct {
		name       string
		kubeconfig string
		wantErr    bool
	}{
		{
			name:       "valid kubeconfig path",
			kubeconfig: "/tmp/test-kubeconfig",
			wantErr:    true, // Will fail because file doesn't exist, but tests the path logic
		},
		{
			name:       "empty kubeconfig uses default",
			kubeconfig: "",
			wantErr:    false, // May succeed if default kubeconfig exists
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.kubeconfig != "" {
				os.Setenv("KUBECONFIG", tt.kubeconfig)
				defer os.Unsetenv("KUBECONFIG")
			}

			err := InitClient()
			if (err != nil) != tt.wantErr {
				t.Errorf("InitClient() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetClient(t *testing.T) {
	// Test when clientset is nil
	clientset = nil
	client := GetClient()
	if client != nil {
		t.Errorf("GetClient() should return nil when clientset is not initialized")
	}

	// Test when clientset is set
	fakeClientset := fake.NewSimpleClientset()
	clientset = fakeClientset
	client = GetClient()
	if client == nil {
		t.Errorf("GetClient() should return clientset when initialized")
	}
}

func TestIsDirectory(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "existing directory",
			path: "/tmp",
			want: true,
		},
		{
			name: "non-existing path",
			path: "/non/existing/path",
			want: false,
		},
		{
			name: "empty path",
			path: "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDirectory(tt.path); got != tt.want {
				t.Errorf("isDirectory() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetPodContainers(t *testing.T) {
	// Create fake clientset with test pods
	fakeClientset := fake.NewSimpleClientset(
		&v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod-1",
				Namespace: "default",
				Labels: map[string]string{
					"app":     "test-app",
					"version": "v1",
				},
			},
			Spec: v1.PodSpec{
				Containers: []v1.Container{
					{Name: "container-1"},
					{Name: "container-2"},
				},
			},
			Status: v1.PodStatus{
				Phase: v1.PodRunning,
			},
		},
		&v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod-2",
				Namespace: "default",
				Labels: map[string]string{
					"app": "test-app",
				},
			},
			Spec: v1.PodSpec{
				Containers: []v1.Container{
					{Name: "container-3"},
				},
			},
			Status: v1.PodStatus{
				Phase: v1.PodRunning,
			},
		},
	)

	// Set the fake clientset
	clientset = fakeClientset

	tests := []struct {
		name          string
		namespace     string
		labelSelector string
		wantCount     int
		wantErr       bool
	}{
		{
			name:          "find containers by app label",
			namespace:     "default",
			labelSelector: "app=test-app",
			wantCount:     3, // 2 containers from pod-1 + 1 from pod-2
			wantErr:       false,
		},
		{
			name:          "find containers by multiple labels",
			namespace:     "default",
			labelSelector: "app=test-app,version=v1",
			wantCount:     2, // 2 containers from pod-1
			wantErr:       false,
		},
		{
			name:          "no matching pods",
			namespace:     "default",
			labelSelector: "app=non-existing",
			wantCount:     0,
			wantErr:       true, // No containers found should return error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			containers, err := GetPodContainers(tt.namespace, tt.labelSelector)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPodContainers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(containers) != tt.wantCount {
				t.Errorf("GetPodContainers() got %d containers, want %d", len(containers), tt.wantCount)
			}
		})
	}
}

func TestGetDeploymentSelector(t *testing.T) {
	// Create fake clientset with test deployments
	fakeClientset := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-deployment-1",
				Namespace: "default",
				Labels: map[string]string{
					"app":     "test-app",
					"version": "v1",
				},
			},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app":     "test-app",
						"version": "v1",
					},
				},
			},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-deployment-2",
				Namespace: "default",
				Labels: map[string]string{
					"app": "other-app",
				},
			},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "other-app",
					},
				},
			},
		},
	)

	// Set the fake clientset
	clientset = fakeClientset

	tests := []struct {
		name           string
		namespace      string
		deploymentName string
		wantSelector   string
		wantErr        bool
	}{
		{
			name:           "get selector from existing deployment",
			namespace:      "default",
			deploymentName: "test-deployment-1",
			wantSelector:   "app=test-app,version=v1",
			wantErr:        false,
		},
		{
			name:           "get selector from deployment with single label",
			namespace:      "default",
			deploymentName: "test-deployment-2",
			wantSelector:   "app=other-app",
			wantErr:        false,
		},
		{
			name:           "deployment not found",
			namespace:      "default",
			deploymentName: "non-existing",
			wantSelector:   "",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector, err := GetDeploymentSelector(tt.namespace, tt.deploymentName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetDeploymentSelector() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if selector != tt.wantSelector {
					t.Errorf("GetDeploymentSelector() got %v, want %v", selector, tt.wantSelector)
				}
			}
		})
	}
}
