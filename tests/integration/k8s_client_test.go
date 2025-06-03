package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	k8s "github.com/kariyertech/Truva.git/internal/k8s"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestK8sClientIntegration(t *testing.T) {
	tests := []struct {
		name string
		fn   func(t *testing.T)
	}{
		{"TestCreateAndGetPod", testCreateAndGetPod},
		{"TestListPods", testListPods},
		{"TestUpdatePod", testUpdatePod},
		{"TestDeletePod", testDeletePod},
		{"TestWatchPods", testWatchPods},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.fn)
	}
}

func testCreateAndGetPod(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	client := &k8s.Client{
		Clientset: clientset,
		Namespace: "default",
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels: map[string]string{
				"app": "test",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "test-container",
					Image: "nginx:latest",
				},
			},
		},
	}

	// Create pod
	createdPod, err := client.CreatePod(context.Background(), pod)
	require.NoError(t, err)
	assert.Equal(t, "test-pod", createdPod.Name)
	assert.Equal(t, "default", createdPod.Namespace)

	// Get pod
	retrievedPod, err := client.GetPod(context.Background(), "test-pod")
	require.NoError(t, err)
	assert.Equal(t, "test-pod", retrievedPod.Name)
	assert.Equal(t, "test", retrievedPod.Labels["app"])
}

func testListPods(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	client := &k8s.Client{
		Clientset: clientset,
		Namespace: "default",
	}

	// Create multiple pods
	for i := 0; i < 3; i++ {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("test-pod-%d", i),
				Namespace: "default",
				Labels: map[string]string{
					"app": "test",
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "test-container",
						Image: "nginx:latest",
					},
				},
			},
		}
		_, err := client.CreatePod(context.Background(), pod)
		require.NoError(t, err)
	}

	// List pods
	pods, err := client.ListPods(context.Background(), metav1.ListOptions{
		LabelSelector: "app=test",
	})
	require.NoError(t, err)
	assert.Len(t, pods.Items, 3)
}

func testUpdatePod(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	client := &k8s.Client{
		Clientset: clientset,
		Namespace: "default",
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels: map[string]string{
				"app": "test",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "test-container",
					Image: "nginx:latest",
				},
			},
		},
	}

	// Create pod
	createdPod, err := client.CreatePod(context.Background(), pod)
	require.NoError(t, err)

	// Update pod labels
	createdPod.Labels["version"] = "v1.0"
	updatedPod, err := client.UpdatePod(context.Background(), createdPod)
	require.NoError(t, err)
	assert.Equal(t, "v1.0", updatedPod.Labels["version"])
}

func testDeletePod(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	client := &k8s.Client{
		Clientset: clientset,
		Namespace: "default",
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "test-container",
					Image: "nginx:latest",
				},
			},
		},
	}

	// Create pod
	_, err := client.CreatePod(context.Background(), pod)
	require.NoError(t, err)

	// Delete pod
	err = client.DeletePod(context.Background(), "test-pod")
	require.NoError(t, err)

	// Verify pod is deleted
	_, err = client.GetPod(context.Background(), "test-pod")
	assert.Error(t, err)
}

func testWatchPods(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	client := &k8s.Client{
		Clientset: clientset,
		Namespace: "default",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start watching
	watcher, err := client.WatchPods(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	defer watcher.Stop()

	// Create a pod in a goroutine
	go func() {
		time.Sleep(100 * time.Millisecond)
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "watch-test-pod",
				Namespace: "default",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "test-container",
						Image: "nginx:latest",
					},
				},
			},
		}
		_, _ = client.CreatePod(context.Background(), pod)
	}()

	// Wait for watch event
	select {
	case event := <-watcher.ResultChan():
		pod, ok := event.Object.(*corev1.Pod)
		require.True(t, ok)
		assert.Equal(t, "watch-test-pod", pod.Name)
	case <-ctx.Done():
		t.Fatal("Timeout waiting for watch event")
	}
}
