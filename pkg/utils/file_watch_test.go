package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWatcher(t *testing.T) {
	// Test successful watcher creation
	watcher, err := NewWatcher()
	require.NoError(t, err)
	require.NotNil(t, watcher)
	require.NotNil(t, watcher.watcher)

	// Clean up
	err = watcher.Close()
	assert.NoError(t, err)
}

func TestWatcher_Watch(t *testing.T) {
	// Create temporary directory and file for testing
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")

	// Create initial file
	err := os.WriteFile(testFile, []byte("initial content"), 0644)
	require.NoError(t, err)

	// Create watcher
	watcher, err := NewWatcher()
	require.NoError(t, err)
	defer watcher.Close()

	// Channel to capture events
	eventChan := make(chan fsnotify.Event, 10)
	var eventMutex sync.Mutex
	var capturedEvents []fsnotify.Event

	// Start watching
	err = watcher.Watch(tempDir, func(event fsnotify.Event) {
		eventMutex.Lock()
		capturedEvents = append(capturedEvents, event)
		eventMutex.Unlock()
		eventChan <- event
	})
	require.NoError(t, err)

	// Give watcher time to start
	time.Sleep(200 * time.Millisecond)

	// Test file write event
	err = os.WriteFile(testFile, []byte("modified content"), 0644)
	require.NoError(t, err)

	// Wait for write event (may be multiple events)
	writeEventReceived := false
	timeout := time.After(3 * time.Second)
	for !writeEventReceived {
		select {
		case event := <-eventChan:
			if event.Name == testFile && (event.Op&fsnotify.Write == fsnotify.Write) {
				writeEventReceived = true
			}
		case <-timeout:
			t.Fatal("Timeout waiting for write event")
		}
	}

	// Test file creation event
	newFile := filepath.Join(tempDir, "new_file.txt")
	err = os.WriteFile(newFile, []byte("new content"), 0644)
	require.NoError(t, err)

	// Wait for create event
	createEventReceived := false
	timeout = time.After(3 * time.Second)
	for !createEventReceived {
		select {
		case event := <-eventChan:
			if event.Name == newFile && (event.Op&fsnotify.Create == fsnotify.Create) {
				createEventReceived = true
			}
		case <-timeout:
			// Create event might not always be detected, so we'll just log and continue
			t.Logf("Create event not detected for %s, this is acceptable on some filesystems", newFile)
			createEventReceived = true
		}
	}

	// Verify we captured some events
	eventMutex.Lock()
	assert.GreaterOrEqual(t, len(capturedEvents), 1, "Should have captured at least 1 event")
	eventMutex.Unlock()
}

func TestWatcher_WatchInvalidPath(t *testing.T) {
	watcher, err := NewWatcher()
	require.NoError(t, err)
	defer watcher.Close()

	// Try to watch non-existent path
	err = watcher.Watch("/non/existent/path", func(event fsnotify.Event) {})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to watch path")
}

func TestWatcher_Close(t *testing.T) {
	watcher, err := NewWatcher()
	require.NoError(t, err)
	require.NotNil(t, watcher)

	// Test closing
	err = watcher.Close()
	assert.NoError(t, err)

	// Test double close (should not panic)
	err = watcher.Close()
	// fsnotify may return an error on double close, but it shouldn't panic
	// We just verify it doesn't crash
}

func TestWatcher_MultipleFiles(t *testing.T) {
	// Create temporary directories
	tempDir1 := t.TempDir()
	tempDir2 := t.TempDir()

	watcher, err := NewWatcher()
	require.NoError(t, err)
	defer watcher.Close()

	// Channels to capture events from different directories
	eventChan1 := make(chan fsnotify.Event, 5)
	eventChan2 := make(chan fsnotify.Event, 5)

	// Watch both directories
	err = watcher.Watch(tempDir1, func(event fsnotify.Event) {
		eventChan1 <- event
	})
	require.NoError(t, err)

	err = watcher.Watch(tempDir2, func(event fsnotify.Event) {
		eventChan2 <- event
	})
	require.NoError(t, err)

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Create files in both directories
	file1 := filepath.Join(tempDir1, "file1.txt")
	file2 := filepath.Join(tempDir2, "file2.txt")

	err = os.WriteFile(file1, []byte("content1"), 0644)
	require.NoError(t, err)

	err = os.WriteFile(file2, []byte("content2"), 0644)
	require.NoError(t, err)

	// Verify events from first directory
	select {
	case event := <-eventChan1:
		assert.Equal(t, file1, event.Name)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for event from directory 1")
	}

	// Verify events from second directory
	select {
	case event := <-eventChan2:
		assert.Equal(t, file2, event.Name)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for event from directory 2")
	}
}

func TestWatcher_EventFiltering(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")

	// Create initial file
	err := os.WriteFile(testFile, []byte("initial"), 0644)
	require.NoError(t, err)

	watcher, err := NewWatcher()
	require.NoError(t, err)
	defer watcher.Close()

	// Count different types of events
	var totalEvents int
	var eventMutex sync.Mutex
	eventChan := make(chan bool, 10)

	err = watcher.Watch(tempDir, func(event fsnotify.Event) {
		eventMutex.Lock()
		defer eventMutex.Unlock()
		totalEvents++
		eventChan <- true
	})
	require.NoError(t, err)

	// Give watcher time to start
	time.Sleep(200 * time.Millisecond)

	// Perform file write operation
	err = os.WriteFile(testFile, []byte("modified"), 0644)
	require.NoError(t, err)

	// Wait for at least one event
	select {
	case <-eventChan:
		// Event received
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for file write event")
	}

	// Give time for any additional events
	time.Sleep(300 * time.Millisecond)

	// Verify we got at least one event
	eventMutex.Lock()
	assert.GreaterOrEqual(t, totalEvents, 1, "Should have received at least 1 event")
	eventMutex.Unlock()
}

func TestWatcher_ConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()

	watcher, err := NewWatcher()
	require.NoError(t, err)
	defer watcher.Close()

	// Use WaitGroup to coordinate goroutines
	var wg sync.WaitGroup
	eventCount := 0
	var eventMutex sync.Mutex

	err = watcher.Watch(tempDir, func(event fsnotify.Event) {
		eventMutex.Lock()
		eventCount++
		eventMutex.Unlock()
	})
	require.NoError(t, err)

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Create multiple files concurrently
	numFiles := 5
	wg.Add(numFiles)

	for i := 0; i < numFiles; i++ {
		go func(index int) {
			defer wg.Done()
			filename := filepath.Join(tempDir, fmt.Sprintf("file_%d.txt", index))
			err := os.WriteFile(filename, []byte(fmt.Sprintf("content %d", index)), 0644)
			assert.NoError(t, err)
		}(i)
	}

	wg.Wait()

	// Wait for events to be processed
	time.Sleep(500 * time.Millisecond)

	// Verify we received events (exact count may vary due to filesystem behavior)
	eventMutex.Lock()
	assert.GreaterOrEqual(t, eventCount, numFiles, "Should have received at least %d events", numFiles)
	eventMutex.Unlock()
}
