package utils

import (
	"fmt"

	"github.com/fsnotify/fsnotify"
)

type Watcher struct {
	watcher *fsnotify.Watcher
}

func NewWatcher() (*Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}
	return &Watcher{watcher: watcher}, nil
}

func (w *Watcher) Watch(path string, onChange func(event fsnotify.Event)) error {
	err := w.watcher.Add(path)
	if err != nil {
		return fmt.Errorf("failed to watch path %s: %w", path, err)
	}

	go func() {
		for {
			select {
			case event, ok := <-w.watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Remove == fsnotify.Remove {
					onChange(event)
				}
			case err, ok := <-w.watcher.Errors:
				if !ok {
					return
				}
				fmt.Println("Error watching file:", err)
			}
		}
	}()
	return nil
}

func (w *Watcher) Close() error {
	return w.watcher.Close()
}
