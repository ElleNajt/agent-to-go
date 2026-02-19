package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config for spawn restrictions
type Config struct {
	AllowedCommands    []string `yaml:"allowed_commands"`
	AllowedDirectories []string `yaml:"allowed_directories"`
}

var config *Config // nil = spawn disabled

func loadConfig() *Config {
	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".config", "agent-to-go", "config.yaml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil // No config = spawn disabled
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Printf("Warning: invalid config file: %v", err)
		return nil
	}

	// Expand ~ in directory paths
	for i, dir := range cfg.AllowedDirectories {
		if strings.HasPrefix(dir, "~/") {
			cfg.AllowedDirectories[i] = filepath.Join(home, dir[2:])
		} else if dir == "~" {
			cfg.AllowedDirectories[i] = home
		}
	}

	return &cfg
}

func isCommandAllowed(cmd string) bool {
	if config == nil {
		return false
	}
	for _, allowed := range config.AllowedCommands {
		if cmd == allowed {
			return true
		}
	}
	return false
}

func isDirectoryAllowed(dir string) bool {
	if config == nil {
		return false
	}
	// Resolve to absolute path, following symlinks if the path exists
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(absDir); err == nil {
		absDir = resolved
	}
	// Check if under any allowed directory
	for _, allowed := range config.AllowedDirectories {
		absAllowed, err := filepath.Abs(allowed)
		if err != nil {
			continue
		}
		if resolved, err := filepath.EvalSymlinks(absAllowed); err == nil {
			absAllowed = resolved
		}
		// Must be exactly the allowed dir or a subdirectory
		if absDir == absAllowed || strings.HasPrefix(absDir, absAllowed+"/") {
			return true
		}
	}
	return false
}
