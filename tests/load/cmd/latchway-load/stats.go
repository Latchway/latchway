package main

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

func percentile(samples []time.Duration, percentile float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	ordered := append([]time.Duration(nil), samples...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left] < ordered[right] })
	if percentile <= 0 {
		return ordered[0]
	}
	if percentile >= 1 {
		return ordered[len(ordered)-1]
	}
	index := int(math.Ceil(percentile*float64(len(ordered)))) - 1
	return ordered[max(0, min(index, len(ordered)-1))]
}

type memorySample struct {
	At  time.Time
	MiB float64
}

func memorySlopeMiBPerMinute(samples []memorySample) float64 {
	if len(samples) < 2 {
		return 0
	}
	origin := samples[0].At
	var sumX, sumY, sumXY, sumXX float64
	for _, sample := range samples {
		x := sample.At.Sub(origin).Minutes()
		y := sample.MiB
		sumX += x
		sumY += y
		sumXY += x * y
		sumXX += x * x
	}
	n := float64(len(samples))
	denominator := n*sumXX - sumX*sumX
	if denominator == 0 {
		return 0
	}
	return (n*sumXY - sumX*sumY) / denominator
}

func processRSSMiB(pid int) (float64, error) {
	if pid <= 0 {
		return 0, errors.New("invalid gateway pid")
	}
	if runtime.GOOS == "linux" {
		file, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				fields := strings.Fields(scanner.Text())
				if len(fields) == 3 && fields[0] == "VmRSS:" && fields[2] == "kB" {
					value, parseErr := strconv.ParseFloat(fields[1], 64)
					if parseErr != nil {
						return 0, parseErr
					}
					return value / 1024, nil
				}
			}
			if err := scanner.Err(); err != nil {
				return 0, err
			}
		}
	}
	output, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, fmt.Errorf("read gateway RSS: %w", err)
	}
	kib, err := strconv.ParseFloat(strings.TrimSpace(string(output)), 64)
	if err != nil {
		return 0, errors.New("read gateway RSS: invalid ps output")
	}
	return kib / 1024, nil
}

func resolvePID(cfg gatewayConfig) (int, error) {
	if cfg.PID > 0 {
		return cfg.PID, nil
	}
	contents, err := os.ReadFile(cfg.PIDFile)
	if err != nil {
		return 0, fmt.Errorf("read gateway pid file: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(contents)))
	if err != nil || pid <= 0 {
		return 0, errors.New("gateway pid file does not contain one positive pid")
	}
	return pid, nil
}

func processExecutable(pid int) (string, error) {
	if pid <= 0 {
		return "", errors.New("invalid gateway pid")
	}
	if runtime.GOOS == "linux" {
		if target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil && target != "" {
			return filepath.Base(target), nil
		}
	}
	output, err := exec.Command("ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return "", fmt.Errorf("read gateway executable identity: %w", err)
	}
	name := filepath.Base(strings.TrimSpace(string(output)))
	if name == "" {
		return "", errors.New("gateway executable identity is empty")
	}
	return name, nil
}
