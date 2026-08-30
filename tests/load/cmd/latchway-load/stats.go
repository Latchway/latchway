package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maximumProcArgv0Bytes   = 4096
	maximumProcessNameBytes = 255
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
		value, found, err := processRSSMiBFromProc(pid)
		if err != nil {
			return 0, err
		}
		if found {
			return value, nil
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

func processRSSMiBFromProc(pid int) (value float64, found bool, resultErr error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, false, nil
	}
	defer func() {
		if closeErr := file.Close(); resultErr == nil && closeErr != nil {
			value = 0
			found = false
			resultErr = errors.New("close gateway proc status")
		}
	}()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 3 && fields[0] == "VmRSS:" && fields[2] == "kB" {
			value, parseErr := strconv.ParseFloat(fields[1], 64)
			if parseErr != nil {
				return 0, false, parseErr
			}
			return value / 1024, true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, false, err
	}
	return 0, false, nil
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
		file, err := os.Open(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			return "", fmt.Errorf("read gateway executable identity: %w", err)
		}
		name, readErr := processExecutableFromProcCmdline(file)
		closeErr := file.Close()
		if readErr != nil {
			return "", readErr
		}
		if closeErr != nil {
			return "", errors.New("close gateway executable identity")
		}
		return name, nil
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

func processExecutableFromProcCmdline(reader io.Reader) (string, error) {
	if reader == nil {
		return "", errors.New("gateway executable cmdline is unavailable")
	}
	contents, err := io.ReadAll(io.LimitReader(reader, maximumProcArgv0Bytes+1))
	if err != nil {
		return "", fmt.Errorf("read gateway executable cmdline: %w", err)
	}
	delimiter := bytes.IndexByte(contents, 0)
	if delimiter < 0 {
		if len(contents) > maximumProcArgv0Bytes {
			return "", errors.New("gateway executable argv0 exceeds the procfs bound")
		}
		return "", errors.New("gateway executable cmdline is not NUL-delimited")
	}
	if delimiter == 0 {
		return "", errors.New("gateway executable argv0 is empty")
	}
	argv0 := contents[:delimiter]
	if !utf8.Valid(argv0) {
		return "", errors.New("gateway executable argv0 is not valid UTF-8")
	}
	for _, character := range argv0 {
		if character < 0x20 || character == 0x7f {
			return "", errors.New("gateway executable argv0 contains control characters")
		}
	}
	name := path.Base(string(argv0))
	if name == "" || name == "." || name == "/" || len(name) > maximumProcessNameBytes {
		return "", errors.New("gateway executable argv0 has an invalid basename")
	}
	return name, nil
}
