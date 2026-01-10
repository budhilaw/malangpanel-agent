package monitor

import (
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// SystemInfo contains static system information
type SystemInfo struct {
	Hostname    string
	OS          string
	OSVersion   string
	Arch        string
	NumCPU      int
	TotalMemory uint64
}

// Metrics contains current system metrics
type Metrics struct {
	Timestamp time.Time

	// CPU
	CPUPercent float64
	CPUPerCore []float64

	// Memory
	MemoryTotal     uint64
	MemoryUsed      uint64
	MemoryAvailable uint64
	MemoryPercent   float64
	MemoryCached    uint64
	MemoryBuffers   uint64
	SwapTotal       uint64
	SwapUsed        uint64
	SwapFree        uint64
	SwapPercent     float64

	// Disk
	Disks  []DiskMetrics
	DiskIO []DiskIO

	// Network
	NetworkBytesSent uint64
	NetworkBytesRecv uint64
	Connections      uint64

	// Load (Linux only)
	Load1  float64
	Load5  float64
	Load15 float64

	// Uptime
	UptimeSeconds uint64
	HostInfo      *HostInfo
}

// DiskIO contains I/O metrics for a disk
type DiskIO struct {
	Name       string
	ReadCount  uint64
	WriteCount uint64
	ReadBytes  uint64
	WriteBytes uint64
}

// HostInfo contains host details
type HostInfo struct {
	Platform             string
	PlatformFamily       string
	PlatformVersion      string
	KernelVersion        string
	KernelArch           string
	VirtualizationSystem string
	VirtualizationRole   string
	BootTime             uint64
}

// DiskMetrics contains metrics for a single disk/partition
type DiskMetrics struct {
	MountPoint    string
	Device        string
	Total         uint64
	Used          uint64
	Free          uint64
	Percent       float64
	Fstype        string
	InodesTotal   uint64
	InodesUsed    uint64
	InodesPercent float64
}

// Monitor collects system metrics
type Monitor struct {
}

// New creates a new Monitor
func New() *Monitor {
	return &Monitor{}
}

// GetSystemInfo returns static system information
func (m *Monitor) GetSystemInfo() (*SystemInfo, error) {
	hostInfo, err := host.Info()
	if err != nil {
		return nil, err
	}

	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	return &SystemInfo{
		Hostname:    hostInfo.Hostname,
		OS:          hostInfo.OS,
		OSVersion:   hostInfo.PlatformVersion,
		Arch:        runtime.GOARCH,
		NumCPU:      runtime.NumCPU(),
		TotalMemory: memInfo.Total,
	}, nil
}

// Collect gathers current system metrics
func (m *Monitor) Collect() (*Metrics, error) {
	metrics := &Metrics{
		Timestamp: time.Now(),
	}

	// CPU
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err == nil && len(cpuPercent) > 0 {
		metrics.CPUPercent = cpuPercent[0]
	}

	cpuPerCore, err := cpu.Percent(time.Second, true)
	if err == nil {
		metrics.CPUPerCore = cpuPerCore
	}

	// Memory
	memInfo, err := mem.VirtualMemory()
	if err == nil {
		metrics.MemoryTotal = memInfo.Total
		metrics.MemoryUsed = memInfo.Used
		metrics.MemoryAvailable = memInfo.Available
		metrics.MemoryPercent = memInfo.UsedPercent
		metrics.MemoryCached = memInfo.Cached
		metrics.MemoryBuffers = memInfo.Buffers
	}

	// Swap
	swapInfo, err := mem.SwapMemory()
	if err == nil {
		metrics.SwapTotal = swapInfo.Total
		metrics.SwapUsed = swapInfo.Used
		metrics.SwapFree = swapInfo.Free
		metrics.SwapPercent = swapInfo.UsedPercent
	}

	// Disk
	partitions, err := disk.Partitions(false)
	if err == nil {
		for _, p := range partitions {
			usage, err := disk.Usage(p.Mountpoint)
			if err != nil {
				continue
			}
			metrics.Disks = append(metrics.Disks, DiskMetrics{
				MountPoint:    p.Mountpoint,
				Device:        p.Device,
				Total:         usage.Total,
				Used:          usage.Used,
				Free:          usage.Free,
				Percent:       usage.UsedPercent,
				Fstype:        usage.Fstype,
				InodesTotal:   usage.InodesTotal,
				InodesUsed:    usage.InodesUsed,
				InodesPercent: usage.InodesUsedPercent,
			})
		}
	}

	// Disk I/O
	diskIO, err := disk.IOCounters()
	if err == nil {
		for name, io := range diskIO {
			metrics.DiskIO = append(metrics.DiskIO, DiskIO{
				Name:       name,
				ReadCount:  io.ReadCount,
				WriteCount: io.WriteCount,
				ReadBytes:  io.ReadBytes,
				WriteBytes: io.WriteBytes,
			})
		}
	}

	// Network
	netStats, err := net.IOCounters(false)
	if err == nil && len(netStats) > 0 {
		metrics.NetworkBytesSent = netStats[0].BytesSent
		metrics.NetworkBytesRecv = netStats[0].BytesRecv
	}

	// Network Connections
	conns, err := net.Connections("all")
	if err == nil {
		metrics.Connections = uint64(len(conns))
	}

	// Load (Linux only)
	loadAvg, err := load.Avg()
	if err == nil {
		metrics.Load1 = loadAvg.Load1
		metrics.Load5 = loadAvg.Load5
		metrics.Load15 = loadAvg.Load15
	}

	// Host Info
	hostInfo, err := host.Info()
	if err == nil {
		metrics.UptimeSeconds = hostInfo.Uptime
		metrics.HostInfo = &HostInfo{
			Platform:             hostInfo.Platform,
			PlatformFamily:       hostInfo.PlatformFamily,
			PlatformVersion:      hostInfo.PlatformVersion,
			KernelVersion:        hostInfo.KernelVersion,
			KernelArch:           hostInfo.KernelArch,
			VirtualizationSystem: hostInfo.VirtualizationSystem,
			VirtualizationRole:   hostInfo.VirtualizationRole,
			BootTime:             hostInfo.BootTime,
		}
	}

	return metrics, nil
}

// ServiceInfo contains service status
type ServiceInfo struct {
	Name        string
	Status      string
	Restarts    int32
	LastRestart string
}

// ContainerInfo contains container status
type ContainerInfo struct {
	ID        string
	Name      string
	Image     string
	Status    string
	Health    string
	Restarts  int32
	StartedAt string
}

// GetServices returns status of systemd services
func (m *Monitor) GetServices() []ServiceInfo {
	services := []ServiceInfo{}

	// Check if systemd is available
	_, err := exec.LookPath("systemctl")
	if err != nil {
		return services
	}

	// List active and failed services
	// systemctl list-units --type=service --state=active,failed --no-pager --no-legend --plain
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--state=active,failed", "--no-pager", "--no-legend", "--plain")
	output, err := cmd.Output()
	if err != nil {
		return services
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		name := fields[0]
		// Remove .service suffix for cleaner display
		displayName := strings.TrimSuffix(name, ".service")

		activeState := fields[2] // active, failed
		subState := fields[3]    // running, exited, failed, dead

		var status string
		switch {
		case activeState == "active" && subState == "running":
			status = "running"
		case activeState == "failed":
			status = "failed"
		case activeState == "active" && subState == "exited":
			status = "exited"
		default:
			status = activeState
		}

		// Filter out some very transient or system-internal services if needed,
		// but for now we list what systemctl returns as "active/failed".
		// Maybe filter out "user@" services which are per-user
		if strings.HasPrefix(name, "user@") || strings.HasPrefix(name, "session-") {
			continue
		}

		services = append(services, ServiceInfo{
			Name:   displayName,
			Status: status,
		})
	}

	return services
}

// GetContainers returns status of Docker containers
func (m *Monitor) GetContainers() []ContainerInfo {
	containers := []ContainerInfo{}

	// Use docker ps to get container info
	// format: ID|Names|Image|Status|State
	cmd := exec.Command("docker", "ps", "-a", "--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.State}}")
	output, err := cmd.Output()
	if err != nil {
		// Docker might not be installed or running
		return containers
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 5 {
			continue
		}

		id := parts[0]
		name := parts[1]
		image := parts[2]
		state := parts[4]

		var status string
		switch state {
		case "running":
			status = "running"
		case "paused":
			status = "paused"
		case "exited":
			status = "exited"
		default:
			status = "stopped"
		}

		containers = append(containers, ContainerInfo{
			ID:     id,
			Name:   name,
			Image:  image,
			Status: status,
		})
	}
	return containers
}
