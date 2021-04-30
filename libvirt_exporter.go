// Copyright 2017 Kumina, https://kumina.nl/
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Project forked from https://github.com/kumina/libvirt_exporter

package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/khlee2637/libvirt_exporter/libvirt_schema"
	"github.com/libvirt/libvirt-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/alecthomas/kingpin.v2"
)

// QueryCPUsResult holds the structured representative of QMP's "query-cpus" output
type QueryCPUsResult struct {
	Return []QemuThread `json:"return"`
}

// QemuThread holds qemu thread info: which virtual cpu is it, what the thread PID is
type QemuThread struct {
	CPU      int
	ThreadID int `json:"thread_id"`
}

// ReadStealTime reads the file /proc/<thread_id>/schedstat and returns
// the second field as a float64 value
func ReadStealTime(pid int) (float64, error) {
	var retval float64
	path := fmt.Sprintf("/proc/%d/schedstat", pid)
	result, err := ioutil.ReadFile(path)
	if err != nil {
		return 0, err
	}

	values := strings.Split(string(result), " ")
	// We expect exactly 3 fields in the output, otherwise we return error
	if len(values) != 3 {
		return 0, fmt.Errorf("unexpected amount of fields in %s. The file content is \"%s\"", path, result)
	}

	retval, err = strconv.ParseFloat(values[1], 64)
	if err != nil {
		return 0, err
	}

	return retval, nil
}

// CollectDomainStealTime contacts the running QEMU instance via QemuMonitorCommand API call,
// gets the PIDs of the running CPU threads.
// It then calls ReadStealTime for every thread to obtain its steal times
func (e *LibvirtExporter) CollectDomainStealTime(ch chan<- prometheus.Metric, domain *libvirt.Domain) error {
	var totalStealTime float64
	//	var domainLabels string

	xmlDesc, err := domain.GetXMLDesc(0)
	if err != nil {
		return err
	}
	var desc libvirt_schema.Domain
	err = xml.Unmarshal([]byte(xmlDesc), &desc)
	if err != nil {
		return err
	}

	dname, err := domain.GetName()
	if err != nil {
		return err
	}
	var domainUUID = desc.UUID
	var domainLabels []string
	if e.exportNovaMetadata {
		var (
			novaName        = desc.Metadata.NovaInstance.Name
			novaFlavor      = desc.Metadata.NovaInstance.Flavor.Name
			novaProjectName = desc.Metadata.NovaInstance.Owner.ProjectName
		)
		domainLabels = []string{dname, domainUUID, novaName, novaFlavor, novaProjectName}
	} else {
		domainLabels = []string{dname, domainUUID}
	}

	// query QEMU directly to ask PID numbers of its CPU threads
	resultJSON, err := domain.QemuMonitorCommand("{\"execute\": \"query-cpus\"}", libvirt.DOMAIN_QEMU_MONITOR_COMMAND_DEFAULT)
	if err != nil {
		return err
	}
	// Allocate a map for the json parser results
	qemuThreadsResult := QueryCPUsResult{Return: make([]QemuThread, 0, 8)}

	// Parse the result into the map
	err = json.Unmarshal([]byte(resultJSON), &qemuThreadsResult)
	if err != nil {
		return err
	}

	// Now iterate over qemuThreadsResult to get the list of QemuThread
	for _, thread := range qemuThreadsResult.Return {
		stealTime, err := ReadStealTime(thread.ThreadID)
		if err != nil {
			log.Printf("Error fetching steal time for the thread %d: %v. Skipping", thread.ThreadID, err)
			continue
		}
		// Increment the total steal time
		totalStealTime += stealTime

		// Send the metric for this CPU
		ch <- prometheus.MustNewConstMetric(
			e.libvirtDomainInfoCPUStealTimeDesc,
			prometheus.CounterValue,
			stealTime,
			append(domainLabels, fmt.Sprintf("%d", thread.CPU))...)

	}
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainInfoCPUStealTimeDesc,
		prometheus.CounterValue,
		totalStealTime,
		append(domainLabels, "total")...)

	return nil

}

// CollectDomain extracts Prometheus metrics from a libvirt domain.
func (e *LibvirtExporter) CollectDomain(ch chan<- prometheus.Metric, stat libvirt.DomainStats) error {

	// Decode XML description of domain to get block device names, etc.
	xmlDesc, err := stat.Domain.GetXMLDesc(0)
	if err != nil {
		return err
	}
	var desc libvirt_schema.Domain
	err = xml.Unmarshal([]byte(xmlDesc), &desc)
	if err != nil {
		return err
	}

	// Report domain info.
	info, err := stat.Domain.GetInfo()
	if err != nil {
		return err
	}

	domain, err := stat.Domain.GetName()
	if err != nil {
		return err
	}
	var domainUUID = desc.UUID
	var domainLabels []string
	if e.exportNovaMetadata {
		var (
			novaName        = desc.Metadata.NovaInstance.Name
			novaFlavor      = desc.Metadata.NovaInstance.Flavor.Name
			novaProjectName = desc.Metadata.NovaInstance.Owner.ProjectName
		)
		domainLabels = []string{domain, domainUUID, novaName, novaFlavor, novaProjectName}
	} else {
		domainLabels = []string{domain, domainUUID}
	}

	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainInfoMaxMemDesc,
		prometheus.GaugeValue,
		float64(info.MaxMem)*1024,
		domainLabels...)
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainInfoMemoryUsageDesc,
		prometheus.GaugeValue,
		float64(info.Memory)*1024,
		domainLabels...)
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainInfoNrVirtCpuDesc,
		prometheus.GaugeValue,
		float64(info.NrVirtCpu),
		domainLabels...)
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainInfoCpuTimeDesc,
		prometheus.CounterValue,
		float64(info.CpuTime)/1e9,
		domainLabels...)
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainInfoVirDomainState,
		prometheus.CounterValue,
		float64(info.State),
		domainLabels...)

	// Report block device statistics.
	for _, disk := range stat.Block {
		var DiskSource string
		if disk.Name == "hdc" {
			continue
		}
		/*  "block.<num>.path" - string describing the source of block device <num>,
		    if it is a file or block device (omitted for network
		    sources and drives with no media inserted). For network device (i.e. rbd) take from xml. */

		for _, dev := range desc.Devices.Disks {
			if dev.Target.Device == disk.Name {
				if disk.PathSet {
					DiskSource = disk.Path

				} else {
					DiskSource = dev.Source.Name
				}
				break
			}
		}

		// https://libvirt.org/html/libvirt-libvirt-domain.html#virConnectGetAllDomainStats
		if disk.RdBytesSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockRdBytesDesc,
				prometheus.CounterValue,
				float64(disk.RdBytes),
				append(domainLabels, DiskSource, disk.Name)...)
		}
		if disk.RdReqsSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockRdReqDesc,
				prometheus.CounterValue,
				float64(disk.RdReqs),
				append(domainLabels, DiskSource, disk.Name)...)
		}
		if disk.RdBytesSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockRdTotalTimesDesc,
				prometheus.CounterValue,
				float64(disk.RdBytes)/1e9,
				append(domainLabels, DiskSource, disk.Name)...)
		}
		if disk.WrBytesSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockWrBytesDesc,
				prometheus.CounterValue,
				float64(disk.WrBytes),
				append(domainLabels, DiskSource, disk.Name)...)
		}
		if disk.WrReqsSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockWrReqDesc,
				prometheus.CounterValue,
				float64(disk.WrReqs),
				append(domainLabels, DiskSource, disk.Name)...)
		}
		if disk.WrTimesSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockWrTotalTimesDesc,
				prometheus.CounterValue,
				float64(disk.WrTimes)/1e9,
				append(domainLabels, DiskSource, disk.Name)...)
		}
		if disk.FlReqsSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockFlushReqDesc,
				prometheus.CounterValue,
				float64(disk.FlReqs),
				append(domainLabels, DiskSource, disk.Name)...)
		}
		if disk.FlTimesSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockFlushTotalTimesDesc,
				prometheus.CounterValue,
				float64(disk.FlTimes),
				append(domainLabels, DiskSource, disk.Name)...)
		}
		if disk.AllocationSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockAllocationDesc,
				prometheus.CounterValue,
				float64(disk.Allocation),
				append(domainLabels, DiskSource, disk.Name)...)
		}
		if disk.CapacitySet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockCapacityDesc,
				prometheus.CounterValue,
				float64(disk.Capacity),
				append(domainLabels, DiskSource, disk.Name)...)
		}
		if disk.PhysicalSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockPhysicalSizeDesc,
				prometheus.CounterValue,
				float64(disk.Physical),
				append(domainLabels, DiskSource, disk.Name)...)
		}
	}

	// Report network interface statistics.
	for _, iface := range desc.Devices.Interfaces {
		if iface.Target.Device == "" {
			continue
		}
		interfaceStats, err := stat.Domain.InterfaceStats(iface.Target.Device)
		if err != nil {
			return err
		}

		if interfaceStats.RxBytesSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainInterfaceRxBytesDesc,
				prometheus.CounterValue,
				float64(interfaceStats.RxBytes),
				append(domainLabels, iface.Source.Bridge, iface.Target.Device)...)
		}
		if interfaceStats.RxPacketsSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainInterfaceRxPacketsDesc,
				prometheus.CounterValue,
				float64(interfaceStats.RxPackets),
				append(domainLabels, iface.Source.Bridge, iface.Target.Device)...)
		}
		if interfaceStats.RxErrsSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainInterfaceRxErrsDesc,
				prometheus.CounterValue,
				float64(interfaceStats.RxErrs),
				append(domainLabels, iface.Source.Bridge, iface.Target.Device)...)
		}
		if interfaceStats.RxDropSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainInterfaceRxDropDesc,
				prometheus.CounterValue,
				float64(interfaceStats.RxDrop),
				append(domainLabels, iface.Source.Bridge, iface.Target.Device)...)
		}
		if interfaceStats.TxBytesSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainInterfaceTxBytesDesc,
				prometheus.CounterValue,
				float64(interfaceStats.TxBytes),
				append(domainLabels, iface.Source.Bridge, iface.Target.Device)...)
		}
		if interfaceStats.TxPacketsSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainInterfaceTxPacketsDesc,
				prometheus.CounterValue,
				float64(interfaceStats.TxPackets),
				append(domainLabels, iface.Source.Bridge, iface.Target.Device)...)
		}
		if interfaceStats.TxErrsSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainInterfaceTxErrsDesc,
				prometheus.CounterValue,
				float64(interfaceStats.TxErrs),
				append(domainLabels, iface.Source.Bridge, iface.Target.Device)...)
		}
		if interfaceStats.TxDropSet {
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainInterfaceTxDropDesc,
				prometheus.CounterValue,
				float64(interfaceStats.TxDrop),
				append(domainLabels, iface.Source.Bridge, iface.Target.Device)...)
		}

	}

	// Collect Memory Stats
	memorystat, err := stat.Domain.MemoryStats(11, 0)
	var MemoryStats libvirt_schema.VirDomainMemoryStats
	var used_percent float64
	if err == nil {
		MemoryStats = MemoryStatCollect(&memorystat)
		if MemoryStats.Usable != 0 && MemoryStats.Available != 0 {
			used_percent = (float64(MemoryStats.Available) - float64(MemoryStats.Usable)) / (float64(MemoryStats.Available) / float64(100))
		}

	}
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainMemoryStatMajorfaultDesc,
		prometheus.CounterValue,
		float64(MemoryStats.Major_fault),
		domainLabels...)
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainMemoryStatMinorFaultDesc,
		prometheus.CounterValue,
		float64(MemoryStats.Minor_fault),
		domainLabels...)
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainMemoryStatUnusedDesc,
		prometheus.CounterValue,
		float64(MemoryStats.Unused),
		domainLabels...)
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainMemoryStatAvailableDesc,
		prometheus.CounterValue,
		float64(MemoryStats.Available),
		domainLabels...)
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainMemoryStatActualBaloonDesc,
		prometheus.CounterValue,
		float64(MemoryStats.Actual_balloon),
		domainLabels...)
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainMemoryStatRssDesc,
		prometheus.CounterValue,
		float64(MemoryStats.Rss),
		domainLabels...)
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainMemoryStatUsableDesc,
		prometheus.CounterValue,
		float64(MemoryStats.Usable),
		domainLabels...)
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainMemoryStatDiskCachesDesc,
		prometheus.CounterValue,
		float64(MemoryStats.Disk_caches),
		domainLabels...)
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainMemoryStatUsedPercentDesc,
		prometheus.CounterValue,
		float64(used_percent),
		domainLabels...)

	return nil
}

func MemoryStatCollect(memorystat *[]libvirt.DomainMemoryStat) libvirt_schema.VirDomainMemoryStats {
	var MemoryStats libvirt_schema.VirDomainMemoryStats
	for _, domainmemorystat := range *memorystat {
		switch tag := domainmemorystat.Tag; tag {
		case 2:
			MemoryStats.Major_fault = domainmemorystat.Val
		case 3:
			MemoryStats.Minor_fault = domainmemorystat.Val
		case 4:
			MemoryStats.Unused = domainmemorystat.Val
		case 5:
			MemoryStats.Available = domainmemorystat.Val
		case 6:
			MemoryStats.Actual_balloon = domainmemorystat.Val
		case 7:
			MemoryStats.Rss = domainmemorystat.Val
		case 8:
			MemoryStats.Usable = domainmemorystat.Val
		case 10:
			MemoryStats.Disk_caches = domainmemorystat.Val
		}
	}
	return MemoryStats
}

// LibvirtExporter implements a Prometheus exporter for libvirt state.
type LibvirtExporter struct {
	uri                string
	login              string
	password           string
	conn               *libvirt.Connect
	exportNovaMetadata bool

	libvirtUpDesc *prometheus.Desc
	//libvirtDomainsNumberDesc *prometheus.Desc

	libvirtDomainInfoVirDomainState *prometheus.Desc
	//libvirtDomainStateCode           *prometheus.Desc
	libvirtDomainInfoMaxMemDesc *prometheus.Desc
	//libvirtDomainInfoMemoryDesc      *prometheus.Desc
	libvirtDomainInfoMemoryUsageDesc *prometheus.Desc
	libvirtDomainInfoNrVirtCpuDesc   *prometheus.Desc
	libvirtDomainInfoCpuTimeDesc     *prometheus.Desc

	libvirtDomainBlockCapacityDesc        *prometheus.Desc
	libvirtDomainBlockAllocationDesc      *prometheus.Desc
	libvirtDomainBlockRdBytesDesc         *prometheus.Desc
	libvirtDomainBlockRdReqDesc           *prometheus.Desc
	libvirtDomainBlockRdTotalTimesDesc    *prometheus.Desc
	libvirtDomainBlockWrBytesDesc         *prometheus.Desc
	libvirtDomainBlockWrReqDesc           *prometheus.Desc
	libvirtDomainBlockWrTotalTimesDesc    *prometheus.Desc
	libvirtDomainBlockFlushReqDesc        *prometheus.Desc
	libvirtDomainBlockFlushTotalTimesDesc *prometheus.Desc
	libvirtDomainBlockPhysicalSizeDesc    *prometheus.Desc

	libvirtDomainMemoryStatActualBaloonDesc *prometheus.Desc
	libvirtDomainMemoryStatAvailableDesc    *prometheus.Desc
	libvirtDomainMemoryStatDiskCachesDesc   *prometheus.Desc
	libvirtDomainMemoryStatMajorfaultDesc   *prometheus.Desc
	libvirtDomainMemoryStatMinorFaultDesc   *prometheus.Desc
	libvirtDomainMemoryStatRssDesc          *prometheus.Desc
	libvirtDomainMemoryStatUnusedDesc       *prometheus.Desc
	libvirtDomainMemoryStatUsableDesc       *prometheus.Desc
	libvirtDomainMemoryStatUsedPercentDesc  *prometheus.Desc

	libvirtDomainInterfaceRxBytesDesc   *prometheus.Desc
	libvirtDomainInterfaceRxPacketsDesc *prometheus.Desc
	libvirtDomainInterfaceRxErrsDesc    *prometheus.Desc
	libvirtDomainInterfaceRxDropDesc    *prometheus.Desc
	libvirtDomainInterfaceTxBytesDesc   *prometheus.Desc
	libvirtDomainInterfaceTxPacketsDesc *prometheus.Desc
	libvirtDomainInterfaceTxErrsDesc    *prometheus.Desc
	libvirtDomainInterfaceTxDropDesc    *prometheus.Desc
	libvirtDomainInfoCPUStealTimeDesc   *prometheus.Desc
}

// NewLibvirtExporter creates a new Prometheus exporter for libvirt.
func NewLibvirtExporter(uri string, login string, password string, exportNovaMetadata bool) (*LibvirtExporter, error) {
	var domainLabels []string
	if exportNovaMetadata {
		domainLabels = []string{"domain", "uuid", "name", "flavor", "project_name"}
	} else {
		domainLabels = []string{"domain", "uuid"}
	}
	return &LibvirtExporter{
		uri:                uri,
		login:              login,
		password:           password,
		exportNovaMetadata: exportNovaMetadata,
		libvirtUpDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "", "up"),
			"Whether scraping libvirt's metrics was successful.",
			nil,
			nil),
		libvirtDomainInfoMaxMemDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_info", "maximum_memory_bytes"),
			"Maximum allowed memory of the domain, in bytes.",
			domainLabels,
			nil),
		libvirtDomainInfoMemoryUsageDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_info", "memory_usage_bytes"),
			"Memory usage of the domain, in bytes.",
			domainLabels,
			nil),
		libvirtDomainInfoNrVirtCpuDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_info", "virtual_cpus"),
			"Number of virtual CPUs for the domain.",
			domainLabels,
			nil),
		libvirtDomainInfoCpuTimeDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_info", "cpu_time_seconds_total"),
			"Amount of CPU time used by the domain, in seconds.",
			domainLabels,
			nil),
		libvirtDomainInfoVirDomainState: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_info", "vstate"),
			"Virtual domain state. 0: no state, 1: the domain is running, 2: the domain is blocked on resource,"+
				" 3: the domain is paused by user, 4: the domain is being shut down, 5: the domain is shut off,"+
				"6: the domain is crashed, 7: the domain is suspended by guest power management",
			domainLabels,
			nil),
		libvirtDomainBlockRdBytesDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "read_bytes_total"),
			"Number of bytes read from a block device, in bytes.",
			append(domainLabels, "source_file", "target_device"),
			nil),
		libvirtDomainBlockRdReqDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "read_requests_total"),
			"Number of read requests from a block device.",
			append(domainLabels, "source_file", "target_device"),
			nil),
		libvirtDomainBlockRdTotalTimesDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "read_time_total"),
			"Total time (ns) spent on reads from a block device, in ns, that is, 1/1,000,000,000 of a second, or 10−9 seconds.",
			append(domainLabels, "source_file", "target_device"),
			nil),
		libvirtDomainBlockWrBytesDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "write_bytes_total"),
			"Number of bytes written to a block device, in bytes.",
			append(domainLabels, "source_file", "target_device"),
			nil),
		libvirtDomainBlockWrReqDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "write_requests_total"),
			"Number of write requests to a block device.",
			append(domainLabels, "source_file", "target_device"),
			nil),
		libvirtDomainBlockWrTotalTimesDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "write_time_total"),
			"Total time (ns) spent on writes on a block device, in ns, that is, 1/1,000,000,000 of a second, or 10−9 seconds.",
			append(domainLabels, "source_file", "target_device"),
			nil),
		libvirtDomainBlockFlushReqDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "flush_requests_total"),
			"Total flush requests from a block device.",
			append(domainLabels, "source_file", "target_device"),
			nil),
		libvirtDomainBlockFlushTotalTimesDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "flush_total"),
			"Total time (ns) spent on cache flushing to a block device, in ns, that is, 1/1,000,000,000 of a second, or 10−9 seconds.",
			append(domainLabels, "source_file", "target_device"),
			nil),
		libvirtDomainBlockAllocationDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "allocation"),
			"Offset of the highest written sector on a block device.",
			append(domainLabels, "source_file", "target_device"),
			nil),
		libvirtDomainBlockCapacityDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "capacity"),
			"Logical size in bytes of the block device		backing image.",
			append(domainLabels, "source_file", "target_device"),
			nil),
		libvirtDomainBlockPhysicalSizeDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "physicalsize"),
			"Physical size in bytes of the container of the backing image.",
			append(domainLabels, "source_file", "target_device"),
			nil),
		libvirtDomainInterfaceRxBytesDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_interface_stats", "receive_bytes_total"),
			"Number of bytes received on a network interface, in bytes.",
			append(domainLabels, "source_bridge", "target_device"),
			nil),
		libvirtDomainInterfaceRxPacketsDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_interface_stats", "receive_packets_total"),
			"Number of packets received on a network interface.",
			append(domainLabels, "source_bridge", "target_device"),
			nil),
		libvirtDomainInterfaceRxErrsDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_interface_stats", "receive_errors_total"),
			"Number of packet receive errors on a network interface.",
			append(domainLabels, "source_bridge", "target_device"),
			nil),
		libvirtDomainInterfaceRxDropDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_interface_stats", "receive_drops_total"),
			"Number of packet receive drops on a network interface.",
			append(domainLabels, "source_bridge", "target_device"),
			nil),
		libvirtDomainInterfaceTxBytesDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_interface_stats", "transmit_bytes_total"),
			"Number of bytes transmitted on a network interface, in bytes.",
			append(domainLabels, "source_bridge", "target_device"),
			nil),
		libvirtDomainInterfaceTxPacketsDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_interface_stats", "transmit_packets_total"),
			"Number of packets transmitted on a network interface.",
			append(domainLabels, "source_bridge", "target_device"),
			nil),
		libvirtDomainInterfaceTxErrsDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_interface_stats", "transmit_errors_total"),
			"Number of packet transmit errors on a network interface.",
			append(domainLabels, "source_bridge", "target_device"),
			nil),
		libvirtDomainInterfaceTxDropDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_interface_stats", "transmit_drops_total"),
			"Number of packet transmit drops on a network interface.",
			append(domainLabels, "source_bridge", "target_device"),
			nil),
		libvirtDomainMemoryStatMajorfaultDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_memory_stats", "major_fault"),
			"Page faults occur when a process makes a valid access to virtual memory that is not available. "+
				"When servicing the page fault, if disk IO is required, it is considered a major fault.",
			domainLabels,
			nil),
		libvirtDomainMemoryStatMinorFaultDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_memory_stats", "minor_fault"),
			"Page faults occur when a process makes a valid access to virtual memory that is not available. "+
				"When servicing the page not fault, if disk IO is required, it is considered a minor fault.",
			domainLabels,
			nil),
		libvirtDomainMemoryStatUnusedDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_memory_stats", "unused"),
			"The amount of memory left completely unused by the system. Memory that is available but used for "+
				"reclaimable caches should NOT be reported as free. This value is expressed in kB.",
			domainLabels,
			nil),
		libvirtDomainMemoryStatAvailableDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_memory_stats", "available"),
			"The total amount of usable memory as seen by the domain. This value may be less than the amount of "+
				"memory assigned to the domain if a balloon driver is in use or if the guest OS does not initialize all "+
				"assigned pages. This value is expressed in kB.",
			domainLabels,
			nil),
		libvirtDomainMemoryStatActualBaloonDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_memory_stats", "actual_balloon"),
			"Current balloon value (in KB).",
			domainLabels,
			nil),
		libvirtDomainMemoryStatRssDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_memory_stats", "rss"),
			"Resident Set Size of the process running the domain. This value is in kB",
			domainLabels,
			nil),
		libvirtDomainMemoryStatUsableDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_memory_stats", "usable"),
			"How much the balloon can be inflated without pushing the guest system to swap, corresponds "+
				"to 'Available' in /proc/meminfo",
			domainLabels,
			nil),
		libvirtDomainMemoryStatDiskCachesDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_memory_stats", "disk_cache"),
			"The amount of memory, that can be quickly reclaimed without additional I/O (in kB)."+
				"Typically these pages are used for caching files from disk.",
			domainLabels,
			nil),
		libvirtDomainMemoryStatUsedPercentDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_memory_stats", "used_percent"),
			"The amount of memory in percent, that used by domain.",
			domainLabels,
			nil),
		libvirtDomainInfoCPUStealTimeDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_info", "cpu_steal_time_total"),
			"Amount of CPU time stolen from the domain, in ns, that is, 1/1,000,000,000 of a second, or 10−9 seconds.",
			append(domainLabels, "cpu"),
			nil),
	}, nil
}

// Describe returns metadata for all Prometheus metrics that may be exported.
func (e *LibvirtExporter) Describe(ch chan<- *prometheus.Desc) {
	// Status
	ch <- e.libvirtUpDesc

	// Domain info
	ch <- e.libvirtDomainInfoMaxMemDesc
	ch <- e.libvirtDomainInfoMemoryUsageDesc
	ch <- e.libvirtDomainInfoNrVirtCpuDesc
	ch <- e.libvirtDomainInfoCpuTimeDesc
	ch <- e.libvirtDomainInfoCPUStealTimeDesc
	ch <- e.libvirtDomainInfoVirDomainState

	// Domain block stats
	ch <- e.libvirtDomainBlockRdBytesDesc
	ch <- e.libvirtDomainBlockRdReqDesc
	ch <- e.libvirtDomainBlockRdTotalTimesDesc
	ch <- e.libvirtDomainBlockWrBytesDesc
	ch <- e.libvirtDomainBlockWrReqDesc
	ch <- e.libvirtDomainBlockWrTotalTimesDesc
	ch <- e.libvirtDomainBlockFlushReqDesc
	ch <- e.libvirtDomainBlockFlushTotalTimesDesc
	ch <- e.libvirtDomainBlockAllocationDesc
	ch <- e.libvirtDomainBlockCapacityDesc
	ch <- e.libvirtDomainBlockPhysicalSizeDesc

	// Domain net interfaces stats
	ch <- e.libvirtDomainInterfaceRxBytesDesc
	ch <- e.libvirtDomainInterfaceRxPacketsDesc
	ch <- e.libvirtDomainInterfaceRxErrsDesc
	ch <- e.libvirtDomainInterfaceRxDropDesc
	ch <- e.libvirtDomainInterfaceTxBytesDesc
	ch <- e.libvirtDomainInterfaceTxPacketsDesc
	ch <- e.libvirtDomainInterfaceTxErrsDesc
	ch <- e.libvirtDomainInterfaceTxDropDesc

	// Domain memory stats
	ch <- e.libvirtDomainMemoryStatMajorfaultDesc
	ch <- e.libvirtDomainMemoryStatMinorFaultDesc
	ch <- e.libvirtDomainMemoryStatUnusedDesc
	ch <- e.libvirtDomainMemoryStatAvailableDesc
	ch <- e.libvirtDomainMemoryStatActualBaloonDesc
	ch <- e.libvirtDomainMemoryStatRssDesc
	ch <- e.libvirtDomainMemoryStatUsableDesc
	ch <- e.libvirtDomainMemoryStatDiskCachesDesc
}

// Collect scrapes Prometheus metrics from libvirt.
func (e *LibvirtExporter) Collect(ch chan<- prometheus.Metric) {
	err := e.CollectFromLibvirt(ch)
	if err == nil {
		ch <- prometheus.MustNewConstMetric(
			e.libvirtUpDesc,
			prometheus.GaugeValue,
			1.0)
	} else {
		log.Printf("Failed to scrape metrics: %s", err)
		ch <- prometheus.MustNewConstMetric(
			e.libvirtUpDesc,
			prometheus.GaugeValue,
			0.0)
	}
}

func (e *LibvirtExporter) connectLibvirtWithAuth(uri string) (*libvirt.Connect, error) {
	if e.login == "" || e.password == "" {
		return nil, fmt.Errorf("empty username or password was provided. Not attempting to authenticate using SASL")
	}

	callback := func(creds []*libvirt.ConnectCredential) {
		for _, cred := range creds {
			switch cred.Type {
			case libvirt.CRED_AUTHNAME:
				cred.Result = e.login
				cred.ResultLen = len(cred.Result)

			case libvirt.CRED_PASSPHRASE:
				cred.Result = e.password
				cred.ResultLen = len(cred.Result)

			}
		}
	}

	auth := &libvirt.ConnectAuth{
		CredType: []libvirt.ConnectCredentialType{
			libvirt.CRED_AUTHNAME, libvirt.CRED_PASSPHRASE,
		},
		Callback: callback,
	}

	return libvirt.NewConnectWithAuth(uri, auth, 0) // connect flag 0 means "read-write"
}

func (e *LibvirtExporter) Connect() (isReadonly bool, err error) {
	// First, try to connect without authentication, and with the full access
	if e.conn, err = libvirt.NewConnect(e.uri); err == nil {
		return
	}

	// Then, if the connection has failed, we try accessing libvirt with the authentication
	if e.conn, err = e.connectLibvirtWithAuth(e.uri); err == nil {
		return
	}

	// Then, if the authenticated connection failed we attempt to connect using readonly
	if e.conn, err = libvirt.NewConnectReadOnly(e.uri); err == nil {
		isReadonly = true
		return
	}

	return
}

func (e *LibvirtExporter) Close() {
	e.conn.Close()
}

// CollectFromLibvirt obtains Prometheus metrics from all domains in a
// libvirt setup.
func (e *LibvirtExporter) CollectFromLibvirt(ch chan<- prometheus.Metric) error {
	readOnly, err := e.Connect()
	if err != nil {
		return err
	}
	defer e.Close()

	stats, err := e.conn.GetAllDomainStats([]*libvirt.Domain{}, libvirt.DOMAIN_STATS_STATE|libvirt.DOMAIN_STATS_CPU_TOTAL|
		libvirt.DOMAIN_STATS_INTERFACE|libvirt.DOMAIN_STATS_BALLOON|libvirt.DOMAIN_STATS_BLOCK|
		libvirt.DOMAIN_STATS_PERF|libvirt.DOMAIN_STATS_VCPU, 0)
	if err != nil {
		return err
	}
	for _, stat := range stats {
		err = e.CollectDomain(ch, stat)
		if err != nil {
			log.Println(err)
			stat.Domain.Free()
			continue
		}
		if !readOnly {
			err = e.CollectDomainStealTime(ch, stat.Domain)
			if err != nil {
				log.Println(err)
				stat.Domain.Free()
				continue
			}
		}
		stat.Domain.Free()
	}
	return nil
}

func main() {
	var (
		app                       = kingpin.New("libvirt_exporter", "Prometheus metrics exporter for libvirt")
		listenAddress             = app.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9177").String()
		metricsPath               = app.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		libvirtURI                = app.Flag("libvirt.uri", "Libvirt URI from which to extract metrics.").Default("qemu:///system").String()
		libvirtUsername           = app.Flag("libvirt.auth.username", "User name for SASL login (you can also use LIBVIRT_EXPORTER_USERNAME environment variable)").Default("").Envar("LIBVIRT_EXPORTER_USERNAME").String()
		libvirtPassword           = app.Flag("libvirt.auth.password", "Password for SASL login (you can also use LIBVIRT_EXPORTER_PASSWORD environment variable)").Default("").Envar("LIBVIRT_EXPORTER_PASSWORD").String()
		libvirtExportNovaMetadata = app.Flag("libvirt.export-nova-metadata", "Export OpenStack Nova specific labels from libvirt domain xml").Default("false").Bool()
	)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	exporter, err := NewLibvirtExporter(*libvirtURI, *libvirtUsername, *libvirtPassword, *libvirtExportNovaMetadata)
	if err != nil {
		panic(err)
	}
	prometheus.MustRegister(exporter)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`
			<html>
			<head><title>Libvirt Exporter</title></head>
			<body>
			<h1>Libvirt Exporter</h1>
			<p><a href='` + *metricsPath + `'>Metrics</a></p>
			</body>
			</html>`))
	})
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
