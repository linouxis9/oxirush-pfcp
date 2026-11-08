// OxiRush
// Copyright 2026 Valentin D'Emmanuele
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0. Unless required by applicable law or agreed
// to in writing, software distributed under the License is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under the
// License.

// The workloads of `measure` of the benches, with go-pfcp:
//
//	go-pfcp WORKLOAD ROUNDS HEX
//
// WORKLOAD is `decode`, the message parsed as go-pfcp parses it, with its IEs as
// octets until a value is asked; `read`, the message parsed and the same values read as
// `read()` of the benches reads them; or `encode`, the parsed message written again. It
// runs the workload ROUNDS times, and prints the time of a round, which is a note, with
// the allocations that the runtime counts for one.
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

var sink uint64

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "go-pfcp WORKLOAD ROUNDS HEX")
		os.Exit(2)
	}
	rounds, _ := strconv.Atoi(os.Args[2])
	octets, _ := hex.DecodeString(os.Args[3])
	parsed, err := message.Parse(octets)
	if err != nil {
		fmt.Fprintln(os.Stderr, "go-pfcp does not parse the message:", err)
		os.Exit(1)
	}
	call := func() {
		if _, err := message.Parse(octets); err != nil {
			panic(err)
		}
	}
	switch os.Args[1] {
	case "read":
		call = func() {
			m, err := message.Parse(octets)
			if err != nil {
				panic(err)
			}
			sink += read(m)
		}
	case "encode":
		call = func() {
			out := make([]byte, parsed.MarshalLen())
			if err := parsed.MarshalTo(out); err != nil {
				panic(err)
			}
			sink += uint64(len(out))
		}
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	call()
	runtime.ReadMemStats(&after)
	started := time.Now()
	for i := 0; i < rounds; i++ {
		call()
	}
	elapsed := time.Since(started)
	fmt.Fprintf(os.Stderr, "%s: %.0f ns a round (a note), %d allocations\n", os.Args[1], float64(elapsed.Nanoseconds())/float64(max(rounds, 1)), after.Mallocs-before.Mallocs)
	fmt.Println(sink)
}

// octets as `read()` takes them: their length and their first octet.
func octets(text string) uint64 {
	if len(text) == 0 {
		return 0
	}
	return uint64(len(text)) + uint64(text[0])
}

// The values that `read()` of the benches reads, through the accessors of go-pfcp: a
// grouped IE's IEs once, then each value.
func read(m message.Message) uint64 {
	request, ok := m.(*message.SessionEstablishmentRequest)
	sum := uint64(m.Sequence())
	if !ok {
		return sum
	}
	if request.NodeID != nil {
		node, _ := request.NodeID.NodeID()
		sum += octets(node)
	}
	if request.CPFSEID != nil {
		fseid, _ := request.CPFSEID.FSEID()
		if fseid != nil {
			sum += fseid.SEID + uint64(len(fseid.IPv4Address))
		}
	}
	for _, pdr := range request.CreatePDR {
		ies, _ := pdr.CreatePDR()
		for _, x := range ies {
			switch x.Type {
			case ie.PDRID:
				id, _ := x.PDRID()
				sum += uint64(id)
			case ie.Precedence:
				p, _ := x.Precedence()
				sum += uint64(p)
			case ie.FARID:
				id, _ := x.FARID()
				sum += uint64(id)
			case ie.URRID:
				id, _ := x.URRID()
				sum += uint64(id)
			case ie.QERID:
				id, _ := x.QERID()
				sum += uint64(id)
			case ie.OuterHeaderRemoval:
				d, _ := x.OuterHeaderRemovalDescription()
				sum += uint64(d)
			case ie.PDI:
				pdi, _ := x.PDI()
				for _, y := range pdi {
					switch y.Type {
					case ie.SourceInterface:
						s, _ := y.SourceInterface()
						sum += uint64(s)
					case ie.FTEID:
						f, _ := y.FTEID()
						if f != nil {
							sum += uint64(f.TEID) + uint64(f.Flags&4>>2) + uint64(len(f.IPv4Address))
						}
					case ie.NetworkInstance:
						n, _ := y.NetworkInstance()
						sum += octets(n)
					case ie.UEIPAddress:
						u, _ := y.UEIPAddress()
						if u != nil {
							sum += uint64(len(u.IPv4Address))
						}
					case ie.SDFFilter:
						s, _ := y.SDFFilter()
						if s != nil {
							sum += octets(s.FlowDescription)
						}
					case ie.QFI:
						q, _ := y.QFI()
						sum += uint64(q)
					}
				}
			}
		}
	}
	for _, far := range request.CreateFAR {
		ies, _ := far.CreateFAR()
		for _, x := range ies {
			switch x.Type {
			case ie.FARID:
				id, _ := x.FARID()
				sum += uint64(id)
			case ie.ApplyAction:
				a, _ := x.ApplyAction()
				if len(a) > 0 {
					sum += uint64(a[0]>>1&1) + uint64(a[0]>>2&1)
				}
			case ie.ForwardingParameters:
				fp, _ := x.ForwardingParameters()
				for _, y := range fp {
					switch y.Type {
					case ie.DestinationInterface:
						d, _ := y.DestinationInterface()
						sum += uint64(d)
					case ie.NetworkInstance:
						n, _ := y.NetworkInstance()
						sum += octets(n)
					case ie.OuterHeaderCreation:
						o, _ := y.OuterHeaderCreation()
						if o != nil {
							sum += uint64(o.TEID) + uint64(len(o.IPv4Address))
						}
					}
				}
			}
		}
	}
	for _, urr := range request.CreateURR {
		ies, _ := urr.CreateURR()
		for _, x := range ies {
			switch x.Type {
			case ie.URRID:
				id, _ := x.URRID()
				sum += uint64(id)
			case ie.MeasurementMethod:
				m, _ := x.MeasurementMethod()
				sum += uint64(m >> 1 & 1)
			case ie.ReportingTriggers:
				r, _ := x.ReportingTriggers()
				if len(r) > 0 {
					sum += uint64(r[0] >> 1 & 1)
				}
			case ie.VolumeThreshold:
				v, _ := x.VolumeThreshold()
				if v != nil {
					sum += v.TotalVolume
				}
			case ie.TimeThreshold:
				t, _ := x.TimeThreshold()
				sum += uint64(t / time.Second)
			}
		}
	}
	for _, qer := range request.CreateQER {
		ies, _ := qer.CreateQER()
		for _, x := range ies {
			switch x.Type {
			case ie.QERID:
				id, _ := x.QERID()
				sum += uint64(id)
			case ie.GateStatus:
				g, _ := x.GateStatus()
				sum += uint64(g >> 2)
			case ie.MBR:
				m, _ := x.MBR()
				sum += uint64(len(m))
			case ie.QFI:
				q, _ := x.QFI()
				sum += uint64(q)
			}
		}
	}
	if request.PDNType != nil {
		p, _ := request.PDNType.PDNType()
		sum += uint64(p)
	}
	if request.APNDNN != nil {
		a, _ := request.APNDNN.APNDNN()
		sum += octets(a)
	}
	if request.SNSSAI != nil {
		s, _ := request.SNSSAI.SNSSAI()
		sum += uint64(len(s))
	}
	if request.UserID != nil {
		u, _ := request.UserID.UserID()
		if u != nil {
			sum += octets(u.IMSI)
		}
	}
	return sum
}
