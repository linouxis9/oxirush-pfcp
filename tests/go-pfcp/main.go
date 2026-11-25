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

// What go-pfcp reads of each message of a corpus:
//
//	go-pfcp < CORPUS.tsv > READINGS.jsonl
//
// CORPUS.tsv has a message a line, its name and its octets in hexadecimal. Each line of
// READINGS.jsonl is a message as go-pfcp reads it: whether message.Parse accepts it, and
// its IEs as ie.Parse frames them one after the other, at every level of the grouped IEs:
// the type, the Length and the Enterprise ID of each, whether the accessor of its type
// reads its value, and where the IEs of a level stop framing. A panic of go-pfcp is a
// refusal, with its text.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// A message: Parse is empty where message.Parse accepts it, and its error otherwise.
type reading struct {
	Name  string      `json:"name"`
	Parse string      `json:"parse"`
	IEs   []ieReading `json:"ies"`
	// The error of the IE where the IEs of the message stop framing.
	Fault string `json:"fault,omitempty"`
}

// An IE. Value is null for a type whose value go-pfcp has no accessor for, empty where the
// accessor reads it, and its error otherwise. Grouped is whether go-pfcp reads IEs in it.
type ieReading struct {
	Type         uint16      `json:"type"`
	Length       uint16      `json:"length"`
	EnterpriseID *uint16     `json:"enterprise_id,omitempty"`
	Grouped      bool        `json:"grouped"`
	Value        *string     `json:"value"`
	IEs          []ieReading `json:"ies,omitempty"`
	Fault        string      `json:"fault,omitempty"`
}

// The error of `call`, or the text of its panic.
func guarded(call func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return call()
}

// The IEs of `b` as ie.ParseMultiIEs frames them, and the error where it stops: an IE is
// parsed, and the next one begins after its MarshalLen. A grouped IE whose own octets
// frame and whose IEs do not is kept with the fault of its IEs, where go-pfcp stops.
func walk(b []byte) ([]ieReading, string) {
	var out []ieReading
	for len(b) > 0 {
		var i *ie.IE
		err := guarded(func() error {
			var err error
			i, err = ie.Parse(b)
			return err
		})
		if err != nil {
			if grouped := shallow(b); grouped != nil {
				grouped.IEs, grouped.Fault = walk(grouped.payload)
				out = append(out, grouped.ieReading)
			}
			return out, err.Error()
		}
		out = append(out, read(i))
		b = b[i.MarshalLen():]
	}
	return out, ""
}

type shallowIE struct {
	ieReading
	payload []byte
}

// A grouped IE whose Type, Length and Enterprise ID frame its content in `b`, as
// ie.UnmarshalBinary reads them, without its IEs; nil for any other.
func shallow(b []byte) *shallowIE {
	if len(b) < 4 {
		return nil
	}
	i := &ie.IE{Type: binary.BigEndian.Uint16(b[0:2]), Length: binary.BigEndian.Uint16(b[2:4])}
	if !i.IsGrouped() {
		return nil
	}
	offset, end := 4, int(i.Length)
	found := shallowIE{ieReading: ieReading{Type: i.Type, Length: i.Length, Grouped: true}}
	if i.IsVendorSpecific() {
		if len(b) < 6 || end < 2 {
			return nil
		}
		id := binary.BigEndian.Uint16(b[4:6])
		found.EnterpriseID = &id
		offset, end = 6, end-2
	}
	if len(b) < offset+end {
		return nil
	}
	found.payload = b[offset : offset+end]
	return &found
}

// An IE that ie.Parse gave, with its value as its accessor reads it, and its IEs.
func read(i *ie.IE) ieReading {
	found := ieReading{Type: i.Type, Length: i.Length, Grouped: i.IsGrouped()}
	if i.IsVendorSpecific() {
		id := i.EnterpriseID
		found.EnterpriseID = &id
	}
	if accessor, ok := accessors[i.Type]; ok {
		text := ""
		if err := guarded(func() error { return accessor(i) }); err != nil {
			text = err.Error()
		}
		found.Value = &text
	}
	for _, child := range i.ChildIEs {
		found.IEs = append(found.IEs, read(child))
	}
	return found
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		name, text, ok := strings.Cut(in.Text(), "\t")
		if !ok {
			continue
		}
		octets, err := hex.DecodeString(text)
		if err != nil {
			fmt.Fprintln(os.Stderr, name, "is no hexadecimal:", err)
			os.Exit(2)
		}
		found := reading{Name: name}
		if err := guarded(func() error { _, err := message.Parse(octets); return err }); err != nil {
			found.Parse = err.Error()
		}
		var header *message.Header
		if err := guarded(func() error { var err error; header, err = message.ParseHeader(octets); return err }); err != nil {
			found.Fault = err.Error()
		} else {
			found.IEs, found.Fault = walk(header.Payload)
		}
		if err := out.Encode(found); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	if err := in.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
