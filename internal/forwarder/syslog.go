package forwarder

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

type SyslogForwarder struct{}

func NewSyslogForwarder() *SyslogForwarder {
	return &SyslogForwarder{}
}

func (f *SyslogForwarder) Send(host string, port int, protocol string, evt event.Event) error {
	if host == "" {
		return fmt.Errorf("syslog host is empty")
	}
	if port <= 0 {
		port = 514
	}
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		protocol = "udp"
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout(protocol, addr, 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	b, err := json.Marshal(evt.ToMap())
	if err != nil {
		return err
	}
	line := fmt.Sprintf("<134>1 %s dmz-collector dmz_collector - - - %s\n", time.Now().UTC().Format(time.RFC3339), string(b))
	_, err = conn.Write([]byte(line))
	return err
}

