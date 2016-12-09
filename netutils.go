package netutils

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var r_hostname *regexp.Regexp = regexp.MustCompile("(?i)^[a-z0-9_][a-z0-9_-]*$")

type AddressInfo struct {
	Host    string
	Netmask int
	Port    int
}

func (ai *AddressInfo) HasPort() bool {
	return ai.Port > 1
}
func (ai *AddressInfo) HasNetmask() bool {
	return ai.Netmask >= 0
}
func (ai *AddressInfo) HasHost() bool {
	return ai.Host != ""
}
func (ai *AddressInfo) IsInterface() bool {
	return ai.HasHost() && ai.HasPort() && !ai.HasNetmask()
}
func (ai *AddressInfo) IsNetwork() bool {
	return ai.HasHost() && ai.HasNetmask() && !ai.HasPort()
}
func (ai *AddressInfo) HostPort() (result string) {
	if ai.HasHost() && ai.HasPort() {
		result = fmt.Sprintf("%s:%d", ai.Host, ai.Port)
	}
	return
}
func (ai *AddressInfo) Resolve() (*ResolvedAddressInfo, error) {
	var rai ResolvedAddressInfo

	if ai.HasHost() {
		if ip := net.ParseIP(ai.Host); ip != nil {
			rai.IP = ip
		} else {
			if addrs, err := net.LookupHost(ai.Host); (err != nil) || (len(addrs) == 0) {
				return nil, errors.New("Error resolving host: " + ai.Host)
			} else {
				rai.IP = net.ParseIP(addrs[0])
			}
		}
	}

	rai.Netmask = ai.Netmask
	rai.Port = ai.Port

	return &rai, nil
}

type ResolvedAddressInfo struct {
	Host    string
	IP      net.IP
	Netmask int
	Port    int
}

func (ai *ResolvedAddressInfo) HasPort() bool {
	return ai.Port >= 1
}
func (ai *ResolvedAddressInfo) HasNetmask() bool {
	return ai.Netmask >= 0
}
func (ai *ResolvedAddressInfo) HasHost() bool {
	return ai.Host != ""
}
func (ai *ResolvedAddressInfo) HasIP() bool {
	return ai.IP != nil
}
func (ai *ResolvedAddressInfo) IsInterface() bool {
	return ai.HasIP() && ai.HasPort() && !ai.HasNetmask()
}
func (ai *ResolvedAddressInfo) IsNetwork() bool {
	return ai.HasIP() && ai.HasNetmask() && !ai.HasPort()
}
func (ai *ResolvedAddressInfo) HostPort() (result string) {
	if ai.HasIP() && ai.HasPort() {
		result = fmt.Sprintf("%s:%d", ai.IP.String(), ai.Port)
	}
	return
}
func (ai *ResolvedAddressInfo) Network() (result string) {
	if ai.HasIP() && ai.HasNetmask() {
		result = fmt.Sprintf("%s/%d", ai.IP.String(), ai.Netmask)
	}
	return
}

func IsValidHostname(h string) bool {
	return r_hostname.MatchString(h) && !strings.HasSuffix(h, "-")
}

func IsValidFQDN(fqdn string) bool {
	if fqdn == "" {
		return false
	}
	for _, h := range strings.Split(fqdn, ".") {
		if !IsValidHostname(h) {
			return false
		}
	}
	return true
}

func ResolvePort(port string) (int, error) {
	port = strings.TrimSpace(port)
	if port == "" {
		return 0, errors.New("Empty port")
	}
	nport, err := net.LookupPort("tcp", port)
	if err != nil {
		nport, err = net.LookupPort("udp", port)
	}
	if err != nil {
		return 0, err
	}
	return nport, nil
}

func Netmask2CIDR(netmask string) (int, error) {

	switch netmask {
	case "255.255.255.255":
		return 32, nil
	case "255.255.255.254":
		return 31, nil
	case "255.255.255.252":
		return 30, nil
	case "255.255.255.248":
		return 29, nil
	case "255.255.255.240":
		return 28, nil
	case "255.255.255.224":
		return 27, nil
	case "255.255.255.192":
		return 26, nil
	case "255.255.255.128":
		return 25, nil
	case "255.255.255.0":
		return 24, nil
	case "255.255.254.0":
		return 23, nil
	case "255.255.252.0":
		return 22, nil
	case "255.255.248.0":
		return 21, nil
	case "255.255.240.0":
		return 20, nil
	case "255.255.224.0":
		return 19, nil
	case "255.255.192.0":
		return 18, nil
	case "255.255.128.0":
		return 17, nil
	case "255.255.0.0":
		return 16, nil
	case "255.254.0.0":
		return 15, nil
	case "255.252.0.0":
		return 14, nil
	case "255.248.0.0":
		return 13, nil
	case "255.240.0.0":
		return 12, nil
	case "255.224.0.0":
		return 11, nil
	case "255.192.0.0":
		return 10, nil
	case "255.128.0.0":
		return 9, nil
	case "255.0.0.0":
		return 8, nil
	case "254.0.0.0":
		return 7, nil
	case "252.0.0.0":
		return 6, nil
	case "248.0.0.0":
		return 5, nil
	case "240.0.0.0":
		return 4, nil
	case "224.0.0.0":
		return 3, nil
	case "192.0.0.0":
		return 2, nil
	case "128.0.0.0":
		return 1, nil
	case "0.0.0.0":
		return 0, nil
	}

	if regexp.MustCompile("^\\d+$").MatchString(netmask) {
		bits, _ := strconv.Atoi(netmask)
		if bits < 31 {
			return bits, nil
		}
	}

	return 0, errors.New(fmt.Sprintf("Invalid netmask: %s", netmask))
}

func ParseAddress(text string) (*AddressInfo, error) {
	var ai AddressInfo

	ai.Netmask = -1

	getAndRemoveMatch := func(t string, r *regexp.Regexp) (string, string) {
		if m := r.FindStringSubmatch(t); len(m) > 0 {
			return m[0], strings.Replace(t, m[0], "", 1)
		}
		return "", t
	}

	nm, text := getAndRemoveMatch(text, regexp.MustCompile("/[0-9.]+.*$"))
	if nm != "" {
		nm, rest := getAndRemoveMatch(nm, regexp.MustCompile("/[0-9.]+"))

		nm = strings.TrimPrefix(nm, "/")
		if ip := net.ParseIP(nm); ip != nil {
			if bits, err := Netmask2CIDR(ip.String()); err != nil {
				return nil, errors.New("Not a valid netmask: " + nm)
			} else {
				ai.Netmask = bits
			}
		} else if bits, err := strconv.Atoi(nm); err == nil && bits < 64 {
			ai.Netmask = bits
		} else {
			return nil, errors.New("Not a valid netmask: " + nm)
		}

		rest = strings.TrimSpace(rest)
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return nil, errors.New("Invalid data after netmask: " + rest)
			}
			rest = strings.TrimPrefix(rest, ":")
			if rest == "" {
				return nil, errors.New("Empty port after netmask")
			}
			nport, err := net.LookupPort("tcp", rest)
			if err != nil {
				nport, err = net.LookupPort("udp", rest)
			}
			if err != nil {
				return nil, errors.New("Invalid port: " + rest)
			}
			ai.Port = nport
		}
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return &ai, nil
	}

	if ip := net.ParseIP(text); ip != nil {
		ai.Host = ip.String()
		return &ai, nil
	}

	if !ai.HasPort() {
		r := regexp.MustCompile(":+([^:\\[\\]]*)$")
		if m := r.FindStringSubmatch(text); len(m) > 1 {
			text = r.ReplaceAllString(text, "")
			if port := m[1]; port != "" {
				nport, err := net.LookupPort("tcp", port)
				if err != nil {
					nport, err = net.LookupPort("udp", port)
				}
				if err != nil {
					return nil, errors.New("Invalid port: " + port)
				}
				ai.Port = nport
			}
		}
		text = strings.TrimSpace(text)
		if text == "" {
			return &ai, nil
		}
	}

	host, text := getAndRemoveMatch(text, regexp.MustCompile("\\[[^\\]]*\\]"))
	text = strings.TrimSpace(text)
	if host != "" {
		host = strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(host, "]"), "["))
		if strings.Contains(host, ":") {
			if ip := net.ParseIP(host); ip == nil {
				return nil, errors.New("Not a valid IPv6 IP: " + host)
			} else {
				if ai.Netmask > 63 {
					return nil, errors.New(fmt.Sprintf("Not a valid IPv6 netmask: %d", ai.Netmask))
				}
				ai.Host = ip.String()
			}
		} else {
			ai.Host = host
		}
		if text != "" {
			return nil, errors.New("Address contains unparsable data: " + text)
		}
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return &ai, nil
	}

	if strings.Contains(text, ":") {
		if ip := net.ParseIP(text); ip == nil {
			return nil, errors.New("Not a valid IPv6: " + text)
		} else {
			if ai.Netmask > 63 {
				return nil, errors.New(fmt.Sprintf("Not a valid IPv6 netmask: %d", ai.Netmask))
			}
			ai.Host = ip.String()
			return &ai, nil
		}
	}

	if ip := net.ParseIP(text); ip != nil {
		if ip.To4() != nil {
			if ai.Netmask > 31 {
				return nil, errors.New(fmt.Sprintf("Not a valid IPv4 netmask: %d", ai.Netmask))
			}
		} else if ip.To16() != nil {
			if ai.Netmask > 63 {
				return nil, errors.New(fmt.Sprintf("Not a valid IPv6 netmask: %d", ai.Netmask))
			}
		}
		ai.Host = ip.String()
		return &ai, nil
	}

	if !IsValidFQDN(text) {
		return nil, errors.New("Not a valid IP or host: " + text)
	} else {
		ai.Host = text
	}
	return &ai, nil
}

func ResolveAddress(text string) (*ResolvedAddressInfo, error) {
	ai, err := ParseAddress(text)
	if err != nil {
		return nil, err
	}
	rai, err := ai.Resolve()
	return rai, err
}
