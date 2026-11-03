// Package cim implements a read-only CIM-XML (WBEM) reachability probe on
// TCP 5988 (http) / 5989 (https), the protocol older management stacks (IBM
// Director/IMM, some HP/Dell agents, VMware, Linux sblim/OpenPegasus) expose.
//
// Safety: the probe POSTs a single read-only intrinsic (EnumerateClassNames on
// root/cimv2) -- it never issues an instance-modifying method (CreateInstance,
// ModifyInstance, DeleteInstance, InvokeMethod), so it cannot change device
// state. Presence is confirmed from the CIMOperation response header, a known
// CIM-broker Server header, a 401 CIM realm, or a CIM-XML body.
package cim

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
)

// Standard WBEM/CIM-XML ports.
const (
	PortHTTP  = 5988
	PortHTTPS = 5989
)

// enumClassNames is a read-only CIM-XML intrinsic (no state change). Namespace
// root/cimv2 is universal; a CIMOM answers MethodResponse (or 401 if it wants
// auth), either of which proves WBEM without enumerating anything sensitive.
const enumClassNames = `<?xml version="1.0" encoding="utf-8"?>` +
	`<CIM CIMVERSION="2.0" DTDVERSION="2.0"><MESSAGE ID="1" PROTOCOLVERSION="1.0">` +
	`<SIMPLEREQ><IMETHODCALL NAME="EnumerateClassNames"><LOCALNAMESPACEPATH>` +
	`<NAMESPACE NAME="root"/><NAMESPACE NAME="cimv2"/></LOCALNAMESPACEPATH>` +
	`<IPARAMVALUE NAME="DeepInheritance"><VALUE>FALSE</VALUE></IPARAMVALUE>` +
	`</IMETHODCALL></SIMPLEREQ></MESSAGE></CIM>`

const enumComputerSystem = `<?xml version="1.0" encoding="utf-8"?>` +
	`<CIM CIMVERSION="2.0" DTDVERSION="2.0"><MESSAGE ID="2" PROTOCOLVERSION="1.0">` +
	`<SIMPLEREQ><IMETHODCALL NAME="EnumerateInstances"><LOCALNAMESPACEPATH>` +
	`<NAMESPACE NAME="root"/><NAMESPACE NAME="cimv2"/></LOCALNAMESPACEPATH>` +
	`<IPARAMVALUE NAME="ClassName"><CLASSNAME NAME="CIM_ComputerSystem"/></IPARAMVALUE>` +
	`<IPARAMVALUE NAME="LocalOnly"><VALUE>FALSE</VALUE></IPARAMVALUE>` +
	`<IPARAMVALUE NAME="IncludeQualifiers"><VALUE>FALSE</VALUE></IPARAMVALUE>` +
	`<IPARAMVALUE NAME="IncludeClassOrigin"><VALUE>FALSE</VALUE></IPARAMVALUE>` +
	`</IMETHODCALL></SIMPLEREQ></MESSAGE></CIM>`

// Result records CIMOM presence and any broker/vendor tell. Port/Scheme are set
// by the caller (identify) so a follow-up authenticated check knows where to go.
type Result struct {
	Broker  string // "OpenPegasus", "SBLIM sfcb", "OpenWBEM", "WMI/WinRM", or ""
	Server  string // raw Server header
	Realm   string // WWW-Authenticate value when auth is required
	AuthReq bool   // CIMOM answered 401 (credentials needed)
	Port    int    // populated by the caller
	Scheme  string // "http"/"https", populated by the caller
}

// Probe posts the read-only intrinsic and returns a Result when a CIMOM answers,
// or nil. The client should skip TLS verification for the https port (scanner
// clients do). It relies on the client's timeout to bound the request.
func Probe(client *http.Client, scheme, hostPort string) *Result {
	return ProbeContext(context.Background(), client, scheme, hostPort)
}

// ProbeContext is Probe with cancellation.
func ProbeContext(ctx context.Context, client *http.Client, scheme, hostPort string) *Result {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, scheme+"://"+hostPort+"/cimom", strings.NewReader(enumClassNames))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	req.Header.Set("CIMProtocolVersion", "1.0")
	req.Header.Set("CIMOperation", "MethodCall")
	req.Header.Set("CIMMethod", "EnumerateClassNames")
	req.Header.Set("CIMObject", "root/cimv2")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	server := resp.Header.Get("Server")
	// A CIMOM echoes CIMOperation (MethodResponse); when it wants auth it answers
	// 401 with a CIM realm. Either -- plus a known broker Server or CIM-XML body --
	// confirms WBEM and rules out an arbitrary web server on the port.
	hasCIMHdr := resp.Header.Get("CIMOperation") != ""
	low := strings.ToLower(server + " " + string(body))
	broker := ""
	switch {
	case strings.Contains(low, "pegasus"):
		broker = "OpenPegasus"
	case strings.Contains(low, "sfcb"), strings.Contains(low, "small footprint cim"):
		broker = "SBLIM sfcb"
	case strings.Contains(low, "openwbem"):
		broker = "OpenWBEM"
	case strings.Contains(low, "microsoft-httpapi"), strings.Contains(low, "winrm"):
		broker = "WMI/WinRM"
	}
	cimXML := strings.Contains(string(body), "<CIM ") ||
		strings.Contains(low, "methodresponse") || strings.Contains(low, "cim_")
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	// 5988/5989 are IANA-dedicated WBEM ports, so an HTTP 401 here is an
	// auth-gated CIMOM even when the 401 body carries no CIM markers. Detecting it
	// is what lets the follow-up default-credential check reach an SMC-style WBEM
	// that keeps its own password.
	authReq := resp.StatusCode == http.StatusUnauthorized && wwwAuth != ""
	if !hasCIMHdr && broker == "" && !cimXML && !authReq {
		return nil
	}
	return &Result{Broker: broker, Server: server, Realm: wwwAuth, AuthReq: authReq}
}

// AuthEvidence records structured evidence from an accepted CIM credential and
// a read-only CIM_ComputerSystem enumeration.
type AuthEvidence struct {
	ClassCount int
	System     SystemInfo
}

// SystemInfo contains common CIM_ComputerSystem identity properties.
type SystemInfo struct {
	ClassName    string
	Name         string
	ElementName  string
	Caption      string
	Description  string
	Manufacturer string
	Model        string
	SerialNumber string
	UUID         string
}

// Authenticate posts read-only CIM intrinsics with HTTP Basic credentials and
// reports whether the CIMOM accepted them.
func Authenticate(client *http.Client, scheme, hostPort, user, pass string) (ok bool, evidence *AuthEvidence) {
	return AuthenticateContext(context.Background(), client, scheme, hostPort, user, pass)
}

// AuthenticateContext is Authenticate with cancellation.
func AuthenticateContext(ctx context.Context, client *http.Client, scheme, hostPort, user, pass string) (ok bool, evidence *AuthEvidence) {
	body, status, err := authenticatedIntrinsic(ctx, client, scheme, hostPort, user, pass, "EnumerateClassNames", enumClassNames)
	if err != nil || status != http.StatusOK {
		return false, nil
	}
	// Require a real CIM MethodResponse so a server that 200s everything can't
	// masquerade as an accepted login.
	s := string(body)
	low := strings.ToLower(s)
	if !strings.Contains(low, "imethodresponse") && !strings.Contains(s, "IRETURNVALUE") && !strings.Contains(s, "<CIM ") {
		return false, nil
	}
	evidence = &AuthEvidence{ClassCount: strings.Count(s, "<CLASSNAME")}
	if systemBody, systemStatus, systemErr := authenticatedIntrinsic(ctx, client, scheme, hostPort, user, pass, "EnumerateInstances", enumComputerSystem); systemErr == nil && systemStatus == http.StatusOK {
		if system, parsed := parseComputerSystem(systemBody); parsed {
			evidence.System = system
		}
	}
	return true, evidence
}

func authenticatedIntrinsic(ctx context.Context, client *http.Client, scheme, hostPort, user, pass, method, requestBody string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, scheme+"://"+hostPort+"/cimom", strings.NewReader(requestBody))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	req.Header.Set("CIMProtocolVersion", "1.0")
	req.Header.Set("CIMOperation", "MethodCall")
	req.Header.Set("CIMMethod", method)
	req.Header.Set("CIMObject", "root/cimv2")
	req.SetBasicAuth(user, pass)
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return body, resp.StatusCode, nil
}

type cimInstance struct {
	ClassName  string        `xml:"CLASSNAME,attr"`
	Properties []cimProperty `xml:"PROPERTY"`
}

type cimProperty struct {
	Name  string `xml:"NAME,attr"`
	Value string `xml:"VALUE"`
}

func parseComputerSystem(body []byte) (SystemInfo, bool) {
	decoder := xml.NewDecoder(strings.NewReader(string(body)))
	for {
		token, err := decoder.Token()
		if err != nil {
			return SystemInfo{}, false
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "INSTANCE" {
			continue
		}
		var instance cimInstance
		if err := decoder.DecodeElement(&instance, &start); err != nil {
			return SystemInfo{}, false
		}
		if !strings.EqualFold(instance.ClassName, "CIM_ComputerSystem") {
			continue
		}
		info := SystemInfo{ClassName: instance.ClassName}
		for _, property := range instance.Properties {
			value := strings.TrimSpace(property.Value)
			switch strings.ToLower(property.Name) {
			case "name":
				info.Name = value
			case "elementname":
				info.ElementName = value
			case "caption":
				info.Caption = value
			case "description":
				info.Description = value
			case "manufacturer":
				info.Manufacturer = value
			case "model":
				info.Model = value
			case "serialnumber":
				info.SerialNumber = value
			case "uuid":
				info.UUID = value
			}
		}
		if info.Name != "" || info.ElementName != "" || info.Manufacturer != "" || info.Model != "" || info.SerialNumber != "" || info.UUID != "" {
			return info, true
		}
	}
}
