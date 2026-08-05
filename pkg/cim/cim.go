package cim

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
)

const (
	PortHTTP  = 5988
	PortHTTPS = 5989
)

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

type Result struct {
	Broker  string
	Server  string
	Realm   string
	AuthReq bool
	Port    int
	Scheme  string
}

func Probe(client *http.Client, scheme, hostPort string) *Result {
	return ProbeContext(context.Background(), client, scheme, hostPort)
}

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

	authReq := resp.StatusCode == http.StatusUnauthorized && wwwAuth != ""
	if !hasCIMHdr && broker == "" && !cimXML && !authReq {
		return nil
	}
	return &Result{Broker: broker, Server: server, Realm: wwwAuth, AuthReq: authReq}
}

type AuthEvidence struct {
	ClassCount int
	System     SystemInfo
}

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

func Authenticate(client *http.Client, scheme, hostPort, user, pass string) (ok bool, evidence *AuthEvidence) {
	return AuthenticateContext(context.Background(), client, scheme, hostPort, user, pass)
}

func AuthenticateContext(ctx context.Context, client *http.Client, scheme, hostPort, user, pass string) (ok bool, evidence *AuthEvidence) {
	body, status, err := authenticatedIntrinsic(ctx, client, scheme, hostPort, user, pass, "EnumerateClassNames", enumClassNames)
	if err != nil || status != http.StatusOK {
		return false, nil
	}

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
