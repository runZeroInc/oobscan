package cisco

import "testing"

func TestParseCIMCInfo(t *testing.T) {
	body := []byte(`{
		"hostname":     "C225-WZP29029BE9",
		"serialNumber": "WZP29029BE9",
		"banner":       "",
		"sessionInfo":  "",
		"SlotId":       "",
		"Error":        0
	}`)
	info, ok := parseCIMCInfo(body)
	if !ok {
		t.Fatal("expected parse ok")
	}
	if info.Hostname != "C225-WZP29029BE9" {
		t.Errorf("hostname = %q", info.Hostname)
	}
	if info.SerialNumber != "WZP29029BE9" {
		t.Errorf("serial = %q", info.SerialNumber)
	}
	if info.Model != "C225" {
		t.Errorf("model = %q, want C225", info.Model)
	}
	if info.ChassisSerial != "WZP29029BE9" {
		t.Errorf("chassis serial = %q", info.ChassisSerial)
	}
}

func TestParseCIMCInfoRejectsEmpty(t *testing.T) {
	if _, ok := parseCIMCInfo([]byte(`{"hostname":"","serialNumber":"","Error":1}`)); ok {
		t.Error("expected reject on empty identity")
	}
	if _, ok := parseCIMCInfo([]byte(`not json`)); ok {
		t.Error("expected reject on non-JSON")
	}
}

func TestDeriveModelSkipsNonSerialSuffix(t *testing.T) {
	// A hostname that is not model-serial should not invent a chassis serial.
	i := &CIMCInfo{Hostname: "my-lab-host"}
	i.deriveModel()
	if i.ChassisSerial != "" {
		t.Errorf("chassis serial should be empty, got %q", i.ChassisSerial)
	}
}
