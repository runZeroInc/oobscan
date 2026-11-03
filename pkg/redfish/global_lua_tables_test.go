package redfish

import "testing"

func TestParseGlobalLuaTablesBody(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		body        string
		want        bool
		memberCount int
	}{
		{name: "empty collection", status: 200, body: `{"@odata.id":"/redfish/v1/GlobalLuaTables","Members":[],"Members@odata.count":0}`, want: true},
		{name: "linked resources", status: 200, body: `{"@odata.id":"/redfish/v1/GlobalLuaTables","Members":[{"@odata.id":"/redfish/v1/AccountService"}]}`, want: true, memberCount: 1},
		{name: "legacy object", status: 200, body: `{"GlobalLuaTables":{"handlerTable":{"x":1}}}`, want: true, memberCount: -1},
		{name: "unrelated resource", status: 200, body: `{"@odata.id":"/redfish/v1/SessionService/Sessions","Members":[]}`, want: false},
		{name: "login page", status: 200, body: `<html><title>login</title></html>`, want: false},
		{name: "non-200", status: 401, body: `{"GlobalLuaTables":{}}`, want: false},
		{name: "short", status: 200, body: `{}`, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, memberCount := parseGlobalLuaTablesBody(tc.status, []byte(tc.body))
			if got != tc.want || memberCount != tc.memberCount {
				t.Fatalf("parseGlobalLuaTablesBody()=(%v, %d) want (%v, %d)", got, memberCount, tc.want, tc.memberCount)
			}
		})
	}
}
