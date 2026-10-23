package vm

import "testing"

func TestResolveSupervisorGatewayEndpoint(t *testing.T) {
	for _, test := range []struct {
		name       string
		configured string
		gatewayURL string
		want       string
	}{
		{name: "configured endpoint wins", configured: "https://configured:7443", gatewayURL: "https://derived:7443", want: "https://configured:7443"},
		{name: "derive from trusted sandbox gateway URL", gatewayURL: "http://127.0.0.1:7443", want: "http://127.0.0.1:7443"},
		{name: "empty stays unset"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := resolveSupervisorGatewayEndpoint(test.configured, test.gatewayURL); got != test.want {
				t.Fatalf("resolveSupervisorGatewayEndpoint() = %q, want %q", got, test.want)
			}
		})
	}
}
