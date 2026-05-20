package proxy

import (
	"testing"

	"github.com/AndEnd-Collective/runsecure/infra/socket-proxy/internal/imageallow"
)

func FuzzValidateContainerCreate(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{}`),
		[]byte(`{"Image":""}`),
		[]byte(`{"Image":"ghcr.io/test/runner@sha256:ff","User":"1001:0","HostConfig":{"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges:true"]}}`),
		[]byte(`{"Image":"ghcr.io/test/runner@sha256:ff","User":"1001","HostConfig":{"Privileged":true}}`),
		[]byte(`not json`),
		[]byte("{\"Image\":\"\\u0000\"}"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	dir := f.TempDir()
	path := dir + "/allow.txt"
	if err := writeFileImpl(path, "ghcr.io/test/runner@sha256:ff\n"); err != nil {
		f.Fatal(err)
	}
	allow, err := imageallow.Load(path)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		// Must never panic.
		_ = ValidateContainerCreate(body, allow)
	})
}
