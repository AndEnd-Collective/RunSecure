package egress

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/runneryml"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/security"
	"github.com/stretchr/testify/require"
)

// Removing the connection-time destination ACL, independently resolving the
// backend again, or allowing CONNECT before checking its port breaks this test.
// Opt in with RUNSECURE_PROXY_INTEGRATION=1 after building infra/squid/Dockerfile.
func TestProxySecurityIntegration(t *testing.T) {
	if os.Getenv("RUNSECURE_PROXY_INTEGRATION") != "1" {
		t.Skip("set RUNSECURE_PROXY_INTEGRATION=1 to run real Squid/HAProxy regressions")
	}
	image := os.Getenv("RUNSECURE_PROXY_TEST_IMAGE")
	require.NotEmpty(t, image, "build infra/squid/Dockerfile and set RUNSECURE_PROXY_TEST_IMAGE")
	fixtureImage := os.Getenv("RUNSECURE_PROXY_FIXTURE_IMAGE")
	if fixtureImage == "" {
		fixtureImage = "node:24.21.0-bookworm-slim"
	}
	id := fmt.Sprintf("rs-egress-%d", time.Now().UnixNano())
	publicNet, privateNet := id+"-a-public", id+"-z-private"
	dockerTest(t, nil, "network", "create", "--ipv6", "--subnet", "2001:db8:248::/64", "--subnet", "203.0.113.0/24", publicNet)
	t.Cleanup(func() { dockerTest(t, nil, "network", "rm", publicNet) })
	dockerTest(t, nil, "network", "create", "--ipv6", "--subnet", "fd00:249::/64", "--subnet", "172.31.249.0/24", privateNet)
	t.Cleanup(func() { dockerTest(t, nil, "network", "rm", privateNet) })
	fixture := id + "-fixture"
	volume := id + "-configs"
	dockerTest(t, nil, "volume", "create", volume)
	t.Cleanup(func() { dockerTest(t, nil, "volume", "rm", volume) })
	dockerTest(t, nil, "create", "--name", fixture, "--network", publicNet, "--ip", "203.0.113.10", "--ip6", "2001:db8:248::10",
		"--mount", "type=volume,source="+volume+",target=/configs", "--env", "NODE_OPTIONS=--no-experimental-webstorage", fixtureImage, "node", "/fixture.js")
	t.Cleanup(func() { dockerTest(t, nil, "rm", "-f", fixture) })
	dockerTest(t, nil, "network", "connect", "--ip", "172.31.249.10", "--ip6", "fd00:249::10", privateNet, fixture)
	copyProxyTestFiles(t, fixture, map[string][]byte{"fixture.js": []byte(proxyFixtureJS)})
	dockerTest(t, nil, "start", fixture)
	waitProxyFixture(t, fixture)
	otherFixture := id + "-other"
	dockerTest(t, nil, "create", "--name", otherFixture, "--network", privateNet, "--ip", "172.31.249.11",
		"--env", "NODE_OPTIONS=--no-experimental-webstorage", fixtureImage, "node", "/fixture.js")
	t.Cleanup(func() { dockerTest(t, nil, "rm", "-f", otherFixture) })
	copyProxyTestFiles(t, otherFixture, map[string][]byte{"fixture.js": []byte(proxyFixtureJS)})
	dockerTest(t, nil, "start", otherFixture)
	waitProxyFixture(t, otherFixture)

	runner := &runneryml.Runner{
		HTTPEgress: []string{"public.test", "private.test"},
		TCPEgress:  []string{"public.test:5432", "private.test:5433", "rebind.test:5434", "linklocal.test:5435", "v6private.test:5436", "missing.test:5437", "otherprivate.test:5438", "203.0.113.10:5439", "v6public.test:5440", "public.test:5441"},
	}
	for _, mode := range []string{"default", "exception", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			policy := security.Defaults("strict")
			if mode == "exception" {
				policy.AllowedPrivateCIDRs = []*net.IPNet{mustParseCIDR("172.31.249.10/32"), mustParseCIDR("fd00:249::10/128")}
			}
			squid, haproxy := RenderSquid(runner, policy), RenderHAProxy(runner, policy)
			if mode == "legacy" {
				squid, haproxy = renderLegacyProxyTest(t)
				// The legacy frontend intentionally binds its fixed internal IP.
				haproxy = bytes.ReplaceAll(haproxy, []byte("10.11.12.13:"), []byte("203.0.113.20:"))
			}
			// Only resolver transport is substituted; all generated destination
			// rules, DNS hold times, and backend directives execute unchanged.
			haproxy = bytes.ReplaceAll(haproxy, []byte("parse-resolv-conf"), []byte("nameserver fixture 203.0.113.10:53"))
			squid = bytes.ReplaceAll(squid, []byte("dns_nameservers 8.8.8.8 8.8.4.4"), []byte("dns_nameservers 203.0.113.10"))
			if !bytes.Contains(squid, []byte("dns_nameservers")) {
				squid = append(squid, []byte("\ndns_nameservers 203.0.113.10\n")...)
			}
			name := id + "-" + mode
			copyProxyTestFiles(t, fixture, map[string][]byte{"configs/" + mode + "/squid.conf": squid, "configs/" + mode + "/haproxy.cfg": haproxy})
			args := []string{"create", "--name", name, "--network", publicNet, "--ip", "203.0.113.20", "--ip6", "2001:db8:248::20",
				"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
				"--mount", "type=volume,source=" + volume + ",target=/configs,readonly", "--env", "SQUID_CFG=/configs/" + mode + "/squid.conf", "--env", "HAPROXY_CFG=/configs/" + mode + "/haproxy.cfg",
				"--tmpfs", "/tmp", "--tmpfs", "/var/run/squid:uid=1001,gid=1001",
				"--tmpfs", "/var/log/squid:uid=1001,gid=1001", "--tmpfs", "/var/spool/squid:uid=1001,gid=1001",
				"--tmpfs", "/var/lib/haproxy:uid=1001,gid=1001", "--env", "ENABLE_HAPROXY=true"}
			args = append(args, image)
			dockerTest(t, nil, args...)
			t.Cleanup(func() { dockerTest(t, nil, "rm", "-f", name) })
			dockerTest(t, nil, "network", "connect", "--ip", "172.31.249.20", "--ip6", "fd00:249::20", privateNet, name)
			dockerTest(t, nil, "start", name)
			address := func(port string) string { return net.JoinHostPort("203.0.113.20", port) }
			publicAddress := address("5432")
			require.Eventually(t, func() bool { return proxyTestExchange(t, fixture, publicAddress) == "echo:203.0.113.10" }, 20*time.Second, 200*time.Millisecond,
				"normal public TCP must return backend bytes; logs: %s", dockerTest(t, nil, "logs", name))
			require.Equal(t, "echo:2001:db8:248::10", proxyTestExchange(t, fixture, address("5440")), "public IPv6-only DNS must remain supported")
			require.Equal(t, "greeting:203.0.113.10", dockerTest(t, nil, "exec", fixture, "node", "-e", proxyClientJS, address("5441"), "", "server-first"), "server-first TCP protocols must connect without waiting for client data")
			if mode != "legacy" {
				require.Eventually(t, func() bool { return proxyTestExchange(t, fixture, address("5439")) == "echo:203.0.113.10" }, 10*time.Second, 200*time.Millisecond, "public IP literals still work")
			}
			proxyAddress := address("3128")
			require.Eventually(t, func() bool { return proxyTestConnect(t, fixture, proxyAddress, "public.test:443") == "200" }, 15*time.Second, 200*time.Millisecond)
			t.Run("CONNECT-port-boundary", func(t *testing.T) {
				require.Equal(t, "403", proxyTestConnect(t, fixture, proxyAddress, "public.test:5432"), "an allowed host must not tunnel to arbitrary TCP ports")
				if mode == "exception" {
					require.Equal(t, "200", proxyTestConnect(t, fixture, proxyAddress, "private.test:443"), "approved private CONNECT 443 remains supported")
					require.Equal(t, "403", proxyTestConnect(t, fixture, proxyAddress, "private.test:5433"), "private CIDR exception must not override CONNECT port restriction")
				}
			})
			t.Run("TCP-destination-policy", func(t *testing.T) {
				if mode == "exception" {
					require.Equal(t, "echo:172.31.249.10", proxyTestExchange(t, fixture, address("5433")), "approved private service must remain reachable")
					require.Equal(t, "echo:fd00:249::10", proxyTestExchange(t, fixture, address("5436")), "approved private IPv6 service must remain reachable")
				} else {
					require.Empty(t, proxyTestExchange(t, fixture, address("5433")), "private hostname must not reach backend")
					require.Empty(t, proxyTestExchange(t, fixture, address("5436")), "private IPv6 hostname must not reach backend")
				}
				for _, port := range []string{"5435", "5437", "5438"} {
					require.Empty(t, proxyTestExchange(t, fixture, address(port)), "link-local, failed DNS, and nonapproved private destinations must fail closed (port %s)", port)
				}
			})
			t.Run("DNS-refresh", func(t *testing.T) {
				dockerTest(t, strings.NewReader("203.0.113.10"), "exec", "-i", fixture, "sh", "-c", "cat > /tmp/rebind")
				rebindAddress := address("5434")
				require.Eventually(t, func() bool { return proxyTestExchange(t, fixture, rebindAddress) == "echo:203.0.113.10" }, 15*time.Second, 200*time.Millisecond)
				// Rebind to the adjacent private host, outside the approved /32.
				dockerTest(t, strings.NewReader("172.31.249.11"), "exec", "-i", fixture, "sh", "-c", "cat > /tmp/rebind")
				deadline := time.Now().Add(15 * time.Second)
				blocked := false
				for time.Now().Before(deadline) {
					got := proxyTestExchange(t, fixture, rebindAddress)
					require.NotEqual(t, "echo:172.31.249.11", got, "DNS refresh must never connect to a forbidden private backend")
					if got == "" {
						blocked = true
						break
					}
					time.Sleep(200 * time.Millisecond)
				}
				require.True(t, blocked, "the refreshed DNS answer must eventually be enforced")
			})
		})
	}
}

func dockerTest(t *testing.T, stdin io.Reader, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = stdin
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "docker %v: %s", args, out)
	return string(out)
}

func copyProxyTestFiles(t *testing.T, container string, files map[string][]byte) {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for name, data := range files {
		require.NoError(t, w.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}))
		_, err := w.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	dockerTest(t, &buf, "cp", "-", container+":/")
}

func waitProxyFixture(t *testing.T, container string) {
	t.Helper()
	require.Eventually(t, func() bool { return strings.Contains(dockerTest(t, nil, "logs", container), "ready") }, 10*time.Second, 100*time.Millisecond)
}

func proxyTestExchange(t *testing.T, fixture, address string) string {
	t.Helper()
	return dockerTest(t, nil, "exec", fixture, "node", "-e", proxyClientJS, address, "")
}

func proxyTestConnect(t *testing.T, fixture, address, target string) string {
	t.Helper()
	return dockerTest(t, nil, "exec", fixture, "node", "-e", proxyClientJS, address, target)
}

const proxyClientJS = `
const net = require('node:net');
const [address,target] = process.argv.slice(1), [host,port] = address.split(':');
const s = net.connect({host,port:Number(port)});
s.setTimeout(4000, () => s.destroy());
s.on('error', () => s.destroy());
s.on('connect', () => { if(process.argv[3] !== 'server-first') s.write(target ? 'CONNECT '+target+' HTTP/1.1\r\nHost: '+target+'\r\n\r\n' : 'security-regression'); });
s.once('data', data => { process.stdout.write(target ? data.toString().split(' ')[1] : data.toString()); s.destroy(); });
`

func renderLegacyProxyTest(t *testing.T) ([]byte, []byte) {
	t.Helper()
	root := t.TempDir()
	// Execute the existing generator in a scratch copy so its output never
	// overwrites an operator's configs or another integration test's files.
	repoRoot := filepath.Join("..", "..", "..", "..")
	for _, dir := range []string{"infra/scripts", "infra/squid"} {
		require.NoError(t, os.CopyFS(filepath.Join(root, dir), os.DirFS(filepath.Join(repoRoot, dir))))
	}
	project := filepath.Join(root, "project")
	require.NoError(t, os.MkdirAll(filepath.Join(project, ".github"), 0o755))
	yaml := "runtime: node:24\nhttp_egress: [public.test]\ntcp_egress: [public.test:5432, private.test:5433, rebind.test:5434, linklocal.test:5435, v6private.test:5436, missing.test:5437, otherprivate.test:5438, v6public.test:5440, public.test:5441]\n"
	require.NoError(t, os.WriteFile(filepath.Join(project, ".github", "runner.yml"), []byte(yaml), 0o600))
	cmd := exec.Command("bash", filepath.Join(root, "infra/scripts/generate-egress-conf.sh"), project)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	squid, err := os.ReadFile(filepath.Join(root, "infra/squid/runtime.conf"))
	require.NoError(t, err)
	haproxy, err := os.ReadFile(filepath.Join(root, "infra/squid/haproxy.cfg"))
	require.NoError(t, err)
	return squid, haproxy
}

const proxyFixtureJS = `
const net = require('node:net'), dns = require('node:dgram'), fs = require('node:fs');
for (const port of [443,5432,5433,5434,5435,5436,5437,5438,5439,5440]) {
  net.createServer(s => s.on('data', () => { console.log('received', s.localAddress, port); s.end('echo:' + s.localAddress.replace('::ffff:', '')); })).listen(port, '::');
}
net.createServer(s => s.end('greeting:' + s.localAddress.replace('::ffff:', ''))).listen(5441, '::');
const server = dns.createSocket('udp4');
server.on('message', (q, peer) => {
  let end = 12, parts = [];
  while(q[end]) { const n = q[end++]; parts.push(q.subarray(end, end+n).toString()); end += n; }
  end += 1; const type = q.readUInt16BE(end); end += 4;
  const host = parts.join('.');
  let ip = {'public.test':'203.0.113.10','private.test':'172.31.249.10','otherprivate.test':'172.31.249.11','linklocal.test':'169.254.169.254'}[host];
  if(host === 'rebind.test') { try { ip = fs.readFileSync('/tmp/rebind', 'utf8').trim(); } catch { ip = '203.0.113.10'; } }
  let data;
  if(type === 1 && ip) data = Buffer.from(ip.split('.').map(Number));
  const v6 = {'v6private.test':['fd00','249','0','0','0','0','0','10'], 'v6public.test':['2001','db8','248','0','0','0','0','10']}[host];
  if(type === 28 && v6) { data = Buffer.alloc(16); v6.forEach((part,i) => data.writeUInt16BE(parseInt(part,16),i*2)); }
  const header = Buffer.from(q.subarray(0,12)); header.writeUInt16BE(0x8180,2); header.writeUInt16BE(data ? 1 : 0,6); header.writeUInt16BE(0,8); header.writeUInt16BE(0,10);
  let answer = Buffer.alloc(0);
  if(data) { answer = Buffer.alloc(12); answer.writeUInt16BE(0xc00c,0); answer.writeUInt16BE(type,2); answer.writeUInt16BE(1,4); answer.writeUInt32BE(1,6); answer.writeUInt16BE(data.length,10); answer = Buffer.concat([answer,data]); }
  console.log('dns',host,type,ip || 'none');
  server.send(Buffer.concat([header,q.subarray(12,end),answer]), peer.port, peer.address);
});
server.bind(53, '0.0.0.0', () => console.log('ready'));
`
