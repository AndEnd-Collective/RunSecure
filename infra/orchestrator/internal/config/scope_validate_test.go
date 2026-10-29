package config

import (
	"fmt"
	"github.com/AndEnd-Collective/runsecure/infra/orchestrator/internal/backend"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func makeScope(t *testing.T, mut func(*Scope)) *Scope {
	t.Helper()
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	require.NoError(t, os.WriteFile(patFile, []byte("ghp_x"), 0o400))
	projDir := filepath.Join(dir, "proj")
	require.NoError(t, os.MkdirAll(filepath.Join(projDir, ".github"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(projDir, ".github", "runner.yml"), []byte("runtime: node:24\n"), 0o644))

	s := &Scope{
		APIVersion:          SupportedAPIVersion,
		Name:                "test",
		GlobalMaxRunners:    8,
		PollIntervalSeconds: 15,
		SecurityProfile:     "strict",
		Auth:                AuthBlock{Type: "pat", PATFile: patFile},
		OrchEgress:          OrchEgressBlock{AllowDomains: []string{"api.github.com"}},
		Repos: []RepoBlock{{
			Repo: "o/r", ProjectDir: projDir, MaxConcurrent: 3,
		}},
	}
	if mut != nil {
		mut(s)
	}
	return s
}

func TestValidate_HappyPath(t *testing.T) {
	s := makeScope(t, nil)
	require.NoError(t, s.Validate())
}

func TestValidate_NameRequired(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Name = "" })
	require.ErrorContains(t, s.Validate(), "name")
}

func TestValidate_PollIntervalFloor(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.PollIntervalSeconds = 3 })
	require.ErrorContains(t, s.Validate(), "poll_interval_seconds")
}

// Mutation kill: scope_validate.go:18 — `< 5` boundary. Mutation `<= 5`
// would also reject 5; mutation `< 4` would accept 4. Cover both ends.
func TestValidate_PollIntervalExactlyFive_Accepted(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.PollIntervalSeconds = 5 })
	require.NoError(t, s.Validate(),
		"poll_interval_seconds=5 is the lower bound and must be accepted")
}

func TestValidate_PollIntervalFour_Rejected(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.PollIntervalSeconds = 4 })
	require.Error(t, s.Validate())
}

func TestValidate_SecurityProfileWhitelist(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.SecurityProfile = "yolo" })
	require.ErrorContains(t, s.Validate(), "security_profile")
}

func TestValidate_CustomProfileRequiresOverrides(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.SecurityProfile = "custom" })
	require.ErrorContains(t, s.Validate(), "security_overrides")
}

func TestValidate_AuthTypeInvalid(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Auth.Type = "oauth" })
	require.ErrorContains(t, s.Validate(), "auth.type")
}

func TestValidate_PATFileRequired(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Auth.PATFile = "" })
	require.ErrorContains(t, s.Validate(), "pat_file")
}

func TestValidate_PATFileMustExist(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Auth.PATFile = "/nonexistent" })
	require.Error(t, s.Validate())
}

func TestValidate_PATFileMode0400Required(t *testing.T) {
	s := makeScope(t, nil)
	require.NoError(t, os.Chmod(s.Auth.PATFile, 0o644))
	require.ErrorContains(t, s.Validate(), "mode 0400")
}

func TestValidate_ApiGithubComRequiredInAllowDomains(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.OrchEgress.AllowDomains = []string{"example.com"} })
	require.ErrorContains(t, s.Validate(), "api.github.com")
}

func TestValidate_ReposNonEmpty(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Repos = nil })
	require.ErrorContains(t, s.Validate(), "repo")
}

func TestValidate_RepoNameRequired(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Repos[0].Repo = "" })
	require.ErrorContains(t, s.Validate(), "repos[0].repo")
}

func TestValidate_MaxConcurrentPositive(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Repos[0].MaxConcurrent = 0 })
	require.ErrorContains(t, s.Validate(), "max_concurrent")
}

func TestValidate_ProjectDirRequired(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Repos[0].ProjectDir = "" })
	require.ErrorContains(t, s.Validate(), "project_dir")
}

func TestValidate_ProjectDirMustExist(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Repos[0].ProjectDir = "/nonexistent" })
	require.ErrorContains(t, s.Validate(), "project_dir")
}

func TestValidate_RunnerYmlMustExist(t *testing.T) {
	s := makeScope(t, nil)
	require.NoError(t, os.Remove(filepath.Join(s.Repos[0].ProjectDir, ".github", "runner.yml")))
	require.ErrorContains(t, s.Validate(), "runner.yml")
}

func TestValidate_GlobalMaxRunnersPositive(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.GlobalMaxRunners = 0 })
	require.ErrorContains(t, s.Validate(), "global_max_runners")
}

// --- backend field ---

// TestValidate_Backend_Empty_DefaultsToCompose verifies that omitting backend
// is equivalent to setting it to "compose" — the zero value is normalised.
func TestValidate_Backend_Empty_DefaultsToCompose(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Backend = "" })
	require.NoError(t, s.Validate())
	require.Equal(t, "compose", s.Backend,
		"empty backend must be normalised to 'compose'")
}

// TestValidate_Backend_Compose_Accepted verifies the explicit "compose" value.
func TestValidate_Backend_Compose_Accepted(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Backend = "compose" })
	require.NoError(t, s.Validate())
}

// TestValidate_Backend_Kube_Accepted verifies that "kube" is a valid backend
// value and that project_dir is NOT required when the kube backend is selected.
func TestValidate_Backend_Kube_Accepted(t *testing.T) {
	s := makeScope(t, func(s *Scope) {
		s.Backend = "kube"
		require.NoError(t, os.Chmod(s.Auth.PATFile, 0o440))
	})
	require.NoError(t, s.Validate())
}

func TestValidate_Backend_Kube_RejectsComposeOnlySecretMode(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Backend = "kube" })
	require.ErrorContains(t, s.Validate(), "mode 0440")
}

// TestValidate_Backend_Kube_NoProjectDir verifies that repos without project_dir
// are valid when backend=="kube" (runner.yml is fetched via the GitHub API).
func TestValidate_Backend_Kube_NoProjectDir(t *testing.T) {
	s := makeScope(t, func(s *Scope) {
		s.Backend = "kube"
		require.NoError(t, os.Chmod(s.Auth.PATFile, 0o440))
		// Strip the project_dir; kube backend must NOT require it.
		s.Repos[0].ProjectDir = ""
	})
	require.NoError(t, s.Validate(),
		"kube backend must not require project_dir")
}

// TestValidate_Backend_Kube_NonexistentProjectDir verifies that a non-existent
// project_dir is silently ignored for the kube backend (the field is unused).
func TestValidate_Backend_Kube_NonexistentProjectDir(t *testing.T) {
	s := makeScope(t, func(s *Scope) {
		s.Backend = "kube"
		require.NoError(t, os.Chmod(s.Auth.PATFile, 0o440))
		s.Repos[0].ProjectDir = "/nonexistent/path"
	})
	require.NoError(t, s.Validate(),
		"kube backend must ignore project_dir even if non-existent")
}

// TestValidate_Backend_Compose_RequiresProjectDir confirms the compose backend
// still enforces project_dir (unchanged behavior).
func TestValidate_Backend_Compose_RequiresProjectDir(t *testing.T) {
	s := makeScope(t, func(s *Scope) {
		s.Backend = "compose"
		s.Repos[0].ProjectDir = ""
	})
	require.ErrorContains(t, s.Validate(), "project_dir",
		"compose backend must still require project_dir")
}

// TestValidate_Backend_Invalid_Rejected verifies that unknown backend values
// are rejected with an informative error.
func TestValidate_Backend_Invalid_Rejected(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Backend = "bogus" })
	require.ErrorContains(t, s.Validate(), "backend")
}

// TestValidate_Backend_Invalid_Rejected_Docker verifies "docker" is not a
// valid alias (the accepted values are precisely "compose" and "kube").
func TestValidate_Backend_Invalid_Rejected_Docker(t *testing.T) {
	s := makeScope(t, func(s *Scope) { s.Backend = "docker" })
	require.ErrorContains(t, s.Validate(), "backend")
}

// --- github_app auth type ---

// makeAppScope builds a valid Scope with auth.type=github_app, writing a
// mode-0400 fake PEM file. The mut function can override any field.
func makeAppScope(t *testing.T, mut func(*Scope)) *Scope {
	t.Helper()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "app.pem")
	require.NoError(t, os.WriteFile(keyFile, []byte("-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"), 0o600))
	require.NoError(t, os.Chmod(keyFile, 0o400))

	projDir := filepath.Join(dir, "proj")
	require.NoError(t, os.MkdirAll(filepath.Join(projDir, ".github"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(projDir, ".github", "runner.yml"), []byte("runtime: node:24\n"), 0o644))

	s := &Scope{
		APIVersion:          SupportedAPIVersion,
		Name:                "app-test",
		GlobalMaxRunners:    4,
		PollIntervalSeconds: 15,
		SecurityProfile:     "strict",
		Auth: AuthBlock{
			Type:           "github_app",
			AppID:          12345,
			InstallationID: 67890,
			PrivateKeyFile: keyFile,
		},
		OrchEgress: OrchEgressBlock{AllowDomains: []string{"api.github.com"}},
		Repos: []RepoBlock{{
			Repo: "o/r", ProjectDir: projDir, MaxConcurrent: 2,
		}},
	}
	if mut != nil {
		mut(s)
	}
	return s
}

// TestValidate_GitHubApp_HappyPath verifies that a correctly configured
// github_app auth block passes validation.
func TestValidate_GitHubApp_HappyPath(t *testing.T) {
	s := makeAppScope(t, nil)
	require.NoError(t, s.Validate())
}

// TestValidate_GitHubApp_AppIDRequired verifies that app_id=0 is rejected.
func TestValidate_GitHubApp_AppIDRequired(t *testing.T) {
	s := makeAppScope(t, func(s *Scope) { s.Auth.AppID = 0 })
	require.ErrorContains(t, s.Validate(), "app_id")
}

// TestValidate_GitHubApp_InstallationIDRequired verifies that installation_id=0
// is rejected.
func TestValidate_GitHubApp_InstallationIDRequired(t *testing.T) {
	s := makeAppScope(t, func(s *Scope) { s.Auth.InstallationID = 0 })
	require.ErrorContains(t, s.Validate(), "installation_id")
}

// TestValidate_GitHubApp_PrivateKeyFileRequired verifies that an empty
// private_key_file is rejected.
func TestValidate_GitHubApp_PrivateKeyFileRequired(t *testing.T) {
	s := makeAppScope(t, func(s *Scope) { s.Auth.PrivateKeyFile = "" })
	require.ErrorContains(t, s.Validate(), "private_key_file")
}

// TestValidate_GitHubApp_PrivateKeyFileMustExist verifies that a non-existent
// private_key_file path is rejected.
func TestValidate_GitHubApp_PrivateKeyFileMustExist(t *testing.T) {
	s := makeAppScope(t, func(s *Scope) { s.Auth.PrivateKeyFile = "/nonexistent/key.pem" })
	require.Error(t, s.Validate())
}

// TestValidate_GitHubApp_PrivateKeyFileMode0400Required verifies that a key
// file with wrong permissions is rejected.
func TestValidate_GitHubApp_PrivateKeyFileMode0400Required(t *testing.T) {
	s := makeAppScope(t, nil)
	require.NoError(t, os.Chmod(s.Auth.PrivateKeyFile, 0o644))
	require.ErrorContains(t, s.Validate(), "mode 0400")
}

func TestValidate_GitHubApp_KubeSecretMode0440(t *testing.T) {
	s := makeAppScope(t, func(s *Scope) {
		s.Backend = "kube"
		require.NoError(t, os.Chmod(s.Auth.PrivateKeyFile, 0o440))
		s.Repos[0].ProjectDir = ""
	})
	require.NoError(t, s.Validate())
}

func sharedScope(t *testing.T, projects string) *Scope {
	t.Helper()
	s := makeScope(t, func(s *Scope) { s.Backend = "kube"; require.NoError(t, os.Chmod(s.Auth.PATFile, 0o440)) })
	require.NoError(t, yaml.Unmarshal([]byte("repos:\n"+projects), s))
	return s
}

const approvedProject = `  - repo: acme/alpha
    namespace: project-alpha
    max_concurrent: 2
    runner_config:
      runtime: node:24
      labels: [self-hosted, Linux, ARM64, container]
      resources: {memory: 2g, cpus: 2, pids: 256}
`

func TestSharedScopeApprovedConfig(t *testing.T) {
	s := sharedScope(t, approvedProject)
	require.NoError(t, s.Validate())
	b, err := yaml.Marshal(s.Repos[0])
	require.NoError(t, err)
	require.Contains(t, string(b), "kubernetes.io/arch: arm64")
	require.Contains(t, string(b), "ephemeral_storage: 10Gi")
}

func TestSharedScopeRejectsInvalidProjects(t *testing.T) {
	cases := map[string]string{
		"missing config":       strings.Replace(approvedProject, "    runner_config:", "    ignored_config:", 1),
		"reserved namespace":   strings.Replace(approvedProject, "project-alpha", "kube-system", 1),
		"controller namespace": strings.Replace(approvedProject, "project-alpha", "runsecure-test", 1),
		"invalid namespace":    strings.Replace(approvedProject, "project-alpha", "Bad/Space", 1),
		"invalid repo":         strings.Replace(approvedProject, "acme/alpha", "alpha", 1),
		"runtime":              strings.Replace(approvedProject, "node:24", "bogus:999", 1),
		"zero cpu":             strings.Replace(approvedProject, "cpus: 2", "cpus: 0", 1),
		"memory":               strings.Replace(approvedProject, "memory: 2g", "memory: 2gBAD", 1),
		"invalid label":        strings.Replace(approvedProject, "container]", "'bad label\n']", 1),
		"duplicate label":      strings.Replace(approvedProject, "container]", "container, container]", 1),
		"image":                approvedProject + "    runner_image: registry.example/runner:latest\n",
		"mixed namespaces":     approvedProject + "  - repo: acme/beta\n    max_concurrent: 1\n",
		"duplicate repo":       approvedProject + strings.Replace(approvedProject, "project-alpha", "project-beta", 1),
		"duplicate namespace":  approvedProject + strings.Replace(approvedProject, "acme/alpha", "acme/beta", 1),
		"disk":                 approvedProject + "    kubernetes: {ephemeral_storage: -1Gi}\n",
		"proxy cpu":            approvedProject + "    kubernetes: {proxy_resources: {cpu: \"0\"}}\n",
		"selector":             approvedProject + "    kubernetes: {node_selector: {'bad key': value}}\n",
		"architecture":         approvedProject + "    kubernetes: {node_selector: {kubernetes.io/arch: amd64}}\n",
		"toleration":           approvedProject + "    kubernetes: {tolerations: [{key: dedicated, operator: Bogus}]}\n",
	}
	for name, projects := range cases {
		t.Run(name, func(t *testing.T) { require.Error(t, sharedScope(t, projects).Validate()) })
	}
}

func TestSharedScopeAcceptsLongValidRepository(t *testing.T) {
	s := sharedScope(t, strings.Replace(approvedProject, "acme/alpha", "acme/"+strings.Repeat("a", 100), 1))
	require.NoError(t, s.Validate())
}

func TestSharedScopeValidationBoundaries(t *testing.T) {
	for name, mutate := range map[string]func(*Scope){
		"compose":                  func(s *Scope) { s.Backend = "compose"; require.NoError(t, os.Chmod(s.Auth.PATFile, 0o400)) },
		"invalid controller":       func(s *Scope) { s.Name = "Invalid_name" },
		"memory ceiling":           func(s *Scope) { s.Repos[0].RunnerConfig.Resources.Memory = "513g" },
		"memory overflow":          func(s *Scope) { s.Repos[0].RunnerConfig.Resources.Memory = "999999999999999999999999999999g" },
		"cpu ceiling":              func(s *Scope) { s.Repos[0].RunnerConfig.Resources.CPUs = 129 },
		"pids zero":                func(s *Scope) { s.Repos[0].RunnerConfig.Resources.PIDs = 0 },
		"labels empty":             func(s *Scope) { s.Repos[0].RunnerConfig.Labels = nil },
		"unsupported architecture": func(s *Scope) { s.Repos[0].RunnerConfig.Labels = []string{"ARM"} },
		"conflicting architecture": func(s *Scope) { s.Repos[0].RunnerConfig.Labels = []string{"X64", "ARM64"} },
		"seccomp":                  func(s *Scope) { s.Repos[0].RunnerConfig.Orchestrator.SeccompProfile = "custom.json" },
		"timeout":                  func(s *Scope) { s.Repos[0].RunnerConfig.Orchestrator.TimeoutSeconds = -1 },
		"egress":                   func(s *Scope) { s.Repos[0].RunnerConfig.HTTPEgress = []string{"bad;domain"} },
		"placement count": func(s *Scope) {
			s.Repos[0].Kubernetes.NodeSelector = map[string]string{}
			for i := 0; i < 17; i++ {
				s.Repos[0].Kubernetes.NodeSelector[fmt.Sprint(i)] = "ci"
			}
		},
		"unsupported node OS": func(s *Scope) { s.Repos[0].Kubernetes.NodeSelector = map[string]string{"kubernetes.io/os": "windows"} },
		"disk upper bound":    func(s *Scope) { s.Repos[0].Kubernetes.EphemeralStorage = "2Ti" },
		"malformed quantity":  func(s *Scope) { s.Repos[0].Kubernetes.ProxyResources.Memory = "garbage" },
	} {
		t.Run(name, func(t *testing.T) { s := sharedScope(t, approvedProject); mutate(s); require.Error(t, s.Validate()) })
	}
}

func TestSharedScopeMaximumBoundsAndTolerationDefaults(t *testing.T) {
	s := sharedScope(t, approvedProject)
	r := &s.Repos[0]
	r.RunnerConfig.Resources.Memory = "512g"
	r.RunnerConfig.Resources.CPUs = 128
	r.RunnerConfig.Resources.PIDs = 32768
	r.RunnerConfig.Labels = []string{"self-hosted", "X64", "Linux"}
	r.RunnerConfig.Orchestrator.TimeoutSeconds = 86400
	r.RunnerImage = "registry.example/runner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	seconds := int64(86400)
	r.Kubernetes = backend.KubePodSettings{NodeSelector: map[string]string{"kubernetes.io/arch": "amd64"}, EphemeralStorage: "1Ti", ProxyResources: backend.KubeProxyResources{CPU: "8", Memory: "8Gi", EphemeralStorage: "100Gi"}, Tolerations: []backend.KubeToleration{{Key: "dedicated", Value: "ci", Effect: "NoSchedule"}, {Key: "maintenance", Operator: "Exists", Effect: "NoExecute", TolerationSeconds: &seconds}}}
	require.NoError(t, s.Validate())
	require.Equal(t, "Equal", r.Kubernetes.Tolerations[0].Operator)
	require.Equal(t, "amd64", r.Kubernetes.NodeSelector["kubernetes.io/arch"])
	legacy := makeScope(t, nil)
	require.Nil(t, legacy.ProjectNamespaces())
}

func TestSharedScopeResolvesApprovedSecurityBeforeStartup(t *testing.T) {
	for name, mutate := range map[string]func(*Scope){
		"project override": func(s *Scope) {
			s.AllowProjectOverrides = []string{"allow_wildcards"}
			s.Repos[0].RunnerConfig.Orchestrator.SecurityOverrides = map[string]any{"allow_wildcards": 123}
		},
		"scope override": func(s *Scope) { s.SecurityOverrides = map[string]any{"allow_imds": "invalid"} },
	} {
		t.Run(name, func(t *testing.T) {
			s := sharedScope(t, approvedProject)
			mutate(s)
			require.ErrorContains(t, s.Validate(), "security")
		})
	}
	s := sharedScope(t, approvedProject)
	s.SecurityOverrides = map[string]any{"allow_imds": false}
	s.AllowProjectOverrides = []string{"allow_wildcards"}
	s.Repos[0].RunnerConfig.Orchestrator.SecurityOverrides = map[string]any{"allow_wildcards": []any{"*.example.org"}, "allow_kube_api": "unpermitted and ignored"}
	require.NoError(t, s.Validate())
	legacy := makeScope(t, nil)
	legacy.SecurityOverrides = map[string]any{"allow_imds": "deferred legacy validation"}
	require.NoError(t, legacy.Validate())
}

func TestSharedScopeChecksLiteralDestinationsWithEffectivePolicy(t *testing.T) {
	s := sharedScope(t, approvedProject)
	s.Repos[0].RunnerConfig.HTTPEgress = []string{"10.1.2.3"}
	require.ErrorContains(t, s.Validate(), "literal IP")
	s.SecurityOverrides = map[string]any{"allow_private_cidrs": []any{"10.0.0.0/8"}}
	require.NoError(t, s.Validate())
	s.Repos[0].RunnerConfig.TCPEgress = []string{"169.254.169.254:5432"}
	require.ErrorContains(t, s.Validate(), "literal IP")
	s.AllowProjectOverrides = []string{"allow_private_cidrs"}
	s.Repos[0].RunnerConfig.Orchestrator.SecurityOverrides = map[string]any{"allow_private_cidrs": []any{"10.0.0.0/8", "169.254.169.254/32"}}
	require.NoError(t, s.Validate(), "scope-authorized project exceptions use resolved effective policy")
}

func TestSharedScopeSelectorLimitUsesNormalizedTotalAndIsIdempotent(t *testing.T) {
	for _, customCount := range []int{13, 14, 15, 16} {
		for _, mandatoryCount := range []int{0, 1, 2} {
			t.Run(fmt.Sprintf("custom-%d-explicit-mandatory-%d", customCount, mandatoryCount), func(t *testing.T) {
				s := sharedScope(t, approvedProject)
				selectors := map[string]string{}
				for i := 0; i < customCount; i++ {
					selectors[fmt.Sprintf("custom-%d", i)] = "ci"
				}
				if mandatoryCount >= 1 {
					selectors["kubernetes.io/arch"] = "arm64"
				}
				if mandatoryCount >= 2 {
					selectors["kubernetes.io/os"] = "linux"
				}
				s.Repos[0].Kubernetes.NodeSelector = selectors
				if customCount > 14 {
					require.ErrorContains(t, s.Validate(), "placement exceeds 16")
					require.ErrorContains(t, s.Validate(), "placement exceeds 16")
					return
				}
				require.NoError(t, s.Validate())
				require.Len(t, selectors, customCount+2)
				normalized, err := yaml.Marshal(s)
				require.NoError(t, err)
				require.NoError(t, s.Validate())
				repeated, err := yaml.Marshal(s)
				require.NoError(t, err)
				require.Equal(t, string(normalized), string(repeated), "accepted scope normalization must be idempotent")
			})
		}
	}
}

func TestSharedSettingsRequireNamespaceEnrollment(t *testing.T) {
	for _, declaration := range []string{
		"runner_config: {runtime: node:24, labels: [container], resources: {memory: 1g, cpus: 1, pids: 256}}",
		"runner_image: registry.example/runner@sha256:" + strings.Repeat("a", 64),
		"kubernetes: {ephemeral_storage: 20Gi}",
		"runner_config: null", "runner_image: ''", "kubernetes: {}",
		"<<: {kubernetes: {}}",
	} {
		t.Run(declaration, func(t *testing.T) {
			s := sharedScope(t, "  - repo: acme/alpha\n    max_concurrent: 1\n    "+declaration+"\n")
			require.ErrorContains(t, s.Validate(), "namespace")
		})
	}
	legacy := sharedScope(t, "  - repo: acme/alpha\n    max_concurrent: 1\n")
	require.NoError(t, legacy.Validate())
	require.False(t, legacy.SharedKubernetes())
}

func TestRepoBlockRejectsInvalidFieldTypes(t *testing.T) {
	var repo RepoBlock
	require.Error(t, yaml.Unmarshal([]byte("kubernetes: invalid"), &repo))
	require.Error(t, yaml.Unmarshal([]byte("max_concurrent: invalid"), &repo))
}
