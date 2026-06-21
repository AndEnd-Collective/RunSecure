// export_test.go exposes internal hooks for white-box testing.
// This file is compiled only during `go test`.
package auth

// ReadFile allows tests to inject a failing ReadFile implementation so the
// os.ReadFile error branch in NewPATProvider can be exercised without OS-level
// tricks (e.g. root-owned files or kernel mocks).
var ReadFile = &osReadFile
