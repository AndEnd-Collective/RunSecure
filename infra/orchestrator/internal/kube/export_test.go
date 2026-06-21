// export_test.go exposes internal hooks for white-box testing.
// This file is compiled only during `go test`.
package kube

// InClusterConfig allows tests to inject a replacement for rest.InClusterConfig
// so the error and success branches of NewInCluster can be exercised without a
// real Kubernetes cluster. The pointer indirection mirrors the pattern used in
// internal/auth/export_test.go.
var InClusterConfig = &inClusterConfig

// NewForConfig allows tests to inject a replacement for kubernetes.NewForConfig
// so the clientset-construction error branch of NewInCluster can be covered.
var NewForConfig = &newForConfig
