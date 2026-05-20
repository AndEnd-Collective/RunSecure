# Socket-proxy security tests

Each script starts a standalone socket-proxy container against a mounted
docker socket (read-only) and verifies the refuse rules from spec §7.2
empirically. These are deliberately small and focused — the in-process
fuzz/unit tests cover the body validator exhaustively; these scripts
verify the wire-level behavior of the actual running binary.
