package cornerstone

// Registry correlation is checked against project-local event records by tests.
var definitions = map[Kind]string{
	Kind("runsecure.socket_proxy.started"):          "a7020c64-9961-429c-891f-1972b367412e",
	Kind("runsecure.socket_proxy.request.denied"):   "a7b09d28-17cb-4227-b1ba-d8c68ccadf69",
	Kind("runsecure.socket_proxy.upstream.failed"):  "092ae181-28d5-477e-b331-19c35c6ac3d5",
	Kind("runsecure.socket_proxy.stopped"):          "b86d18a2-2b5b-4ada-aeee-c877955a6e3c",
	Kind("runsecure.socket_proxy.process.failed"):   "8ebbc7ca-ffc1-494a-8f53-63fe0835dc95",
	Kind("runsecure.socket_proxy.process.message"):  "89d13c9c-bd56-4a3a-b364-cd8830a0640c",
	Kind("runsecure.socket_proxy.telemetry.failed"): "af41ab2b-fab3-4ee5-a0f5-f30fb4a4c5d7",
}
