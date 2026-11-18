// REQ: FLT-006, API-010 (T24.30, ADR-996) — the words for where a device's group came from and
// which key matched it, shared by the Policy panel, the Flow page and Explain.

export const groupFromText: Record<string, string> = {
  device: "the device's own groups",
  network: 'its network',
  router_name: 'a name its router gave it',
  kubernetes: 'its Kubernetes workload',
  default: 'no network or device names a group: the default',
};

export const matchedByText: Record<string, string> = {
  client_id: 'client ID',
  edns_mac: 'MAC in the query',
  neighbor_mac: 'MAC',
  kubernetes: 'Kubernetes workload',
  ip: 'address',
  cidr: 'network',
  router_name: 'router name',
  default: 'nothing: the default group',
};
