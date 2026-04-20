import ipaddress
import json
import os
import socket
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Tuple


PORT = int(os.getenv("PORT", "5000"))
MY_IP = os.getenv("MY_IP", "127.0.0.1").strip()
ROUTER_ID = os.getenv("ROUTER_ID", MY_IP).strip() or MY_IP
NEIGHBORS = [n.strip() for n in os.getenv("NEIGHBORS", "").split(",") if n.strip()]
DIRECT_SUBNETS_ENV = [s.strip() for s in os.getenv("DIRECT_SUBNETS", "").split(",") if s.strip()]

VERSION = 1.0
INFINITY = int(os.getenv("INFINITY", "16"))
UPDATE_INTERVAL = float(os.getenv("UPDATE_INTERVAL", "5"))
ROUTE_TIMEOUT = float(os.getenv("ROUTE_TIMEOUT", "15"))
GARBAGE_TIMEOUT = float(os.getenv("GARBAGE_TIMEOUT", "30"))
TRIGGERED_MIN_INTERVAL = float(os.getenv("TRIGGERED_MIN_INTERVAL", "1"))


# routing_table[subnet] = {
#   "distance": int,
#   "next_hop": str,
#   "learned_from": str,
#   "last_updated": float,
#   "is_direct": bool,
#   "invalid_since": Optional[float],
# }
routing_table: Dict[str, Dict[str, Any]] = {}
neighbor_last_seen: Dict[str, float] = {}

lock = threading.Lock()
route_changed_event = threading.Event()


def log(message: str) -> None:
    """Print a timestamped log message to stdout."""
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def run_command(args: List[str]) -> Tuple[int, str]:
    """Run a shell command and return its exit code and combined output."""
    try:
        result = subprocess.run(args, check=False, capture_output=True, text=True)
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode, output.strip()
    except Exception as exc:
        return 1, str(exc)


def valid_subnet(subnet: str) -> bool:
    """Return True when a subnet string is valid CIDR notation."""
    try:
        ipaddress.ip_network(subnet, strict=False)
        return True
    except ValueError:
        return False


def discover_direct_subnets() -> List[str]:
    """Discover directly connected IPv4 subnets from env or local interfaces."""
    if DIRECT_SUBNETS_ENV:
        subnets: List[str] = []
        for subnet in DIRECT_SUBNETS_ENV:
            if valid_subnet(subnet):
                subnets.append(str(ipaddress.ip_network(subnet, strict=False)))
            else:
                log(f"Skipping invalid DIRECT_SUBNETS entry: {subnet}")
        return sorted(set(subnets))

    code, output = run_command(["ip", "-o", "-4", "addr", "show", "scope", "global"])
    if code != 0:
        log(f"Could not discover direct subnets via ip command: {output}")
        return []

    subnets = set()
    for line in output.splitlines():
        parts = line.split()
        if "inet" not in parts:
            continue
        idx = parts.index("inet")
        if idx + 1 >= len(parts):
            continue
        cidr = parts[idx + 1]
        try:
            network = ipaddress.ip_interface(cidr).network
            subnets.add(str(network))
        except ValueError:
            continue

    return sorted(subnets)


def bootstrap_direct_routes() -> None:
    """Initialize routing table entries for directly connected subnets."""
    now = time.time()
    direct_subnets = discover_direct_subnets()
    if not direct_subnets:
        log("No direct subnets detected. Set DIRECT_SUBNETS env var if needed.")

    with lock:
        for subnet in direct_subnets:
            routing_table[subnet] = {
                "distance": 0,
                "next_hop": "0.0.0.0",
                "learned_from": "self",
                "last_updated": now,
                "is_direct": True,
                "invalid_since": None,
            }

    if direct_subnets:
        log(f"Direct subnets: {', '.join(direct_subnets)}")
    print_routing_table()


def build_packet_for_neighbor(target_neighbor: str) -> bytes:
    """Build a DV-JSON update packet filtered by split horizon for one neighbor."""
    routes_payload = []
    with lock:
        for subnet, entry in routing_table.items():
            advertised_distance = entry["distance"]

            # Split horizon: do not advertise a route back to where it was learned.
            if not entry["is_direct"] and entry["learned_from"] == target_neighbor:
                continue

            if advertised_distance < INFINITY:
                routes_payload.append(
                    {
                        "subnet": subnet,
                        "distance": int(min(INFINITY, advertised_distance)),
                    }
                )

    packet = {
        "router_id": ROUTER_ID,
        "version": VERSION,
        "routes": routes_payload,
    }
    return json.dumps(packet, separators=(",", ":")).encode("utf-8")


def sync_kernel_route(subnet: str, new_entry: Optional[Dict[str, Any]], old_entry: Optional[Dict[str, Any]]) -> None:
    """Apply route add/replace/delete operations to the Linux kernel table."""
    if new_entry and new_entry["is_direct"]:
        return

    if new_entry is None or new_entry["distance"] >= INFINITY:
        if old_entry and not old_entry.get("is_direct", False):
            old_hop = old_entry.get("next_hop")
            if old_hop and old_hop != "0.0.0.0":
                run_command(["ip", "route", "del", subnet, "via", old_hop])
            run_command(["ip", "route", "del", subnet])
        return

    new_hop = new_entry["next_hop"]
    code, output = run_command(["ip", "route", "replace", subnet, "via", new_hop])
    if code != 0:
        log(f"Failed to apply route {subnet} via {new_hop}: {output}")


def update_logic(neighbor_ip: str, routes_from_neighbor: List[Dict[str, Any]]) -> bool:
    """Process a neighbor update and apply Bellman-Ford table changes."""
    now = time.time()
    changed = False
    kernel_ops: List[Tuple[str, Optional[Dict[str, Any]], Optional[Dict[str, Any]]]] = []

    with lock:
        neighbor_last_seen[neighbor_ip] = now

        for route in routes_from_neighbor:
            subnet = str(route.get("subnet", "")).strip()
            if not valid_subnet(subnet):
                continue
            subnet = str(ipaddress.ip_network(subnet, strict=False))

            try:
                neighbor_distance = int(route.get("distance"))
            except (TypeError, ValueError):
                continue

            new_distance = min(INFINITY, max(0, neighbor_distance) + 1)

            existing = routing_table.get(subnet)
            if existing and existing["is_direct"]:
                continue

            if existing is None:
                if new_distance >= INFINITY:
                    continue
                new_entry = {
                    "distance": new_distance,
                    "next_hop": neighbor_ip,
                    "learned_from": neighbor_ip,
                    "last_updated": now,
                    "is_direct": False,
                    "invalid_since": None,
                }
                routing_table[subnet] = new_entry
                changed = True
                kernel_ops.append((subnet, dict(new_entry), None))
                continue

            should_update = False
            if new_distance < existing["distance"]:
                should_update = True
            elif existing["learned_from"] == neighbor_ip and new_distance != existing["distance"]:
                should_update = True

            if should_update:
                old_entry = dict(existing)
                existing["distance"] = new_distance
                existing["next_hop"] = neighbor_ip
                existing["learned_from"] = neighbor_ip
                existing["last_updated"] = now
                existing["invalid_since"] = now if new_distance >= INFINITY else None
                changed = True
                kernel_ops.append((subnet, dict(existing), old_entry))

    for subnet, new_entry, old_entry in kernel_ops:
        sync_kernel_route(subnet, new_entry, old_entry)

    if changed:
        route_changed_event.set()

    return changed


def parse_packet(payload: bytes, sender_addr: Tuple[str, int]) -> Optional[Tuple[str, List[Dict[str, Any]]]]:
    """Parse and validate an incoming DV-JSON packet from UDP payload bytes."""
    try:
        message = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

    if not isinstance(message, dict):
        return None

    version = message.get("version")
    try:
        if float(version) != VERSION:
            return None
    except (TypeError, ValueError):
        return None

    routes = message.get("routes")
    if not isinstance(routes, list):
        return None

    router_id = str(message.get("router_id", "")).strip()
    if router_id:
        try:
            ipaddress.ip_address(router_id)
        except ValueError:
            pass

    # In multi-interface routers, sender_addr[0] is the reachable interface
    # and therefore the safe next-hop for kernel route updates.
    neighbor_ip = sender_addr[0]

    return neighbor_ip, routes


def broadcast_updates() -> None:
    """Send periodic or triggered routing updates to all configured neighbors."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    last_sent = 0.0

    while True:
        # Wait for either periodic timer or a triggered table change.
        triggered = route_changed_event.wait(timeout=UPDATE_INTERVAL)
        if triggered:
            route_changed_event.clear()
            elapsed = time.monotonic() - last_sent
            if elapsed < TRIGGERED_MIN_INTERVAL:
                time.sleep(TRIGGERED_MIN_INTERVAL - elapsed)

        for neighbor in NEIGHBORS:
            packet = build_packet_for_neighbor(neighbor)
            try:
                sock.sendto(packet, (neighbor, PORT))
            except OSError as exc:
                log(f"Send failed to {neighbor}:{PORT} - {exc}")

        last_sent = time.monotonic()


def timeout_manager() -> None:
    """Invalidate and garbage-collect stale learned routes based on timers."""
    while True:
        now = time.time()
        changed = False
        kernel_ops: List[Tuple[str, Optional[Dict[str, Any]], Optional[Dict[str, Any]]]] = []

        with lock:
            for subnet, entry in list(routing_table.items()):
                if entry["is_direct"]:
                    continue

                age = now - entry["last_updated"]
                if entry["distance"] < INFINITY and age > ROUTE_TIMEOUT:
                    old_entry = dict(entry)
                    entry["distance"] = INFINITY
                    entry["invalid_since"] = now
                    changed = True
                    kernel_ops.append((subnet, dict(entry), old_entry))

                invalid_since = entry.get("invalid_since")
                if invalid_since is not None and (now - invalid_since) > GARBAGE_TIMEOUT:
                    old_entry = dict(entry)
                    del routing_table[subnet]
                    changed = True
                    kernel_ops.append((subnet, None, old_entry))

        for subnet, new_entry, old_entry in kernel_ops:
            sync_kernel_route(subnet, new_entry, old_entry)

        if changed:
            route_changed_event.set()

        time.sleep(1)


def listen_for_updates() -> None:
    """Listen for UDP routing updates and apply route recomputation."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", PORT))
    log(f"Listening on UDP {PORT}; neighbors: {NEIGHBORS}")

    while True:
        payload, addr = sock.recvfrom(65535)
        parsed = parse_packet(payload, addr)
        if parsed is None:
            continue

        neighbor_ip, routes = parsed
        changed = update_logic(neighbor_ip, routes)
        if changed:
            log(f"Updated routes from {neighbor_ip}")
            print_routing_table()


def print_routing_table() -> None:
    """Print the current routing table in a readable log format."""
    with lock:
        rows = []
        for subnet, entry in sorted(routing_table.items()):
            rows.append(
                f"{subnet:18} dist={entry['distance']:2} "
                f"next={entry['next_hop']:15} direct={entry['is_direct']}"
            )

    log("Routing table:\n" + ("\n".join(rows) if rows else "(empty)"))


def main() -> None:
    """Start router workers and enter the UDP receive loop."""
    log(f"Router starting: ROUTER_ID={ROUTER_ID} MY_IP={MY_IP}")
    bootstrap_direct_routes()

    threading.Thread(target=broadcast_updates, daemon=True).start()
    threading.Thread(target=timeout_manager, daemon=True).start()

    listen_for_updates()


if __name__ == "__main__":
    main()
