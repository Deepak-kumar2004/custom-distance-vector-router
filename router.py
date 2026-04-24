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
neighbor_routes: Dict[str, Dict[str, int]] = {}

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
        direct_subnets: List[str] = []
        for subnet in DIRECT_SUBNETS_ENV:
            if valid_subnet(subnet):
                direct_subnets.append(str(ipaddress.ip_network(subnet, strict=False)))
            else:
                log(f"Skipping invalid DIRECT_SUBNETS entry: {subnet}")
        return sorted(set(direct_subnets))

    code, output = run_command(["ip", "-o", "-4", "addr", "show", "scope", "global"])
    if code != 0:
        log(f"Could not discover direct subnets via ip command: {output}")
        return []

    discovered_subnets: set[str] = set()
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
            discovered_subnets.add(str(network))
        except ValueError:
            continue

    return sorted(discovered_subnets)


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
        return

    new_hop = new_entry["next_hop"]
    code, output = run_command(["ip", "route", "replace", subnet, "via", new_hop])
    if code != 0:
        log(f"Failed to apply route {subnet} via {new_hop}: {output}")


def route_signature(entry: Optional[Dict[str, Any]]) -> Optional[Tuple[int, str, str, bool]]:
    """Return the stable fields used to detect meaningful route changes."""
    if entry is None:
        return None
    return (
        int(entry["distance"]),
        str(entry["next_hop"]),
        str(entry["learned_from"]),
        bool(entry["is_direct"]),
    )


def recompute_routes_locked() -> Tuple[bool, List[Tuple[str, Optional[Dict[str, Any]], Optional[Dict[str, Any]]]]]:
    """Rebuild best routes from current direct links and live neighbor state."""
    now = time.time()
    old_table = {subnet: dict(entry) for subnet, entry in routing_table.items()}

    new_table: Dict[str, Dict[str, Any]] = {}
    for subnet in discover_direct_subnets():
        old_direct = old_table.get(subnet)
        last_updated = now
        if old_direct and old_direct.get("is_direct"):
            last_updated = float(old_direct.get("last_updated", now))

        new_table[subnet] = {
            "distance": 0,
            "next_hop": "0.0.0.0",
            "learned_from": "self",
            "last_updated": last_updated,
            "is_direct": True,
            "invalid_since": None,
        }

    stale_neighbors = [
        neighbor_ip
        for neighbor_ip, last_seen in neighbor_last_seen.items()
        if (now - last_seen) > GARBAGE_TIMEOUT
    ]
    for neighbor_ip in stale_neighbors:
        neighbor_last_seen.pop(neighbor_ip, None)
        neighbor_routes.pop(neighbor_ip, None)

    for neighbor_ip, advertised in neighbor_routes.items():
        last_seen = neighbor_last_seen.get(neighbor_ip, 0.0)
        if (now - last_seen) > ROUTE_TIMEOUT:
            continue

        for subnet, neighbor_distance in advertised.items():
            if subnet in new_table:
                continue

            candidate = min(INFINITY, max(0, neighbor_distance) + 1)
            if candidate >= INFINITY:
                continue

            current = new_table.get(subnet)
            if current is None:
                old_entry = old_table.get(subnet)
                last_updated = now
                if old_entry and not old_entry.get("is_direct"):
                    if old_entry.get("next_hop") == neighbor_ip and int(old_entry.get("distance", INFINITY)) == candidate:
                        last_updated = float(old_entry.get("last_updated", now))

                new_table[subnet] = {
                    "distance": candidate,
                    "next_hop": neighbor_ip,
                    "learned_from": neighbor_ip,
                    "last_updated": last_updated,
                    "is_direct": False,
                    "invalid_since": None,
                }
                continue

            better_distance = candidate < int(current["distance"])
            same_distance_better_tie = candidate == int(current["distance"]) and neighbor_ip < str(current["next_hop"])
            if better_distance or same_distance_better_tie:
                new_table[subnet] = {
                    "distance": candidate,
                    "next_hop": neighbor_ip,
                    "learned_from": neighbor_ip,
                    "last_updated": now,
                    "is_direct": False,
                    "invalid_since": None,
                }

    kernel_ops: List[Tuple[str, Optional[Dict[str, Any]], Optional[Dict[str, Any]]]] = []
    changed = False
    for subnet in sorted(set(old_table.keys()) | set(new_table.keys())):
        old_entry = old_table.get(subnet)
        new_entry = new_table.get(subnet)
        if route_signature(old_entry) != route_signature(new_entry):
            changed = True
            kernel_ops.append((subnet, dict(new_entry) if new_entry else None, dict(old_entry) if old_entry else None))

    routing_table.clear()
    routing_table.update(new_table)
    return changed, kernel_ops


def recompute_routes() -> bool:
    """Recompute routes and synchronize kernel state for changed entries."""
    with lock:
        changed, kernel_ops = recompute_routes_locked()

    for subnet, new_entry, old_entry in kernel_ops:
        sync_kernel_route(subnet, new_entry, old_entry)

    if changed:
        route_changed_event.set()
    return changed


def update_logic(neighbor_ip: str, routes_from_neighbor: List[Dict[str, Any]]) -> bool:
    """Process a neighbor update and apply Bellman-Ford table changes."""
    with lock:
        neighbor_last_seen[neighbor_ip] = time.time()
        cleaned_routes: Dict[str, int] = {}
        for route in routes_from_neighbor:
            subnet = str(route.get("subnet", "")).strip()
            if not valid_subnet(subnet):
                continue
            subnet = str(ipaddress.ip_network(subnet, strict=False))

            try:
                neighbor_distance = int(route.get("distance"))
            except (TypeError, ValueError):
                continue
            cleaned_routes[subnet] = min(INFINITY, max(0, neighbor_distance))

        neighbor_routes[neighbor_ip] = cleaned_routes

    return recompute_routes()


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
        recompute_routes()
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
