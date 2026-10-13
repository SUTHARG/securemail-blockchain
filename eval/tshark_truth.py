"""tshark Ground-Truth Extractor for SecureMailScope.

Given an email traffic PCAP, runs tshark and writes a JSON ground-truth file
containing, per TCP connection identified by (client endpoint, server endpoint, first frame number):
  - reassembled client and server byte streams (tshark -z follow,tcp,raw,<stream>)
  - SMTP commands and reply codes seen
  - TLS parameters:
      - handshake type list
      - ClientHello legacy version
      - supported_versions values
      - offered cipher suite codes
      - SNI
      - ServerHello selected cipher and version
      - JA3 and JA3S fingerprints (if exposed by installed tshark)
      - certificate fingerprints (SHA-256)
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def get_tshark_runner() -> Tuple[List[str], str]:
    """Finds tshark in host PATH or falls back to WSL tshark, and returns runner cmd and version."""
    if shutil.which("tshark"):
        cmd = ["tshark"]
    elif shutil.which("wsl"):
        res = subprocess.run(["wsl", "-d", "Ubuntu", "which", "tshark"], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip():
            cmd = ["wsl", "-d", "Ubuntu", "tshark"]
        else:
            raise FileNotFoundError("tshark is neither installed on host nor in WSL Ubuntu")
    else:
        raise FileNotFoundError("tshark could not be found")

    v_res = subprocess.run(cmd + ["-v"], capture_output=True, text=True, check=True)
    first_line = v_res.stdout.splitlines()[0] if v_res.stdout else "Unknown tshark version"
    return cmd, first_line


def to_runner_path(runner_cmd: List[str], p: Path) -> str:
    """Converts a Path to a path accessible by the runner (e.g. /mnt/c/... for WSL)."""
    abs_path = p.resolve()
    if "wsl" in runner_cmd:
        drive = abs_path.drive.lower().replace(":", "")
        parts = [p_part for p_part in abs_path.parts[1:]]
        posix_rel = "/".join(parts)
        return f"/mnt/{drive}/{posix_rel}"
    return str(abs_path)


def format_endpoint(ip: str, port: str) -> str:
    """Formats endpoint according to docs/decisions/001-hashing-and-ids.md."""
    if ":" in ip:
        # IPv6
        return f"[{ip.lower()}]:{port}"
    return f"{ip}:{port}"


def extract_tcp_streams(runner: List[str], pcap_str: str) -> List[Dict[str, Any]]:
    """Discovers all TCP streams in the capture."""
    cmd = runner + [
        "-r", pcap_str,
        "-T", "fields",
        "-e", "tcp.stream",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ipv6.src",
        "-e", "ipv6.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    streams: Dict[int, Dict[str, Any]] = {}

    for line in res.stdout.splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 10 or not parts[0]:
            continue
        try:
            stream_idx = int(parts[0])
            frame_no = int(parts[1])
        except ValueError:
            continue

        ip_src = parts[2] if parts[2] else parts[4]
        ip_dst = parts[3] if parts[3] else parts[5]
        sport = parts[6]
        dport = parts[7]
        syn = parts[8].strip().lower() in ("1", "true")
        ack = parts[9].strip().lower() in ("1", "true")

        if stream_idx not in streams:
            streams[stream_idx] = {
                "streamIndex": stream_idx,
                "firstFrame": frame_no,
                "firstSender": (ip_src, sport),
                "firstReceiver": (ip_dst, dport),
                "synClient": None,
                "synServer": None,
            }

        # First SYN without ACK identifies client
        if syn and not ack and streams[stream_idx]["synClient"] is None:
            streams[stream_idx]["synClient"] = (ip_src, sport)
            streams[stream_idx]["synServer"] = (ip_dst, dport)

    results = []
    for s_idx, data in sorted(streams.items()):
        if data["synClient"]:
            c_ip, c_port = data["synClient"]
            s_ip, s_port = data["synServer"]
            client_inferred = False
        else:
            c_ip, c_port = data["firstSender"]
            s_ip, s_port = data["firstReceiver"]
            client_inferred = True

        results.append({
            "streamIndex": s_idx,
            "firstFrame": data["firstFrame"],
            "clientEndpoint": format_endpoint(c_ip, c_port),
            "serverEndpoint": format_endpoint(s_ip, s_port),
            "clientInferred": client_inferred,
        })
    return results


def extract_stream_payloads(runner: List[str], pcap_str: str, stream_idx: int) -> Tuple[str, str]:
    """Reassembles client and server raw byte streams via follow,tcp,raw."""
    cmd = runner + ["-r", pcap_str, "-q", "-z", f"follow,tcp,raw,{stream_idx}"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)

    client_hex_parts = []
    server_hex_parts = []
    in_follow = False
    hex_pattern = re.compile(r"^[0-9a-fA-F]+$")

    for line in res.stdout.splitlines():
        if "Follow: tcp,raw" in line:
            in_follow = True
            continue
        if not in_follow:
            continue
        if line.startswith("===") or line.startswith("Node 0:") or line.startswith("Node 1:") or line.startswith("Filter:"):
            continue

        stripped = line.strip()
        if not hex_pattern.match(stripped):
            continue

        if line.startswith("\t"):
            server_hex_parts.append(stripped)
        else:
            client_hex_parts.append(stripped)

    return "".join(client_hex_parts), "".join(server_hex_parts)


def extract_smtp_info(runner: List[str], pcap_str: str, stream_idx: int) -> Dict[str, Any]:
    """Extracts SMTP commands and reply codes for a stream."""
    cmd = runner + [
        "-r", pcap_str,
        "-Y", f"tcp.stream eq {stream_idx} && smtp",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "smtp.req.command",
        "-e", "smtp.req.parameter",
        "-e", "smtp.response.code",
        "-e", "smtp.rsp.parameter",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)

    commands = []
    reply_codes = []

    for line in res.stdout.splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 2:
            continue
        req_cmd = parts[1] if len(parts) > 1 and parts[1] else None
        req_param = parts[2] if len(parts) > 2 and parts[2] else None
        resp_code = parts[3] if len(parts) > 3 and parts[3] else None

        if req_cmd:
            full_cmd = f"{req_cmd} {req_param}".strip() if req_param else req_cmd
            commands.append(full_cmd)

        if resp_code:
            for code_str in resp_code.split(","):
                try:
                    reply_codes.append(int(code_str))
                except ValueError:
                    pass

    return {
        "commands": commands,
        "replyCodes": reply_codes,
    }


def extract_tls_info(runner: List[str], pcap_str: str, stream_idx: int) -> Dict[str, Any]:
    """Extracts TLS parameters, fingerprints, and certificate information for a stream."""
    cmd = runner + [
        "-r", pcap_str,
        "-Y", f"tcp.stream eq {stream_idx} && tls",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "tls.handshake.type",
        "-e", "tls.handshake.version",
        "-e", "tls.handshake.extensions.supported_version",
        "-e", "tls.handshake.ciphersuite",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "tls.handshake.ja3",
        "-e", "tls.handshake.ja3s",
        "-e", "tls.handshake.certificate",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)

    handshake_types = []
    client_hello_version = None
    supported_versions = []
    offered_ciphers = []
    selected_cipher = None
    selected_version = None
    sni = None
    ja3 = None
    ja3s = None
    cert_fingerprints = []

    for line in res.stdout.splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 2:
            continue

        types_in_frame = []
        if len(parts) > 1 and parts[1]:
            for t in parts[1].split(","):
                try:
                    t_val = int(t)
                    types_in_frame.append(t_val)
                    if t_val not in handshake_types:
                        handshake_types.append(t_val)
                except ValueError:
                    pass

        # ClientHello (type 1)
        if 1 in types_in_frame:
            if len(parts) > 2 and parts[2] and not client_hello_version:
                client_hello_version = parts[2].split(",")[0]
            if len(parts) > 3 and parts[3]:
                for sv in parts[3].split(","):
                    if sv and sv not in supported_versions:
                        supported_versions.append(sv)
            if len(parts) > 4 and parts[4] and not offered_ciphers:
                for c in parts[4].split(","):
                    try:
                        c_code = int(c, 16) if c.startswith("0x") else int(c)
                        offered_ciphers.append(c_code)
                    except ValueError:
                        pass
            if len(parts) > 5 and parts[5] and not sni:
                sni = parts[5].split(",")[0]
            if len(parts) > 6 and parts[6] and not ja3:
                ja3 = parts[6].split(",")[0]

        # ServerHello (type 2)
        if 2 in types_in_frame:
            # Under RFC 8446 Section 4.2.1, if supported_versions extension is present in ServerHello,
            # that is the true negotiated version (the legacy tls.handshake.version is locked to 0x0303).
            if len(parts) > 3 and parts[3] and not selected_version:
                selected_version = parts[3].split(",")[0]
            elif len(parts) > 2 and parts[2] and not selected_version:
                selected_version = parts[2].split(",")[0]
            if len(parts) > 4 and parts[4] and not selected_cipher:
                sc_str = parts[4].split(",")[0]
                try:
                    selected_cipher = int(sc_str, 16) if sc_str.startswith("0x") else int(sc_str)
                except ValueError:
                    selected_cipher = sc_str
            if len(parts) > 7 and parts[7] and not ja3s:
                ja3s = parts[7].split(",")[0]

        # Certificate blobs
        if len(parts) > 8 and parts[8]:
            for cert_hex in parts[8].split(","):
                clean_hex = cert_hex.replace(":", "").strip()
                if clean_hex:
                    try:
                        cert_bytes = bytes.fromhex(clean_hex)
                        fp = hashlib.sha256(cert_bytes).hexdigest()
                        if fp not in cert_fingerprints:
                            cert_fingerprints.append(fp)
                    except ValueError:
                        pass

    return {
        "handshakeTypes": handshake_types,
        "clientHelloVersion": client_hello_version,
        "supportedVersions": supported_versions,
        "offeredCiphers": offered_ciphers,
        "sni": sni,
        "selectedCipher": selected_cipher,
        "selectedVersion": selected_version,
        "ja3": ja3,
        "ja3s": ja3s,
        "certFingerprints": cert_fingerprints,
    }


def extract_truth(pcap_path: Path) -> Dict[str, Any]:
    """Extracts complete tshark ground truth for a PCAP file."""
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    runner, tshark_version = get_tshark_runner()
    pcap_str = to_runner_path(runner, pcap_path)

    tcp_streams = extract_tcp_streams(runner, pcap_str)
    connections: Dict[str, Any] = {}

    for s in tcp_streams:
        s_idx = s["streamIndex"]
        first_frame = s["firstFrame"]
        c_ep = s["clientEndpoint"]
        s_ep = s["serverEndpoint"]

        conn_key = f"{c_ep}->{s_ep}#{first_frame}"

        c_hex, s_hex = extract_stream_payloads(runner, pcap_str, s_idx)
        smtp_data = extract_smtp_info(runner, pcap_str, s_idx)
        tls_data = extract_tls_info(runner, pcap_str, s_idx)

        connections[conn_key] = {
            "clientEndpoint": c_ep,
            "serverEndpoint": s_ep,
            "firstFrame": first_frame,
            "clientInferred": s["clientInferred"],
            "clientBytesHex": c_hex,
            "serverBytesHex": s_hex,
            "smtp": smtp_data,
            "tls": tls_data,
        }

    return {
        "metadata": {
            "pcapFile": pcap_path.name,
            "pcapSha256": hashlib.sha256(pcap_path.read_bytes()).hexdigest(),
            "tsharkVersion": tshark_version,
            "connectionCount": len(connections),
        },
        "connections": connections,
    }


def main():
    parser = argparse.ArgumentParser(description="Extract tshark ground-truth JSON for email PCAP")
    parser.add_argument("pcap", type=str, help="Path to PCAP file")
    parser.add_argument("--out", type=str, default=None, help="Output JSON path")
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    truth = extract_truth(pcap_path)

    if args.out:
        out_path = Path(args.out)
    else:
        repo_root = Path(__file__).resolve().parents[1]
        out_path = repo_root / "eval" / "truth" / f"{pcap_path.stem}.json"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(truth, f, indent=2)

    print(f"[+] Ground-truth written to: {out_path}")
    print(f"    Total connections: {truth['metadata']['connectionCount']}")
    print(f"    tshark version: {truth['metadata']['tsharkVersion']}")


if __name__ == "__main__":
    main()
