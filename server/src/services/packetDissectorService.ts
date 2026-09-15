/**
 * packetDissectorService.ts
 * =========================
 * Deep Packet Inspection (DPI) & Packet Frame Dissector.
 * Generates authentic packet sequences, protocol layer hierarchies,
 * and Wireshark-standard hex dumps for network flows.
 */

export interface IPacketFrame {
  frameNumber: number;
  offsetSeconds: number;
  timeFormatted: string;
  source: string;
  destination: string;
  direction: 'inbound' | 'outbound';
  protocol: string;
  flags?: string;
  length: number;
  ttl: number;
  winSize?: number;
  seq?: number;
  ack?: number;
  info: string;
  layers: string[];
  hexDump: string[];
  payloadAscii?: string;
}

export function formatHexDump(content: string): string[] {
  const buf = Buffer.from(content);
  const lines: string[] = [];
  for (let i = 0; i < buf.length; i += 16) {
    const chunk = buf.slice(i, i + 16);
    const hex = Array.from(chunk)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ');
    const ascii = Array.from(chunk)
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
      .join('');
    const offset = i.toString(16).padStart(4, '0');
    lines.push(`${offset}   ${hex.padEnd(48, ' ')}  ${ascii}`);
  }
  return lines;
}

export function generatePacketSequence(flow: {
  src: string;
  dst: string;
  proto: string;
  bytes: number;
  score: number;
}): IPacketFrame[] {
  const [srcIp, srcPortStr] = flow.src.split(':');
  const [dstIp, dstPortStr] = flow.dst.split(':');
  const srcPort = Number(srcPortStr) || 49152;
  const dstPort = Number(dstPortStr) || 80;
  const proto = (flow.proto || 'TCP').toUpperCase();

  const isSMB = dstPort === 445 || dstPort === 139;
  const isSSH = dstPort === 22;
  const isDNS = dstPort === 53 || proto === 'UDP';
  const isHTTP = dstPort === 80 || dstPort === 8080;
  const isHTTPS = dstPort === 443 || dstPort === 8443;
  const isScan = flow.score >= 0.45 && flow.bytes < 3500 && proto === 'TCP' && !isSMB;

  const packets: IPacketFrame[] = [];

  const addPacket = (
    frameNumber: number,
    offsetSeconds: number,
    dir: 'outbound' | 'inbound',
    flags: string,
    len: number,
    ttl: number,
    win: number,
    seq: number,
    ack: number,
    info: string,
    appLayerText: string,
    payloadSummary: string
  ) => {
    const source = dir === 'outbound' ? `${srcIp}:${srcPort}` : `${dstIp}:${dstPort}`;
    const destination = dir === 'outbound' ? `${dstIp}:${dstPort}` : `${srcIp}:${srcPort}`;

    const layers = [
      `Frame ${frameNumber}: ${len} bytes on wire (${len * 8} bits)`,
      `Ethernet II, Src: 02:42:ac:1f:45:1c, Dst: 02:42:ac:1f:00:02`,
      `Internet Protocol Version 4, Src: ${dir === 'outbound' ? srcIp : dstIp}, Dst: ${dir === 'outbound' ? dstIp : srcIp}, TTL: ${ttl}`,
      `${proto === 'TCP' ? 'Transmission Control Protocol' : 'User Datagram Protocol'}, Src Port: ${dir === 'outbound' ? srcPort : dstPort}, Dst Port: ${dir === 'outbound' ? dstPort : srcPort}${flags ? `, Flags: [${flags}]` : ''}`,
      appLayerText,
    ];

    const hexDump = formatHexDump(payloadSummary);

    packets.push({
      frameNumber,
      offsetSeconds: Number(offsetSeconds.toFixed(4)),
      timeFormatted: `+${offsetSeconds.toFixed(3)}s`,
      source,
      destination,
      direction: dir,
      protocol: isSMB ? 'SMB2' : isSSH ? 'SSHv2' : isDNS ? 'DNS' : isHTTP ? 'HTTP' : isHTTPS ? 'TLSv1.3' : proto,
      flags,
      length: len,
      ttl,
      winSize: win,
      seq,
      ack,
      info,
      layers,
      hexDump,
      payloadAscii: payloadSummary,
    });
  };

  if (isScan) {
    // Port Scanning sequence: SYN followed by RST, ACK or ICMP port unreachable
    addPacket(
      1,
      0.0,
      'outbound',
      'SYN',
      60,
      64,
      1024,
      1000,
      0,
      `[SYN] Seq=0 Win=1024 Len=0 MSS=1460 (Probe Scan)`,
      'TCP: Flag SYN probe without connection intent',
      `\x45\x00\x00\x3c\x1a\x2b\x40\x00\x40\x06\xb2\xa1${srcIp} -> ${dstIp} TCP SYN probe port ${dstPort}`
    );
    addPacket(
      2,
      0.0031,
      'inbound',
      'RST, ACK',
      54,
      128,
      0,
      0,
      1001,
      `[RST, ACK] Seq=1 Ack=1 Win=0 Len=0 (Port Closed / Filtered)`,
      'TCP: Target actively rejected probe with RST/ACK',
      `\x45\x00\x00\x36\x00\x01\x00\x00\x80\x06\x3f\x7b${dstIp} -> ${srcIp} TCP RST ACK closed port ${dstPort}`
    );
  } else if (isSMB) {
    // SMB Lateral Movement Sequence
    addPacket(1, 0.0, 'outbound', 'SYN', 60, 64, 64240, 100, 0, '[SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1', 'TCP: Connection establishment', `TCP SYN to SMB 445`);
    addPacket(2, 0.0024, 'inbound', 'SYN, ACK', 60, 128, 65535, 200, 101, '[SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460', 'TCP: Server handshake ack', `TCP SYN ACK from SMB 445`);
    addPacket(3, 0.0028, 'outbound', 'ACK', 52, 64, 64240, 101, 201, '[ACK] Seq=1 Ack=1 Win=64240 Len=0', 'TCP: Handshake completed', `TCP ACK 3-way handshake established`);
    addPacket(4, 0.0084, 'outbound', 'PSH, ACK', 188, 64, 64240, 101, 201, 'SMB2 Negotiate Protocol Request (Dialect: 0x0311)', 'Server Message Block 2: Negotiate Protocol Request', `\xfeSMB\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Negotiate Request: Dialect 3.1.1, Security Mode: Signing Enabled, Capabilities: DFS/Multi-channel`);
    addPacket(5, 0.0112, 'inbound', 'PSH, ACK', 264, 128, 65535, 201, 237, 'SMB2 Negotiate Protocol Response (Dialect: 0x0311, Capabilities: Multi-channel)', 'Server Message Block 2: Negotiate Protocol Response', `\xfeSMB\x00\x00\x00\x00\x01\x00\x00\x00Selected Dialect: 0x0311, Server GUID: {4a2e8810-77a4-4321-9988-123456789abc}, Auth: SPNEGO`);
    addPacket(6, 0.0189, 'outbound', 'PSH, ACK', 342, 64, 64240, 237, 413, 'SMB2 Session Setup Request, NTLMSSP_AUTH (User: Administrator)', 'Server Message Block 2: Session Setup Request', `\xfeSMB\x00\x00\x00\x00\x02\x00\x00\x00NTLMSSP_AUTH User: corp\\Administrator Workstation: fin-db-02 NTResponse: [32-byte hash]`);
    addPacket(7, 0.0245, 'inbound', 'PSH, ACK', 162, 128, 65535, 413, 527, 'SMB2 Session Setup Response (STATUS_SUCCESS, SessionId: 0x0041)', 'Server Message Block 2: Session Setup Response', `\xfeSMB\x00\x00\x00\x00\x03\x00\x00\x00Session Setup STATUS_SUCCESS SessionId: 0x0041002233445566`);
    addPacket(8, 0.0341, 'outbound', 'PSH, ACK', 148, 64, 64240, 527, 523, `SMB2 Tree Connect Request: \\\\${dstIp}\\ADMIN$`, 'Server Message Block 2: Tree Connect Request', `\xfeSMB\x00\x00\x00\x00\x04\x00\x00\x00Tree Connect Path: \\\\${dstIp}\\ADMIN$ (Privileged Share)`);
    addPacket(9, 0.0382, 'inbound', 'PSH, ACK', 124, 128, 65535, 523, 623, 'SMB2 Tree Connect Response (STATUS_SUCCESS, TreeId: 0x0001)', 'Server Message Block 2: Tree Connect Response', `\xfeSMB\x00\x00\x00\x00\x05\x00\x00\x00Tree Connect STATUS_SUCCESS TreeId: 0x0001 ShareType: Disk`);
    addPacket(10, 0.0512, 'outbound', 'PSH, ACK', 214, 64, 64240, 623, 595, 'SMB2 Create Request File: C$\\Windows\\System32\\cmd.exe', 'Server Message Block 2: Create Request (File Execution Precursor)', `\xfeSMB\x00\x00\x00\x00\x06\x00\x00\x00Create Request: C$\\Windows\\System32\\cmd.exe DesiredAccess: GENERIC_EXECUTE`);
  } else if (isSSH) {
    // SSH Lateral / Remote Access
    addPacket(1, 0.0, 'outbound', 'SYN', 60, 64, 64240, 100, 0, '[SYN] Seq=0 Win=64240 Len=0 MSS=1460', 'TCP: SSH connection setup', 'TCP SYN port 22');
    addPacket(2, 0.0034, 'inbound', 'SYN, ACK', 60, 128, 65535, 200, 101, '[SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0', 'TCP: Server handshake', 'TCP SYN ACK port 22');
    addPacket(3, 0.0038, 'outbound', 'ACK', 52, 64, 64240, 101, 201, '[ACK] Seq=1 Ack=1 Win=64240 Len=0', 'TCP: Handshake completed', 'TCP ACK port 22');
    addPacket(4, 0.0092, 'inbound', 'PSH, ACK', 98, 128, 65535, 201, 101, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5', 'Secure Shell Protocol: Banner exchange', 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n');
    addPacket(5, 0.0105, 'outbound', 'PSH, ACK', 92, 64, 64240, 101, 247, 'SSH-2.0-OpenSSH_8.9p1', 'Secure Shell Protocol: Client banner', 'SSH-2.0-OpenSSH_8.9p1\r\n');
    addPacket(6, 0.0182, 'outbound', 'PSH, ACK', 840, 64, 64240, 141, 247, 'Key Exchange Init (diffie-hellman-group-exchange-sha256)', 'Secure Shell Protocol: KEXINIT', 'SSH Key Exchange Init: Ciphers: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com');
  } else if (isDNS) {
    // DNS Query / Response
    addPacket(1, 0.0, 'outbound', '—', 78, 64, 0, 0, 0, 'Standard query 0x2a14 A corp-dc-01.internal', 'Domain Name System (query)', `DNS Query ID: 0x2a14 Opcode: Standard query (0) Name: corp-dc-01.internal Type: A (Host Address)`);
    addPacket(2, 0.0042, 'inbound', '—', 94, 128, 0, 0, 0, `Standard query response 0x2a14 A ${dstIp}`, 'Domain Name System (response)', `DNS Response ID: 0x2a14 Answers: corp-dc-01.internal: type A, class IN, addr ${dstIp} TTL: 300s`);
  } else if (isHTTP) {
    // HTTP C2 Beacon / Telemetry
    addPacket(1, 0.0, 'outbound', 'SYN', 60, 64, 64240, 100, 0, '[SYN] Seq=0 Win=64240 Len=0', 'TCP: HTTP connection setup', 'TCP SYN port 8080');
    addPacket(2, 0.012, 'inbound', 'SYN, ACK', 60, 128, 29200, 200, 101, '[SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0', 'TCP: Server ack', 'TCP SYN ACK port 8080');
    addPacket(3, 0.0125, 'outbound', 'ACK', 52, 64, 64240, 101, 201, '[ACK] Seq=1 Ack=1 Win=64240 Len=0', 'TCP: Handshake completed', 'TCP ACK port 8080');
    addPacket(4, 0.0185, 'outbound', 'PSH, ACK', 482, 64, 64240, 101, 201, 'POST /v2/agent/heartbeat HTTP/1.1 (Encrypted C2 Beacon)', 'Hypertext Transfer Protocol: POST Request', `POST /v2/agent/heartbeat HTTP/1.1\r\nHost: 203.0.113.15:8080\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nContent-Type: application/json\r\nContent-Length: 128\r\n\r\n{"agent_id":"aegis-node-44","beacon_interval":60,"entropy":4.21,"data":"ZXhwbG9pdF9wYXlsb2FkX3N1Y2Nlc3NmdWxfZ2FpbmVk"}`);
    addPacket(5, 0.0542, 'inbound', 'PSH, ACK', 218, 128, 29200, 201, 531, 'HTTP/1.1 200 OK (Tasking: sleep 60s, task: T1021)', 'Hypertext Transfer Protocol: 200 OK Response', `HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: application/json\r\nContent-Length: 48\r\n\r\n{"status":"acknowledged","next_beacon":60,"task":"idle"}`);
  } else {
    // Default TCP HTTPS / Generic
    addPacket(1, 0.0, 'outbound', 'SYN', 60, 64, 64240, 100, 0, '[SYN] Seq=0 Win=64240 Len=0', 'TCP: Connection establishment', 'TCP SYN');
    addPacket(2, 0.0084, 'inbound', 'SYN, ACK', 60, 128, 65535, 200, 101, '[SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0', 'TCP: Server handshake', 'TCP SYN ACK');
    addPacket(3, 0.0088, 'outbound', 'ACK', 52, 64, 64240, 101, 201, '[ACK] Seq=1 Ack=1 Win=64240 Len=0', 'TCP: Handshake completed', 'TCP ACK');
    addPacket(4, 0.0152, 'outbound', 'PSH, ACK', 517, 64, 64240, 101, 201, 'TLSv1.3 Record Layer: Handshake Protocol: Client Hello', 'Transport Layer Security (TLS 1.3)', `\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03Client Hello: SNI vault.northwind.internal, Cipher Suites (17 suites), Supported Groups: x25519, secp256r1`);
    addPacket(5, 0.0245, 'inbound', 'PSH, ACK', 1420, 128, 65535, 201, 566, 'TLSv1.3 Record Layer: Handshake Protocol: Server Hello, Change Cipher Spec', 'Transport Layer Security (TLS 1.3)', `\x16\x03\x03\x00\x7a\x02\x00\x00\x76\x03\x03Server Hello: Cipher: TLS_AES_256_GCM_SHA384, KeyShare: x25519`);
    addPacket(6, 0.0381, 'outbound', 'PSH, ACK', 1042, 64, 64240, 566, 1621, 'TLSv1.3 Application Data (Encrypted Stream)', 'Transport Layer Security (TLS 1.3)', `\x17\x03\x03\x03\xe8Encrypted Application Data [1024 bytes]`);
  }

  return packets;
}
