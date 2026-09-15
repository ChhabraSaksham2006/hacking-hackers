import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const rootSampleDir = path.resolve(__dirname, '../../sample_captures');
const publicSampleDir = path.resolve(__dirname, '../../frontend/public/sample_captures');

fs.mkdirSync(rootSampleDir, { recursive: true });
fs.mkdirSync(publicSampleDir, { recursive: true });

// ── 1. Helper to construct binary PCAP files ────────────────────────

function createPcapBuffer(packets) {
  // Global Header (24 bytes)
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4, 0); // Magic number
  header.writeUInt16LE(2, 4);          // Major version 2
  header.writeUInt16LE(4, 6);          // Minor version 4
  header.writeInt32LE(0, 8);           // Thiszone (GMT)
  header.writeUInt32LE(0, 12);         // Sigfigs
  header.writeUInt32LE(65535, 16);     // Snaplen
  header.writeUInt32LE(1, 20);         // LinkType: Ethernet (1)

  const packetBuffers = [];

  for (const pkt of packets) {
    // Ethernet (14) + IPv4 (20) + TCP (20) + Payload
    const ethLen = 14;
    const ipLen = 20;
    const tcpLen = 20;
    const payload = pkt.payload || Buffer.alloc(0);
    const totalPktLen = ethLen + ipLen + tcpLen + payload.length;

    // Packet Header (16 bytes)
    const pktHdr = Buffer.alloc(16);
    pktHdr.writeUInt32LE(pkt.tsSec || 1718000000, 0);
    pktHdr.writeUInt32LE(pkt.tsUsec || 0, 4);
    pktHdr.writeUInt32LE(totalPktLen, 8);  // incl_len
    pktHdr.writeUInt32LE(totalPktLen, 12); // orig_len

    // Ethernet Frame (14 bytes)
    const eth = Buffer.alloc(14);
    eth.set([0x00, 0x50, 0x56, 0xfa, 0x12, 0x34], 0); // Dst MAC
    eth.set([0x00, 0x0c, 0x29, 0xbb, 0xcc, 0xdd], 6); // Src MAC
    eth.writeUInt16BE(0x0800, 12); // IPv4

    // IPv4 Header (20 bytes)
    const ip = Buffer.alloc(20);
    ip[0] = 0x45; // Version 4, IHL 5
    ip[1] = 0x00; // DSCP/ECN
    ip.writeUInt16BE(ipLen + tcpLen + payload.length, 2); // Total Length
    ip.writeUInt16BE(pkt.id || 0x1234, 4); // ID
    ip.writeUInt16BE(0x4000, 6); // Flags: DF
    ip[8] = 64; // TTL
    ip[9] = 6;  // Protocol: TCP
    ip.writeUInt16BE(0x0000, 10); // Header Checksum

    // Src IP
    const srcParts = (pkt.srcIp || '192.168.1.100').split('.').map(Number);
    ip[12] = srcParts[0]; ip[13] = srcParts[1]; ip[14] = srcParts[2]; ip[15] = srcParts[3];

    // Dst IP
    const dstParts = (pkt.dstIp || '192.168.1.200').split('.').map(Number);
    ip[16] = dstParts[0]; ip[17] = dstParts[1]; ip[18] = dstParts[2]; ip[19] = dstParts[3];

    // TCP Header (20 bytes)
    const tcp = Buffer.alloc(20);
    tcp.writeUInt16BE(pkt.srcPort || 49152, 0);
    tcp.writeUInt16BE(pkt.dstPort || 80, 2);
    tcp.writeUInt32BE(pkt.seq || 1000, 4);
    tcp.writeUInt32BE(pkt.ack || 0, 8);
    tcp[12] = (5 << 4); // Data Offset 5 (20 bytes)
    tcp[13] = pkt.flags || 0x02; // Flags: SYN = 0x02, ACK = 0x10, PSH = 0x08
    tcp.writeUInt16BE(pkt.window || 64240, 14);
    tcp.writeUInt16BE(0x0000, 16); // Checksum
    tcp.writeUInt16BE(0x0000, 18); // Urgent pointer

    packetBuffers.push(pktHdr, eth, ip, tcp, payload);
  }

  return Buffer.concat([header, ...packetBuffers]);
}

// ── 2. Generate Sample 1: Mirai SYN Flood DDoS (.pcap) ─────────────
// Multi-stage progression: Normal HTTP -> Recon SYN Sweep -> Volumetric DDoS Flood
const synFloodPackets = [];
const botnetIps = [
  '185.220.101.5', '45.142.214.88', '91.240.118.12', '194.26.29.4',
  '103.145.13.77', '185.196.220.31', '79.137.195.120', '193.32.162.9',
];

for (let i = 0; i < 240; i++) {
  const tSec = Math.floor(i * 0.25); // spans 60.0 seconds
  const tUsec = (i * 250000) % 1000000;
  
  if (tSec < 22) {
    // Phase 1: Baseline Normal Web Traffic (0 - 22s)
    synFloodPackets.push({
      tsSec: 1718000000 + tSec,
      tsUsec: tUsec,
      srcIp: '192.168.1.45',
      dstIp: '192.168.1.200',
      srcPort: 52100 + (i % 5),
      dstPort: 80,
      flags: i % 3 === 0 ? 0x02 : 0x10, // normal SYN then ACK
      payload: Buffer.from('GET /index.html HTTP/1.1\r\n\r\n'),
    });
  } else if (tSec < 36) {
    // Phase 2: Reconnaissance Port Sweep (22 - 36s)
    synFloodPackets.push({
      tsSec: 1718000000 + tSec,
      tsUsec: tUsec,
      srcIp: '45.142.214.88',
      dstIp: '192.168.1.200',
      srcPort: 40000 + (i * 17) % 20000,
      dstPort: 70 + (i % 20),
      flags: 0x02, // SYN scan
      payload: Buffer.alloc(0),
    });
  } else {
    // Phase 3: Volumetric TCP SYN Flood Assault (36 - 60s)
    const srcIp = botnetIps[i % botnetIps.length];
    synFloodPackets.push({
      tsSec: 1718000000 + tSec,
      tsUsec: tUsec,
      srcIp,
      dstIp: '192.168.1.200',
      srcPort: 32768 + (i * 137) % 32000,
      dstPort: i % 4 === 0 ? 443 : 80,
      flags: 0x02, // Pure SYN
      payload: Buffer.alloc(0),
    });
  }
}

const pcap1 = createPcapBuffer(synFloodPackets);
fs.writeFileSync(path.join(rootSampleDir, 'sample_1_mirai_synflood_ddos.pcap'), pcap1);
fs.writeFileSync(path.join(publicSampleDir, 'sample_1_mirai_synflood_ddos.pcap'), pcap1);
console.log('✓ Generated sample_1_mirai_synflood_ddos.pcap (%d bytes)', pcap1.length);

// ── 3. Generate Sample 2: EternalBlue Lateral SMB Spread (.pcap) ──
// Multi-stage progression: Normal Intranet -> Port Discovery -> SMB Lateral Exploitation
const smbPackets = [];
const smbTargets = ['10.0.4.50', '10.0.4.55', '10.0.4.60'];

for (let i = 0; i < 240; i++) {
  const tSec = Math.floor(i * 0.25); // spans 60.0 seconds
  const tUsec = (i * 250000) % 1000000;

  if (tSec < 22) {
    // Phase 1: Baseline Normal Workstation Traffic (0 - 22s)
    // Routine DNS and internal web communication (Ports 53, 80)
    smbPackets.push({
      tsSec: 1718000000 + tSec,
      tsUsec: tUsec,
      srcIp: '10.0.4.15',
      dstIp: i % 2 === 0 ? '10.0.0.1' : '10.0.4.2',
      srcPort: 49152 + (i % 10),
      dstPort: i % 2 === 0 ? 53 : 80,
      flags: 0x10, // ACK
      payload: Buffer.from('Standard client request data'),
    });
  } else if (tSec < 36) {
    // Phase 2: Internal Discovery & Service Enumeration (22 - 36s)
    // Probing internal subnet across ports 135, 139, 445, 3389
    const probePorts = [135, 139, 445, 3389];
    smbPackets.push({
      tsSec: 1718000000 + tSec,
      tsUsec: tUsec,
      srcIp: '10.0.4.15',
      dstIp: smbTargets[i % smbTargets.length],
      srcPort: 50000 + i,
      dstPort: probePorts[i % probePorts.length],
      flags: 0x02, // SYN probe
      payload: Buffer.alloc(0),
    });
  } else {
    // Phase 3: EternalBlue MS17-010 SMB Session Exploitation (36 - 60s)
    // Heavy SMB negotiation and exploit payload on Port 445
    const smbPayload = Buffer.from(
      '\xffSMBs\x00\x00\x00\x00\x18\x07\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00'
    );
    smbPackets.push({
      tsSec: 1718000000 + tSec,
      tsUsec: tUsec,
      srcIp: '10.0.4.15',
      dstIp: smbTargets[i % smbTargets.length],
      srcPort: 49152 + (i % 30),
      dstPort: 445,
      flags: 0x18, // PSH ACK
      payload: smbPayload,
    });
  }
}

const pcap2 = createPcapBuffer(smbPackets);
fs.writeFileSync(path.join(rootSampleDir, 'sample_2_ransomware_eternalblue_smb.pcap'), pcap2);
fs.writeFileSync(path.join(publicSampleDir, 'sample_2_ransomware_eternalblue_smb.pcap'), pcap2);
console.log('✓ Generated sample_2_ransomware_eternalblue_smb.pcap (%d bytes)', pcap2.length);

// ── 4. Generate Sample 3: DNS Tunneling & Exfiltration (.csv) ──────
const csvHeader = 'timestamp,src_ip,src_port,dst_ip,dst_port,protocol,flags,total_ip_bytes,packet_count,duration_seconds,prob,stage,anomaly_reason,technique_id\n';
const dnsRows = [];

for (let i = 0; i < 60; i++) {
  const ts = new Date(1718000000000 + i * 2000).toISOString().replace('T', ' ').slice(0, 19);
  
  if (i < 20) {
    // Normal Baseline (0 - 40s)
    dnsRows.push(
      `${ts},172.16.8.22,${52000 + (i % 20)},10.0.0.1,53,UDP,UDP,140,2,2.0,0.06,Normal,"Standard enterprise internal DNS query",None`
    );
  } else if (i < 35) {
    // Initial Access / C2 Beaconing (40 - 70s)
    dnsRows.push(
      `${ts},172.16.8.22,${52000 + (i % 20)},198.51.100.53,53,UDP,UDP,850,8,2.0,0.42,Command & Control,"Periodic low-jitter DNS check-in to external nameserver 198.51.100.53",T1071.004`
    );
  } else {
    // Exfiltration Surge (70 - 120s)
    dnsRows.push(
      `${ts},172.16.8.22,${52000 + (i % 20)},198.51.100.53,53,UDP,UDP,${42000 + i * 800},${240 + i * 4},2.0,0.89,Exfiltration,"Covert DNS TXT tunnel transmitting encoded database chunks",T1048.003`
    );
  }
}

const csvContent = csvHeader + dnsRows.join('\n');
fs.writeFileSync(path.join(rootSampleDir, 'sample_3_c2_dns_tunnel_exfiltration.csv'), csvContent);
fs.writeFileSync(path.join(publicSampleDir, 'sample_3_c2_dns_tunnel_exfiltration.csv'), csvContent);
console.log('✓ Generated sample_3_c2_dns_tunnel_exfiltration.csv (%d rows)', dnsRows.length);

// ── 5. Generate Sample 4: SSH Brute Force Credential Spray (.csv) ──
const sshRows = [];
for (let i = 0; i < 60; i++) {
  const ts = new Date(1718000000000 + i * 2000).toISOString().replace('T', ' ').slice(0, 19);
  
  if (i < 20) {
    // Normal Baseline
    sshRows.push(
      `${ts},10.20.1.50,49152,10.20.1.10,22,TCP,ACK,2100,14,2.0,0.05,Normal,"Authorized administrator SSH session",None`
    );
  } else if (i < 35) {
    // Recon / Port Probes
    sshRows.push(
      `${ts},91.240.118.172,${41000 + i},10.20.1.10,22,TCP,SYN,340,3,2.0,0.38,Reconnaissance,"Slow rate SSH port verification probe",T1046`
    );
  } else {
    // Aggressive Brute Force Storm
    sshRows.push(
      `${ts},91.240.118.172,${41000 + i},10.20.1.10,22,TCP,SYN PSH,${28000 + i * 600},${180 + i * 5},2.0,0.88,Initial Access,"High-velocity dictionary credential stuffing storm against root/admin accounts",T1110.001`
    );
  }
}

const sshContent = csvHeader + sshRows.join('\n');
fs.writeFileSync(path.join(rootSampleDir, 'sample_4_ssh_bruteforce_auth_spray.csv'), sshContent);
fs.writeFileSync(path.join(publicSampleDir, 'sample_4_ssh_bruteforce_auth_spray.csv'), sshContent);
console.log('✓ Generated sample_4_ssh_bruteforce_auth_spray.csv (%d rows)', sshRows.length);

console.log('\nAll 4 sample capture files generated with realistic multi-stage progression.');
