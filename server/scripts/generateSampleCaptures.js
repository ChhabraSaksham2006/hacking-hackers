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
// Scenario: Volumetric TCP SYN flood assaulting web service 192.168.1.200:80
// High packet rate, random spoofed botnet source IPs, 100% SYN flags.

const synFloodPackets = [];
const botnetIps = [
  '185.220.101.5',
  '45.142.214.88',
  '91.240.118.12',
  '194.26.29.4',
  '103.145.13.77',
  '185.196.220.31',
  '79.137.195.120',
  '193.32.162.9',
];

for (let i = 0; i < 180; i++) {
  const srcIp = botnetIps[i % botnetIps.length];
  const srcPort = 32768 + ((i * 137) % 32000);
  const dstPort = i % 5 === 0 ? 443 : 80;
  const isAttack = i >= 30; // Onset at packet 30
  
  synFloodPackets.push({
    tsSec: 1718000000 + Math.floor(i * 0.2),
    tsUsec: (i * 200000) % 1000000,
    srcIp: isAttack ? srcIp : '192.168.1.55',
    dstIp: '192.168.1.200',
    srcPort: isAttack ? srcPort : 54321,
    dstPort,
    flags: isAttack ? 0x02 : (i % 2 === 0 ? 0x12 : 0x10), // SYN flood vs normal
    payload: isAttack ? Buffer.from('GET / HTTP/1.1\r\nHost: target\r\n\r\n') : Buffer.alloc(0),
  });
}

const pcap1 = createPcapBuffer(synFloodPackets);
fs.writeFileSync(path.join(rootSampleDir, 'sample_1_mirai_synflood_ddos.pcap'), pcap1);
fs.writeFileSync(path.join(publicSampleDir, 'sample_1_mirai_synflood_ddos.pcap'), pcap1);
console.log('✓ Generated sample_1_mirai_synflood_ddos.pcap (%d bytes)', pcap1.length);

// ── 3. Generate Sample 2: EternalBlue Lateral SMB Spread (.pcap) ──
// Scenario: Internal host 10.0.4.15 laterally exploiting Port 445 on 10.0.4.50, 10.0.4.55

const smbPackets = [];
const smbTargets = ['10.0.4.50', '10.0.4.55', '10.0.4.60', '10.0.4.65'];

for (let i = 0; i < 140; i++) {
  const dstIp = smbTargets[Math.floor(i / 35) % smbTargets.length];
  const isAttack = i >= 20;
  const srcPort = 49152 + (i % 50);

  // SMB negotiation payload snippet
  const smbPayload = isAttack
    ? Buffer.from('\xffSMBs\x00\x00\x00\x00\x18\x07\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00')
    : Buffer.alloc(0);

  smbPackets.push({
    tsSec: 1718000000 + Math.floor(i * 0.35),
    tsUsec: (i * 350000) % 1000000,
    srcIp: '10.0.4.15',
    dstIp,
    srcPort,
    dstPort: 445,
    flags: isAttack ? 0x18 : 0x02, // PSH ACK during exploit negotiation
    payload: smbPayload,
  });
}

const pcap2 = createPcapBuffer(smbPackets);
fs.writeFileSync(path.join(rootSampleDir, 'sample_2_ransomware_eternalblue_smb.pcap'), pcap2);
fs.writeFileSync(path.join(publicSampleDir, 'sample_2_ransomware_eternalblue_smb.pcap'), pcap2);
console.log('✓ Generated sample_2_ransomware_eternalblue_smb.pcap (%d bytes)', pcap2.length);

// ── 4. Generate Sample 3: DNS Tunneling & Exfiltration (.csv) ──────
// Scenario: Host 172.16.8.22 tunneling sensitive documents over Port 53 queries

const csvHeader = 'timestamp,src_ip,src_port,dst_ip,dst_port,protocol,flags,total_ip_bytes,packet_count,duration_seconds,prob,stage,anomaly_reason,technique_id\n';
const dnsRows = [];

for (let i = 0; i < 100; i++) {
  const ts = new Date(1718000000000 + i * 2000).toISOString().replace('T', ' ').slice(0, 19);
  const isAttack = i >= 35;
  const bytes = isAttack ? 48000 + (i * 1250) : 1400 + ((i * 37) % 800);
  const pkts = isAttack ? 320 + (i * 8) : 14 + (i % 6);
  const prob = isAttack ? Number(Math.min(0.96, 0.58 + (i - 35) * 0.015).toFixed(3)) : 0.06;
  const stage = isAttack ? (i > 65 ? 'Exfiltration' : 'Command & Control') : 'Normal';
  const reason = isAttack
    ? 'Covert DNS TXT tunnel transmitting encoded database chunks to rogue NS 198.51.100.53'
    : 'Routine internal DNS lookup queries to local resolver';
  const techId = isAttack ? (i > 65 ? 'T1048.003' : 'T1071.004') : 'None';

  dnsRows.push(
    `${ts},172.16.8.22,${52000 + (i % 200)},198.51.100.53,53,UDP,UDP,${bytes},${pkts},2.0,${prob},${stage},"${reason}",${techId}`
  );
}

const csvContent = csvHeader + dnsRows.join('\n');
fs.writeFileSync(path.join(rootSampleDir, 'sample_3_c2_dns_tunnel_exfiltration.csv'), csvContent);
fs.writeFileSync(path.join(publicSampleDir, 'sample_3_c2_dns_tunnel_exfiltration.csv'), csvContent);
console.log('✓ Generated sample_3_c2_dns_tunnel_exfiltration.csv (%d rows)', dnsRows.length);

// ── 5. Generate Sample 4: SSH Brute Force Credential Spray (.csv) ──
// Scenario: External IP 91.240.118.172 spraying SSH logins against Bastion 10.20.1.10:22

const sshRows = [];
for (let i = 0; i < 90; i++) {
  const ts = new Date(1718000000000 + i * 2000).toISOString().replace('T', ' ').slice(0, 19);
  const isAttack = i >= 25;
  const bytes = isAttack ? 32000 + (i * 850) : 2100;
  const pkts = isAttack ? 180 + (i * 5) : 18;
  const prob = isAttack ? Number(Math.min(0.92, 0.52 + (i - 25) * 0.016).toFixed(3)) : 0.05;
  const stage = isAttack ? (i > 55 ? 'Initial Access' : 'Reconnaissance') : 'Normal';
  const reason = isAttack
    ? 'High-velocity SSH authentication failure storm probing root and admin accounts'
    : 'Standard authorized SSH key exchange session';
  const techId = isAttack ? 'T1110.001' : 'None';

  sshRows.push(
    `${ts},91.240.118.172,${41000 + (i % 100)},10.20.1.10,22,TCP,SYN PSH,${bytes},${pkts},2.0,${prob},${stage},"${reason}",${techId}`
  );
}

const sshContent = csvHeader + sshRows.join('\n');
fs.writeFileSync(path.join(rootSampleDir, 'sample_4_ssh_bruteforce_auth_spray.csv'), sshContent);
fs.writeFileSync(path.join(publicSampleDir, 'sample_4_ssh_bruteforce_auth_spray.csv'), sshContent);
console.log('✓ Generated sample_4_ssh_bruteforce_auth_spray.csv (%d rows)', sshRows.length);

console.log('\nAll 4 sample capture files generated successfully in:');
console.log('1. Root: %s', rootSampleDir);
console.log('2. Public Web: %s', publicSampleDir);
