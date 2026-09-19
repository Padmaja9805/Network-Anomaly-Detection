const { spawn } = require('child_process');
const fs = require('fs-extra');
const { createObjectCsvWriter } = require('csv-writer');
const path = require('path');

// Absolute path to tshark on Windows
const TSHARK_PATH = 'C:\\Program Files\\Wireshark\\tshark.exe';

class PacketProcessor {
    constructor(outputFile = 'numeric_dataset.csv') {
        this.outputFile = outputFile;
        this.csvWriter = createObjectCsvWriter({
            path: outputFile,
            header: [
                { id: 'timestamp', title: 'Timestamp' },
                { id: 'length', title: 'Packet Length' },
                { id: 'protocol', title: 'Protocol' },
                { id: 'gap', title: 'Gap' },
                { id: 'label', title: 'Label' }
            ]
        });
        this.lastTimestamp = null;
        this.protocolMap = {
            'TCP': 1,
            'UDP': 2,
            'ICMP': 3,
            'DNS': 4,
            'TLS': 5,
            'HTTP': 6,
            'ARP': 7
        };
    }

    getProtocolId(proto) {
        return this.protocolMap[proto.toUpperCase()] || 0;
    }

    async processPacketLine(line) {
        try {
            const [timestamp, length, tcp, udp, icmp, dns, tls, arp] = line.split(',');
            if (!timestamp || !length) return null;

            let protocol = 0; // OTHER
            if (tcp && tcp !== '') protocol = 1;
            else if (udp && udp !== '') protocol = 2;
            else if (icmp && icmp !== '') protocol = 3;
            else if (dns && dns !== '') protocol = 4;
            else if (tls && tls !== '') protocol = 5;
            else if (arp && arp !== '') protocol = 7;

            const time = parseFloat(timestamp);
            const gap = this.lastTimestamp ? (time - this.lastTimestamp) : 0;
            this.lastTimestamp = time;

            return {
                timestamp: time,
                length: parseInt(length),
                protocol,
                gap,
                label: 0
            };
        } catch (e) {
            return null;
        }
    }

    async startLiveCapture(durationSeconds = 10, interfaceIdx, callback) {
        if (!interfaceIdx) {
            const { getActiveInterfaceGUID } = require('./interface_detector');
            interfaceIdx = getActiveInterfaceGUID();
        }
        if (!interfaceIdx) interfaceIdx = '5'; // Fallback to 5 which worked

        // Use a safe temp directory without spaces if possible
        const os = require('os');
        const pcapFile = path.join(os.tmpdir(), `capture_${Date.now()}.pcap`);
        console.log(`Phase 1: Capturing on interface ${interfaceIdx} to ${pcapFile}...`);

        return new Promise((resolve, reject) => {
            const capture = spawn(TSHARK_PATH, [
                '-i', interfaceIdx,
                '-a', `duration:${durationSeconds}`,
                '-w', pcapFile
            ]);

            capture.on('error', (err) => {
                console.error('Failed to start capture process:', err);
                reject(err);
            });

            capture.on('close', async (code) => {
                console.log(`Phase 1 finished (code ${code})`);
                try {
                    if (!fs.existsSync(pcapFile)) {
                        console.error('PCAP file was not created!');
                        return resolve([]);
                    }
                    const stats = fs.statSync(pcapFile);
                    console.log(`PCAP File Size: ${stats.size} bytes`);

                    if (stats.size < 100) {
                        console.log('No packets captured.');
                        await fs.remove(pcapFile);
                        return resolve([]);
                    }

                    console.log(`Phase 2: Extracting from ${pcapFile}...`);
                    const extract = spawn(TSHARK_PATH, [
                        '-r', pcapFile,
                        '-T', 'fields',
                        '-e', 'frame.time_epoch',
                        '-e', 'frame.len',
                        '-e', 'tcp',
                        '-e', 'udp',
                        '-e', 'icmp',
                        '-e', 'dns',
                        '-e', 'tls',
                        '-e', 'arp',
                        '-E', 'separator=,'
                    ]);

                    let buffer = '';
                    const records = [];

                    extract.stdout.on('data', (data) => {
                        const lines = (buffer + data.toString()).split('\n');
                        buffer = lines.pop();
                        for (const line of lines) {
                            const record = this.processPacketLineSync(line.trim());
                            if (record) {
                                records.push(record);
                                if (callback) callback(record);
                            }
                        }
                    });

                    extract.on('close', async (extractCode) => {
                        console.log(`Extraction finished (code ${extractCode}). Saved ${records.length} packets.`);
                        await this.csvWriter.writeRecords(records);
                        await fs.remove(pcapFile);
                        resolve(records);
                    });
                } catch (e) {
                    console.error('Phase 2 error:', e);
                    reject(e);
                }
            });

            capture.stderr.on('data', (data) => console.log(`Capture Stderr: ${data.toString().trim()}`));
        });
    }

    processPacketLineSync(line) {
        try {
            const [timestamp, length, tcp, udp, icmp, dns, tls, arp] = line.split(',');
            if (!timestamp || !length) return null;
            let protocol = 0;
            if (tcp && tcp !== '') protocol = 1;
            else if (udp && udp !== '') protocol = 2;
            else if (icmp && icmp !== '') protocol = 3;
            else if (dns && dns !== '') protocol = 4;
            else if (tls && tls !== '') protocol = 5;
            else if (arp && arp !== '') protocol = 7;
            return { timestamp: parseFloat(timestamp), length: parseInt(length), protocol, gap: 0, label: 0 };
        } catch (e) { return null; }
    }
}

module.exports = PacketProcessor;
