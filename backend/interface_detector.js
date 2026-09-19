const { spawnSync } = require('child_process');

function getActiveInterfaceGUID() {
    const TSHARK_PATH = 'C:\\Program Files\\Wireshark\\tshark.exe';

    const result = spawnSync(TSHARK_PATH, ['-D']);
    if (result.status !== 0) return null;

    const output = result.stdout.toString();
    const lines = output.split('\n');

    // Look for Wi-Fi or any active interface
    const wifiLine = lines.find(line => line.includes('Wi-Fi'));
    const ethernetLine = lines.find(line => line.includes('Ethernet'));

    const targetLine = wifiLine || ethernetLine || lines[0];
    if (!targetLine) return null;

    // Extract GUID from line like "5. \Device\NPF_{...} (Wi-Fi)"
    const match = targetLine.match(/(\\Device\\NPF_{[A-Z0-9-]+})/);
    if (match) {
        console.log(`Detected persistent GUID: ${match[1]}`);
        return match[1];
    }

    // Fallback to index if GUID match fails
    const indexMatch = targetLine.match(/^(\d+)\./);
    return indexMatch ? indexMatch[1] : '1';
}

module.exports = { getActiveInterfaceGUID };
