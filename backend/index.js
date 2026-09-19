const express = require('express');
const cors = require('cors');
const path = require('path');
const PacketProcessor = require('./packet_processor');

const app = express();
const port = 3001;

app.use(cors());
app.use(express.json());

const processor = new PacketProcessor(path.join(__dirname, 'numeric_dataset.csv'));

let isCapturing = false;
let latestStats = {
    totalPackets: 0,
    protocols: {},
    maliciousCount: 0
};

app.get('/api/interfaces', async (req, res) => {
    try {
        const { spawnSync } = require('child_process');
        const tsharkPath = 'C:\\Program Files\\Wireshark\\tshark.exe';
        const result = spawnSync(tsharkPath, ['-D']);

        if (result.error) {
            console.error('TShark -D Error:', result.error);
            return res.status(500).json({ error: result.error.message });
        }

        const rawOutput = result.stdout.toString();
        const interfaces = rawOutput
            .split('\n')
            .map(l => l.trim())
            .filter(l => l !== '')
            .map(l => {
                // Handle "1. \Device\..." format
                const match = l.match(/^(\d+)\.\s+(.+)$/);
                return match ? { id: match[1], name: match[2] } : null;
            })
            .filter(i => i !== null);

        console.log(`Discovered ${interfaces.length} interfaces.`);
        res.json(interfaces);
    } catch (err) {
        console.error('API Interfaces Error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/capture/live', async (req, res) => {
    if (isCapturing) return res.status(400).json({ error: 'Capture already in progress' });

    const duration = req.body.duration || 10;
    const interfaceIdx = req.body.interfaceIdx;
    isCapturing = true;

    try {
        const records = await processor.startLiveCapture(duration, interfaceIdx, (record) => {
            latestStats.totalPackets++;
            latestStats.protocols[record.protocol] = (latestStats.protocols[record.protocol] || 0) + 1;
        });
        isCapturing = false;
        res.json({ message: 'Capture completed', count: records.length });
    } catch (error) {
        isCapturing = false;
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/stats', (req, res) => {
    res.json(latestStats);
});

app.get('/api/dataset', (req, res) => {
    const filePath = path.join(__dirname, 'numeric_dataset.csv');
    res.download(filePath);
});

app.listen(port, () => {
    console.log(`Backend listening at http://localhost:${port}`);
});
