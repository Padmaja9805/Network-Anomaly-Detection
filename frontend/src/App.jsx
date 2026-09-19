import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Activity, Shield, Database, Download, Play, Server, Zap } from 'lucide-react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, Title } from 'chart.js';
import { Pie } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, Title);

const API_BASE = 'http://localhost:3001/api';

function App() {
    const [isCapturing, setIsCapturing] = useState(false);
    const [stats, setStats] = useState({ totalPackets: 0, protocols: {}, maliciousCount: 0 });
    const [interfaces, setInterfaces] = useState([]);
    const [selectedInterface, setSelectedInterface] = useState('');

    const fetchStats = async () => {
        try {
            const res = await axios.get(`${API_BASE}/stats`);
            setStats(res.data);
        } catch (err) {
            console.error('Stats fetch error', err);
        }
    };

    const fetchInterfaces = async () => {
        try {
            const response = await axios.get(`${API_BASE}/interfaces`);
            setInterfaces(response.data);
            if (response.data.length > 0) {
                const best = response.data.find(i => i.name.includes('Wi-Fi')) || response.data[0];
                setSelectedInterface(best.id);
            }
        } catch (error) {
            console.error('Error fetching interfaces:', error);
        }
    };

    useEffect(() => {
        fetchStats();
        fetchInterfaces();
        const interval = setInterval(fetchStats, 2000);
        return () => clearInterval(interval);
    }, []);

    const startCapture = async () => {
        setIsCapturing(true);
        try {
            await axios.post(`${API_BASE}/capture/live`, {
                duration: 30,
                interfaceIdx: selectedInterface
            });
            fetchStats();
        } catch (error) {
            alert('Capture failed. Check if TShark is installed and backend is running.');
            console.error('Error starting capture:', error);
        } finally {
            setIsCapturing(false);
        }
    };

    const downloadDataset = () => window.open(`${API_BASE}/dataset`, '_blank');

    const pieData = {
        labels: Object.keys(stats.protocols).map(p => `Protocol ${p}`),
        datasets: [{
            data: Object.values(stats.protocols),
            backgroundColor: ['rgba(56, 189, 248, 0.6)', 'rgba(129, 140, 248, 0.6)', 'rgba(244, 114, 182, 0.6)', 'rgba(52, 211, 153, 0.6)'],
            borderColor: ['#38bdf8', '#818cf8', '#f472b6', '#34d399'],
            borderWidth: 1,
        }],
    };

    return (
        <div className="container">
            <header className="flex justify-between items-center mb-12">
                <div>
                    <h1 className="font-bold gradient-text text-4xl mb-2">Network Traffic Dataset for ML</h1>
                    <p className="text-secondary text-lg">Classify, Analyze, and Create numeric datasets in real-time.</p>
                </div>
            </header>

            <div className="stats-grid mb-12">
                <div className="glass-card flex items-center gap-4">
                    <div className="p-3 bg-blue-500/10 rounded-xl"><Database className="text-blue-400" size={24} /></div>
                    <div><p className="text-secondary text-sm">Total Packets</p><h3 className="text-2xl font-bold">{stats.totalPackets.toLocaleString()}</h3></div>
                </div>
                <div className="glass-card flex items-center gap-4">
                    <div className="p-3 bg-red-500/10 rounded-xl"><Shield className="text-red-400" size={24} /></div>
                    <div><p className="text-secondary text-sm">Anomalies Detected</p><h3 className="text-2xl font-bold">{stats.maliciousCount}</h3></div>
                </div>
                <div className="glass-card flex items-center gap-4">
                    <div className="p-3 bg-purple-500/10 rounded-xl"><Zap className="text-purple-400" size={24} /></div>
                    <div><p className="text-secondary text-sm">Features Extracted</p><h3 className="text-2xl font-bold">5</h3></div>
                </div>
                <div className="glass-card flex items-center gap-4">
                    <div className="p-3 bg-green-500/10 rounded-xl"><Server className="text-green-400" size={24} /></div>
                    <div><p className="text-secondary text-sm">System Status</p><h3 className="text-2xl font-bold text-green-400">Live</h3></div>
                </div>
            </div>

            <div className="grid md:grid-cols-3 gap-8 mb-12">
                <div className="glass-card md:col-span-2">
                    <h3 className="text-xl font-bold mb-6">Protocol Usage</h3>
                    <div className="chart-container flex items-center justify-center">
                        {Object.keys(stats.protocols).length > 0 ? (
                            <Pie data={pieData} options={{ maintainAspectRatio: false }} />
                        ) : <p className="text-secondary italic">Start capture to see data.</p>}
                    </div>
                </div>

                <div className="glass-card">
                    <h3 className="text-xl font-bold mb-6">Device Control</h3>
                    <div className="space-y-6">
                        <div className="form-group">
                            <label className="text-sm opacity-70 mb-2 block">Network Interface</label>
                            <select
                                className="w-full p-2 rounded-lg bg-white/10 border border-white/20 text-white"
                                value={selectedInterface}
                                onChange={(e) => setSelectedInterface(e.target.value)}
                                disabled={isCapturing}
                            >
                                {interfaces.map(i => (
                                    <option key={i.id} value={i.id} style={{ color: '#000' }}>{i.name}</option>
                                ))}
                            </select>
                        </div>

                        <button
                            className={`btn ${isCapturing ? 'btn-secondary' : 'btn-primary'} w-full flex items-center justify-center gap-2`}
                            onClick={startCapture}
                            disabled={isCapturing}
                        >
                            {isCapturing ? <Activity className="animate-spin" size={20} /> : <Play size={20} />}
                            {isCapturing ? 'Capturing Traffic...' : 'Start Data Capture'}
                        </button>

                        <button
                            className="btn btn-secondary w-full flex items-center justify-center gap-2"
                            onClick={downloadDataset}
                        >
                            <Download size={20} /> Download CSV Dataset
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default App;
