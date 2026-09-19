import React, { useState, useEffect, useMemo } from 'react'
import axios from 'axios'
import {
    Shield, Activity, FileText, AlertTriangle, CheckCircle2,
    Upload, X, Loader2, Search, Filter, Download,
    ChevronLeft, ChevronRight, Moon, Sun, Zap, Clock, ShieldAlert, Info, XCircle
} from 'lucide-react'
import {
    BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
    PieChart, Pie, Cell, ResponsiveContainer
} from 'recharts'

// Configuration - Using Vite Proxy for stability
const API_BASE_URL = '/api'

// --- Components (Defined in the same file to ensure paths never fail) ---

const StatCard = ({ label, value, icon: Icon, color, bg, border }) => (
    <div className="bg-card/60 backdrop-blur-md border border-white/10 rounded-2xl p-5 flex items-center gap-5 shadow-xl transition-all hover:scale-[1.02]">
        <div className={`p-4 rounded-2xl ${bg} ${color} border ${border} shadow-inner`}>
            <Icon className="w-7 h-7" />
        </div>
        <div className="flex flex-col">
            <p className="text-[11px] font-bold opacity-50 uppercase tracking-[0.15em] mb-1">{label}</p>
            <p className="text-3xl font-black tracking-tight">{value}</p>
        </div>
    </div>
)

const App = () => {
    // State
    const [data, setData] = useState({
        total_flows: 0,
        total_anomalies: 0,
        total_packets: 0,
        accuracy: 98.7,
        flows: []
    })
    const [loading, setLoading] = useState(false)
    const [status, setStatus] = useState('connecting...')
    const [darkMode, setDarkMode] = useState(true)
    const [notification, setNotification] = useState(null)

    // Table state
    const [searchTerm, setSearchTerm] = useState('')
    const [protocolFilter, setProtocolFilter] = useState('All')
    const [anomalyOnly, setAnomalyOnly] = useState(false)
    const [currentPage, setCurrentPage] = useState(1)
    const itemsPerPage = 8

    // Check backend connection on mount
    useEffect(() => {
        const checkConnection = async () => {
            try {
                const res = await axios.get(`${API_BASE_URL}/`)
                if (res.data.status === 'Backend is running') {
                    setStatus('connected')
                } else {
                    setStatus('warning')
                }
            } catch (err) {
                console.error("Connection check failed:", err)
                setStatus('disconnected')
            }
        }
        checkConnection()
    }, [])

    // Helper: show toast
    const showNotification = (message, type = 'success') => {
        setNotification({ message, type })
        setTimeout(() => setNotification(null), 5000)
    }

    // File Upload Logic
    const handleFileUpload = async (e) => {
        const file = e.target.files[0]
        if (!file) return
        if (!file.name.endsWith('.pcap') && !file.name.endsWith('.pcapng')) {
            showNotification("Invalid file type. Please use .pcap or .pcapng", "error")
            return
        }

        setLoading(true)
        const formData = new FormData()
        formData.append('file', file)

        try {
            showNotification("Uploading and analyzing traffic...", "info")
            const response = await axios.post(`${API_BASE_URL}/upload`, formData, {
                headers: { 'Content-Type': 'multipart/form-data' },
                timeout: 120000 // 2 minutes for slow TShark processing
            })

            const res = response.data
            const flows = res.flows || []
            const anomalies = flows.filter(f => f.anomaly === 1 || f.is_anomaly)

            setData({
                total_flows: res.total_flows || flows.length,
                total_anomalies: res.total_anomalies || anomalies.length,
                total_packets: flows.reduce((acc, f) => acc + (f.length || f.packet_length || 0), 0),
                accuracy: res.accuracy || 98.7,
                flows: flows
            })
            showNotification(`Success: ${anomalies.length} anomalies detected`)
        } catch (err) {
            console.error(err)
            showNotification("Analysis failed. Check backend connection.", "error")
            setStatus('disconnected')
        } finally {
            setLoading(false)
        }
    }

    // Memoized filtered data
    const filteredFlows = useMemo(() => {
        return data.flows.filter(f => {
            const matchSearch = (f.src_ip + f.dst_ip).toLowerCase().includes(searchTerm.toLowerCase())
            const matchProtocol = protocolFilter === 'All' || f.protocol === protocolFilter
            const matchAnomaly = !anomalyOnly || (f.anomaly === 1 || f.is_anomaly)
            return matchSearch && matchProtocol && matchAnomaly
        })
    }, [data.flows, searchTerm, protocolFilter, anomalyOnly])

    const paginatedFlows = useMemo(() => {
        const start = (currentPage - 1) * itemsPerPage
        return filteredFlows.slice(start, start + itemsPerPage)
    }, [filteredFlows, currentPage])

    const totalPages = Math.ceil(filteredFlows.length / itemsPerPage)

    // Chart Data
    const chartData = useMemo(() => {
        if (!data.flows.length) return { pie: [], bar: [] }

        const pie = [
            { name: 'Normal', value: data.flows.filter(f => !f.anomaly && !f.is_anomaly).length, color: '#10b981' },
            { name: 'Anomaly', value: data.flows.filter(f => f.anomaly === 1 || f.is_anomaly).length, color: '#ef4444' }
        ]

        const protoMap = data.flows.reduce((acc, f) => {
            acc[f.protocol] = (acc[f.protocol] || 0) + 1
            return acc
        }, {})
        const bar = Object.entries(protoMap).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value)

        return { pie, bar }
    }, [data.flows])

    const exportCSV = () => {
        if (!data.flows.length) return
        const csvContent = "Source,Dest,Proto,Len,Anomaly\n" +
            data.flows.map(f => `${f.src_ip},${f.dst_ip},${f.protocol},${f.length},${f.anomaly ? 'YES' : 'NO'}`).join('\n')
        const blob = new Blob([csvContent], { type: 'text/csv' })
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `report_${Date.now()}.csv`
        a.click()
    }

    return (
        <div className={`min-h-screen transition-all duration-500 font-sans ${darkMode ? 'dark bg-[#0a0c10] text-[#e2e8f0]' : 'bg-[#f8fafc] text-[#0f172a]'}`}>

            {/* Navbar */}
            <nav className="h-16 border-b border-white/5 flex items-center justify-between px-6 sticky top-0 bg-background/80 backdrop-blur-xl z-50">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-blue-500/20 rounded-xl">
                        <Shield className="w-7 h-7 text-blue-500" />
                    </div>
                    <div>
                        <h1 className="text-lg font-black tracking-tight leading-none uppercase">SecureTraffic</h1>
                        <p className="text-[9px] uppercase tracking-[0.3em] font-bold opacity-40 mt-1">Anomaly Detection Engine</p>
                    </div>
                </div>

                <div className="flex items-center gap-5">
                    <div className="flex items-center gap-2 px-3 py-1.5 bg-white/5 rounded-full border border-white/5">
                        <div className={`w-1.5 h-1.5 rounded-full ${status === 'connected' ? 'bg-emerald-500 animate-pulse' : 'bg-red-500 shadow-[0_0_8px_red]'}`} />
                        <span className="text-[10px] font-black uppercase tracking-widest opacity-70">{status}</span>
                    </div>
                    <button onClick={() => setDarkMode(!darkMode)} className="p-2 bg-white/5 rounded-xl border border-white/10 hover:bg-white/10 transition-all">
                        {darkMode ? <Sun className="w-5 h-5 text-amber-500" /> : <Moon className="w-5 h-5 text-indigo-500" />}
                    </button>
                </div>
            </nav>

            {/* Main Content */}
            <main className="p-6 max-w-[1600px] mx-auto w-full grid grid-cols-1 lg:grid-cols-4 gap-6">

                {/* Left Column (Upload & Alerts) */}
                <section className="lg:col-span-1 flex flex-col gap-6">

                    {/* Upload Card */}
                    <div className="bg-card/40 backdrop-blur-md border border-white/10 rounded-2xl p-6 shadow-2xl">
                        <div className="flex items-center gap-2 mb-6">
                            <Upload className="w-5 h-5 text-blue-500" />
                            <h2 className="font-bold text-sm uppercase tracking-widest">Traffic Ingestion</h2>
                        </div>

                        <label className="group relative border-2 border-dashed border-white/10 rounded-2xl p-8 flex flex-col items-center justify-center gap-4 cursor-pointer hover:border-blue-500/50 hover:bg-blue-500/5 transition-all">
                            <input type="file" onChange={handleFileUpload} className="hidden" />
                            <div className="p-4 bg-white/5 rounded-full group-hover:bg-blue-500/10 transition-colors">
                                <Upload className="w-8 h-8 opacity-40 group-hover:opacity-100 group-hover:text-blue-500" />
                            </div>
                            <div className="text-center">
                                <p className="text-xs font-black uppercase tracking-widest opacity-70">Drop PCAP Trace</p>
                                <p className="text-[9px] opacity-40 mt-1 font-bold">PCAP / PCAPNG Supported</p>
                            </div>
                        </label>

                        <button
                            disabled={loading}
                            className="w-full h-12 mt-6 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-black uppercase tracking-widest text-[11px] rounded-xl transition-all shadow-lg shadow-blue-500/20"
                        >
                            {loading ? <Loader2 className="w-5 h-5 animate-spin mx-auto" /> : "Manual Analysis"}
                        </button>
                    </div>

                    {/* Alerts Card */}
                    <div className="bg-card/40 backdrop-blur-md border border-white/10 rounded-2xl p-6 flex-1 shadow-2xl overflow-hidden flex flex-col">
                        <div className="flex items-center justify-between mb-6">
                            <div className="flex items-center gap-2">
                                <AlertTriangle className="w-5 h-5 text-red-500" />
                                <h2 className="font-bold text-sm uppercase tracking-widest">Active Alerts</h2>
                            </div>
                            <span className="text-[9px] font-black bg-red-500 px-1.5 py-0.5 rounded text-white animate-pulse">LIVE</span>
                        </div>

                        <div className="flex-1 overflow-y-auto space-y-3 pr-2">
                            {data.flows.filter(f => f.anomaly || f.is_anomaly).slice(0, 10).map((alert, i) => (
                                <div key={i} className="p-3 rounded-xl bg-red-500/5 border border-red-500/10 hover:border-red-500/30 transition-all group">
                                    <p className="text-[9px] font-black uppercase tracking-widest text-red-400 mb-1 italic">Threat Detected</p>
                                    <p className="text-[11px] font-bold leading-tight line-clamp-2">Possible malicious activity from {alert.src_ip}</p>
                                    <div className="mt-2 flex items-center gap-2 opacity-50">
                                        <Clock className="w-3 h-3" />
                                        <span className="text-[9px] font-bold">Just Now</span>
                                    </div>
                                </div>
                            ))}
                            {data.flows.filter(f => f.anomaly || f.is_anomaly).length === 0 && (
                                <div className="flex flex-col items-center justify-center py-20 opacity-20 grayscale">
                                    <ShieldAlert className="w-12 h-12" />
                                    <p className="text-[10px] font-black mt-3 flex items-center justify-center uppercase tracking-[0.2em] text-center w-full">Clean Environment</p>
                                </div>
                            )}
                        </div>
                    </div>
                </section>

                {/* Right Column (Dashboard) */}
                <section className="lg:col-span-3 flex flex-col gap-6">

                    {/* Summary Stats */}
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                        <StatCard label="Total Flows" value={data.total_flows} icon={Activity} color="text-blue-400" bg="bg-blue-400/10" border="border-blue-400/20" />
                        <StatCard label="Total Packets" value={(data.total_packets / 1000).toFixed(1) + 'k'} icon={FileText} color="text-purple-400" bg="bg-purple-400/10" border="border-purple-400/20" />
                        <StatCard label="Anomalies" value={data.total_anomalies} icon={AlertTriangle} color="text-red-400" bg="bg-red-400/10" border="border-red-400/20" />
                        <StatCard label="Model Confidence" value={data.accuracy + '%'} icon={CheckCircle2} color="text-emerald-400" bg="bg-emerald-400/10" border="border-emerald-400/20" />
                    </div>

                    {/* Charts Row */}
                    <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                        <div className="bg-card/40 backdrop-blur-md border border-white/10 rounded-2xl p-6 h-[320px] shadow-2xl flex flex-col">
                            <h3 className="text-[11px] font-black uppercase tracking-[0.2em] opacity-40 mb-6">Classification Distribution</h3>
                            <div className="flex-1">
                                {chartData.pie.length > 0 ? (
                                    <ResponsiveContainer width="100%" height="100%">
                                        <PieChart>
                                            <Pie data={chartData.pie} cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={8} dataKey="value">
                                                {chartData.pie.map((entry, index) => <Cell key={`c-${index}`} fill={entry.color} />)}
                                            </Pie>
                                            <Tooltip
                                                contentStyle={{ backgroundColor: '#1a1c23', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', fontSize: '10px' }}
                                                itemStyle={{ color: '#e2e8f0', fontWeight: 'bold' }}
                                            />
                                        </PieChart>
                                    </ResponsiveContainer>
                                ) : <div className="h-full flex items-center justify-center opacity-20 text-[10px] uppercase font-black tracking-widest italic">Awaiting Telemetry</div>}
                            </div>
                        </div>

                        <div className="bg-card/40 backdrop-blur-md border border-white/10 rounded-2xl p-6 h-[320px] shadow-2xl flex flex-col">
                            <h3 className="text-[11px] font-black uppercase tracking-[0.2em] opacity-40 mb-6">Protocol Analysis</h3>
                            <div className="flex-1">
                                {chartData.bar.length > 0 ? (
                                    <ResponsiveContainer width="100%" height="100%">
                                        <BarChart data={chartData.bar} layout="vertical" margin={{ left: -20 }}>
                                            <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="rgba(255,255,255,0.05)" />
                                            <XAxis type="number" hide />
                                            <YAxis dataKey="name" type="category" axisLine={false} tickLine={false} tick={{ fill: 'white', fontSize: 10, opacity: 0.5 }} width={80} />
                                            <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={20} fill="#3b82f6" />
                                        </BarChart>
                                    </ResponsiveContainer>
                                ) : <div className="h-full flex items-center justify-center opacity-20 text-[10px] uppercase font-black tracking-widest italic">Awaiting Telemetry</div>}
                            </div>
                        </div>
                    </div>

                    {/* Flow Table */}
                    <div className="bg-card/40 backdrop-blur-md border border-white/10 rounded-2xl flex flex-col min-h-[500px] shadow-2xl overflow-hidden">
                        <div className="p-5 border-b border-white/5 flex flex-col md:flex-row md:items-center justify-between gap-4">
                            <div className="flex flex-col">
                                <h3 className="font-black text-sm uppercase tracking-widest leading-none">Flow Inspection</h3>
                                <p className="text-[10px] opacity-40 font-bold mt-1">Deep Packet Analytics</p>
                            </div>

                            <div className="flex flex-wrap items-center gap-3">
                                <div className="relative">
                                    <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 opacity-30" />
                                    <input
                                        type="text"
                                        placeholder="Search IP addresses..."
                                        value={searchTerm}
                                        onChange={(e) => setSearchTerm(e.target.value)}
                                        className="bg-[#0f172a]/50 border border-white/5 rounded-xl pl-9 pr-4 py-2 text-[11px] focus:outline-none focus:ring-1 focus:ring-blue-500/50 w-full md:w-56"
                                    />
                                </div>

                                <select
                                    value={protocolFilter}
                                    onChange={(e) => setProtocolFilter(e.target.value)}
                                    className="bg-[#0f172a]/50 border border-white/5 rounded-xl px-3 py-2 text-[11px] font-bold outline-none cursor-pointer"
                                >
                                    <option value="All">All Protos</option>
                                    <option value="TCP">TCP</option>
                                    <option value="UDP">UDP</option>
                                </select>

                                <button
                                    onClick={() => setAnomalyOnly(!anomalyOnly)}
                                    className={`px-4 py-2 rounded-xl text-[11px] font-black uppercase tracking-widest border transition-all ${anomalyOnly ? 'bg-red-500 text-white border-red-500' : 'bg-white/5 border-white/5 opacity-50'
                                        }`}
                                >
                                    Glitches
                                </button>

                                <button onClick={exportCSV} className="bg-blue-600 hover:bg-blue-500 p-2 rounded-xl text-white shadow-lg transition-all">
                                    <Download className="w-5 h-5" />
                                </button>
                            </div>
                        </div>

                        <div className="flex-1 overflow-x-auto">
                            <table className="w-full text-left border-collapse">
                                <thead>
                                    <tr className="bg-white/5 border-b border-white/5">
                                        <th className="px-6 py-4 text-[10px] font-black opacity-30 uppercase tracking-[0.2em]">Source Host</th>
                                        <th className="px-6 py-4 text-[10px] font-black opacity-30 uppercase tracking-[0.2em]">Remote Host</th>
                                        <th className="px-6 py-4 text-[10px] font-black opacity-30 uppercase tracking-[0.2em]">Protocol</th>
                                        <th className="px-6 py-4 text-[10px] font-black opacity-30 uppercase tracking-[0.2em]">Byte Size</th>
                                        <th className="px-6 py-4 text-[10px] font-black opacity-30 uppercase tracking-[0.2em]">Classification</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-white/5">
                                    {paginatedFlows.map((flow, i) => (
                                        <tr key={i} className="hover:bg-white/[0.02] transition-colors border-b border-white/5">
                                            <td className="px-6 py-4 font-mono text-xs font-bold leading-none">{flow.src_ip}</td>
                                            <td className="px-6 py-4 font-mono text-xs font-bold leading-none opacity-60">{flow.dst_ip}</td>
                                            <td className="px-6 py-4">
                                                <span className="px-2 py-0.5 rounded text-[9px] font-black uppercase bg-white/5 border border-white/5">{flow.protocol}</span>
                                            </td>
                                            <td className="px-6 py-4 font-mono text-[10px] font-bold opacity-40">{flow.length || 0} B</td>
                                            <td className="px-6 py-4">
                                                {flow.anomaly ? (
                                                    <span className="flex items-center gap-1.5 text-red-500 text-[10px] font-black uppercase italic animate-pulse">
                                                        <AlertTriangle className="w-3.5 h-3.5" />
                                                        ABNORMAL
                                                    </span>
                                                ) : (
                                                    <span className="flex items-center gap-1.5 text-emerald-500 text-[10px] font-black uppercase">
                                                        <CheckCircle2 className="w-3.5 h-3.5" />
                                                        BENIGN
                                                    </span>
                                                )}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                            {filteredFlows.length === 0 && (
                                <div className="py-20 text-center opacity-30 text-[10px] font-black uppercase tracking-widest italic">No matching records found</div>
                            )}
                        </div>

                        <div className="p-4 border-t border-white/5 flex items-center justify-between bg-white/[0.01]">
                            <span className="text-[10px] font-black opacity-30 uppercase tracking-[0.2em]">Offset {filteredFlows.length ? (currentPage - 1) * itemsPerPage + 1 : 0} of {filteredFlows.length}</span>
                            <div className="flex items-center gap-2">
                                <button disabled={currentPage === 1} onClick={() => setCurrentPage(p => p - 1)} className="p-2 bg-white/5 rounded-xl border border-white/10 disabled:opacity-20 hover:bg-white/10"><ChevronLeft className="w-4 h-4" /></button>
                                <button disabled={currentPage >= totalPages} onClick={() => setCurrentPage(p => p + 1)} className="p-2 bg-white/5 rounded-xl border border-white/10 disabled:opacity-20 hover:bg-white/10"><ChevronRight className="w-4 h-4" /></button>
                            </div>
                        </div>
                    </div>
                </section>
            </main>

            {/* Popups */}
            {notification && (
                <div className={`fixed bottom-8 right-8 z-[100] p-4 rounded-2xl border shadow-2xl flex items-center gap-3 min-w-[320px] backdrop-blur-xl animate-in fade-in slide-in-from-bottom-4 duration-300 ${notification.type === 'error' ? 'bg-red-600/90 border-red-500 text-white' :
                    notification.type === 'info' ? 'bg-blue-600/90 border-blue-500 text-white' : 'bg-emerald-600/90 border-emerald-500 text-white'
                    }`}>
                    {notification.type === 'error' ? <XCircle className="w-6 h-6" /> : <Info className="w-6 h-6" />}
                    <p className="text-[11px] font-black uppercase tracking-wide">{notification.message}</p>
                </div>
            )}
        </div>
    )
}

export default App
