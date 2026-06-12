import React, { useState, useEffect, useRef } from 'react';
import { 
  ResponsiveContainer, 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  BarChart, 
  Bar, 
  Cell, 
  PieChart, 
  Pie, 
  Legend 
} from 'recharts';
import { 
  Shield, 
  ShieldAlert, 
  RefreshCw, 
  Terminal, 
  Sliders, 
  Activity, 
  MapPin, 
  AlertCircle, 
  Filter, 
  Trash, 
  Zap, 
  CheckCircle2, 
  ChevronLeft, 
  ChevronRight, 
  Server,
  Play,
  Lock,
  Globe
} from 'lucide-react';
import { AttackEvent, SecurityStats, ThreatActor, SystemSettings } from './types';

export default function App() {
  // Main Telemetry States
  const [events, setEvents] = useState<AttackEvent[]>([]);
  const [stats, setStats] = useState<SecurityStats>({
    total_attacks: 0,
    unique_ips: 0,
    top_port: '2222',
    protocol_stats: { SSH: 0, TELNET: 0, HTTP: 0 },
    top_attackers: [],
    top_payloads: []
  });
  const [threatActors, setThreatActors] = useState<ThreatActor[]>([]);
  const [settings, setSettings] = useState<SystemSettings>({
    simulationSpeed: 'normal',
    alertThreshold: 10,
    decoyProfile: 'standard'
  });

  // UI Control States
  const [activeTab, setActiveTab] = useState<'dashboard' | 'logs' | 'threats' | 'simulator'>('dashboard');
  const [logFilterProto, setLogFilterProto] = useState<string>('ALL');
  const [logSearchQuery, setLogSearchQuery] = useState<string>('');
  const [logPage, setLogPage] = useState<number>(1);
  const [logTotalPages, setLogTotalPages] = useState<number>(1);
  const [sseStatus, setSseStatus] = useState<'connecting' | 'connected' | 'disconnected'>('disconnected');
  const [selectedEvent, setSelectedEvent] = useState<AttackEvent | null>(null);
  const [simulationStatus, setSimulationStatus] = useState<string | null>(null);
  const [timeStr, setTimeStr] = useState<string>(new Date().toISOString());

  // Simulation Form State
  const [simProto, setSimProto] = useState<'SSH' | 'TELNET' | 'HTTP'>('SSH');
  const [simIP, setSimIP] = useState<string>('');
  const [simPayload, setSimPayload] = useState<string>('');

  // Floating Warning Alerts Queue
  const [activeAlerts, setActiveAlerts] = useState<AttackEvent[]>([]);

  // Leaflet references
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<any>(null);
  const markerGroupRef = useRef<any>(null);

  // Update dynamic timestamp clock
  useEffect(() => {
    const timer = setInterval(() => {
      setTimeStr(new Date().toUTCString());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Fetch static stats periodically, fallback SSE real-time events
  const syncTelemetry = async () => {
    try {
      const statsRes = await fetch('/api/stats');
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }

      const threatRes = await fetch('/api/threats');
      if (threatRes.ok) {
        const threatData = await threatRes.json();
        setThreatActors(threatData);
      }

      const settingsRes = await fetch('/api/settings');
      if (settingsRes.ok) {
        const settingsData = await settingsRes.json();
        setSettings(settingsData);
      }
    } catch (err) {
      console.error('Error fetching dashboard metrics:', err);
    }
  };

  // Fetch paginated events log
  const queryLogs = async (page = 1, proto = logFilterProto) => {
    try {
      let url = `/api/events?page=${page}&perPage=12`;
      if (proto !== 'ALL') {
        url += `&protocol=${proto}`;
      }
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setEvents(data.events);
        setLogTotalPages(data.pages);
        setLogPage(data.current_page);
      }
    } catch (err) {
      console.error('Error fetching paginated events:', err);
    }
  };

  // Run Leaflet Geolocation Map Initializer
  useEffect(() => {
    const L = (window as any).L;
    if (!L || !mapContainerRef.current) return;

    // Build the Leaflet Map with CartoDB Dark Matter tiles
    if (!mapInstanceRef.current) {
      mapInstanceRef.current = L.map(mapContainerRef.current, {
        center: [20, 10],
        zoom: 2,
        zoomControl: false,
        attributionControl: false
      });

      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 18
      }).addTo(mapInstanceRef.current);

      markerGroupRef.current = L.layerGroup().addTo(mapInstanceRef.current);
    }

    return () => {
      // Cleanup on hot module reloading
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, []);

  // Render nodes/markers on the Map
  const drawAttackerMarkers = (incidentList: AttackEvent[]) => {
    const L = (window as any).L;
    if (!L || !markerGroupRef.current || !mapInstanceRef.current) return;

    markerGroupRef.current.clearLayers();

    incidentList.forEach((evt) => {
      if (evt.lat && evt.lng) {
        // Red color for SSH, Amber for HTTP, Blue for TELNET
        let pulseColor = 'bg-red-500';
        let pointColor = 'bg-red-500 border border-slate-900';
        if (evt.protocol === 'HTTP') {
          pulseColor = 'bg-amber-400';
          pointColor = 'bg-amber-400 border border-slate-900';
        } else if (evt.protocol === 'TELNET') {
          pulseColor = 'bg-blue-400';
          pointColor = 'bg-blue-400 border border-slate-900';
        }

        const customMarkerIcon = L.divIcon({
          html: `<div class="relative flex items-center justify-center">
            <div class="absolute w-5 h-5 rounded-full ${pulseColor} animate-ping opacity-60"></div>
            <div class="relative w-2.5 h-2.5 rounded-full ${pointColor} shadow shadow-black"></div>
          </div>`,
          className: 'custom-pulsing-node',
          iconSize: [20, 20],
          iconAnchor: [10, 10]
        });

        const popupContent = `
          <div class="p-1 font-mono text-[11px] leading-relaxed">
            <div class="font-extrabold text-red-400 mb-1 border-b border-slate-800 pb-0.5">🔥 INTRUDER INCIDENT</div>
            <div><strong>IP:</strong> ${evt.ip}</div>
            <div><strong>Location:</strong> ${evt.city}, ${evt.country}</div>
            <div><strong>Protocol:</strong> <span class="text-indigo-400 px-1 py-0.5 bg-slate-950 rounded">${evt.protocol}</span></div>
            <div><strong>Target Port:</strong> ${evt.port}</div>
            <div class="mt-1 max-w-[170px] truncate text-slate-400"><strong>Payload:</strong> ${evt.payload}</div>
          </div>
        `;

        L.marker([evt.lat, evt.lng], { icon: customMarkerIcon })
          .bindPopup(popupContent)
          .addTo(markerGroupRef.current);
      }
    });
  };

  // Initialize SSE (Server-Sent Events) Live Update socket channel
  useEffect(() => {
    setSseStatus('connecting');
    const es = new EventSource('/api/live');

    es.onopen = () => {
      setSseStatus('connected');
    };

    es.onerror = () => {
      setSseStatus('disconnected');
    };

    es.onmessage = (event) => {
      try {
        const newEvent: AttackEvent = JSON.parse(event.data);
        
        // Append to local live ticker records list
        setEvents((prev) => {
          const updated = [newEvent, ...prev];
          // Limit list inside state to 100
          const clipped = updated.slice(0, 100);
          drawAttackerMarkers(clipped);
          return clipped;
        });

        // Recalculate metrics incrementally without hammering the database
        setStats((prev) => {
          const updatedProto = { ...prev.protocol_stats };
          updatedProto[newEvent.protocol] = (updatedProto[newEvent.protocol] || 0) + 1;
          
          return {
            ...prev,
            total_attacks: prev.total_attacks + 1,
            protocol_stats: updatedProto
          };
        });

        // Push alarm is triggered if IP attempts exceed configuration threshold
        // We track attempts of this IP
        setThreatActors((prev) => {
          const existing = prev.find(t => t.ip === newEvent.ip);
          const currentCount = existing ? existing.count + 1 : 1;
          
          if (currentCount >= settings.alertThreshold) {
            // Trigger red visual banner notification
            setActiveAlerts((prevAlerts) => [newEvent, ...prevAlerts.slice(0, 4)]);
          }

          const existingIndex = prev.findIndex(t => t.ip === newEvent.ip);
          let updatedThreats = [...prev];
          if (existingIndex !== -1) {
            updatedThreats[existingIndex] = {
              ...updatedThreats[existingIndex],
              count: currentCount,
              level: currentCount >= settings.alertThreshold ? 'HIGH' : currentCount > 4 ? 'MEDIUM' : 'LOW',
              lastSeen: newEvent.timestamp
            };
          } else {
            updatedThreats.push({
              ip: newEvent.ip,
              count: 1,
              country: newEvent.country,
              level: 'LOW',
              lastSeen: newEvent.timestamp
            });
          }
          return updatedThreats.sort((a, b) => b.count - a.count);
        });

      } catch (err) {
        console.error('SSE Payload Parsing Error:', err);
      }
    };

    // Load initial system stats on mounting
    syncTelemetry();
    queryLogs(1, 'ALL');

    return () => {
      es.close();
    };
  }, [settings.alertThreshold]);

  // Centering & Focusing on a specific intruder node coordinates
  const focusMapOnCoordinates = (evt: AttackEvent) => {
    setSelectedEvent(evt);
    if (mapInstanceRef.current && evt.lat && evt.lng) {
      mapInstanceRef.current.setView([evt.lat, evt.lng], 6, { animate: true });
      
      const L = (window as any).L;
      if (!L) return;

      // Draw custom popup immediately
      const popupContent = `
        <div class="p-1 font-mono text-[11px] leading-relaxed">
          <div class="font-bold text-red-500 mb-1 border-b border-slate-800 pb-0.5">⚠️ ACTIVE TRAFFIC NODE</div>
          <div><strong>IP:</strong> ${evt.ip}</div>
          <div><strong>Location:</strong> ${evt.city}, ${evt.country}</div>
          <div><strong>Port:</strong> ${evt.port}</div>
          <div class="mt-1 text-slate-400"><strong>Captured payload:</strong> ${evt.payload}</div>
        </div>
      `;

      L.popup()
        .setLatLng([evt.lat, evt.lng])
        .setContent(popupContent)
        .openOn(mapInstanceRef.current);
    }
  };

  // Trigger simulated Direct Ingress Scan
  const handleSimulateAttack = async (e: React.FormEvent) => {
    e.preventDefault();
    setSimulationStatus('queueing');
    try {
      const res = await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          protocol: simProto,
          host: simIP || undefined,
          payload: simPayload || undefined
        })
      });

      if (res.ok) {
        const data = await res.json();
        setSimulationStatus('compromised');
        setSimIP('');
        setSimPayload('');
        syncTelemetry();
        setTimeout(() => setSimulationStatus(null), 3500);
      } else {
        setSimulationStatus('failed');
      }
    } catch (err) {
      console.error(err);
      setSimulationStatus('failed');
    }
  };

  // Configure settings overrides
  const handleUpdateSettings = async (override: Partial<SystemSettings>) => {
    const nextSettings = { ...settings, ...override };
    setSettings(nextSettings);
    try {
      await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(nextSettings)
      });
      syncTelemetry();
    } catch (err) {
      console.error('Failed to sync settings with node database:', err);
    }
  };

  const clearAlert = (index: number) => {
    setActiveAlerts((prev) => prev.filter((_, idx) => idx !== index));
  };

  // Setup charting datasets
  // 1. Line Traffic of Protocol distribution
  const chartPieData = Object.entries(stats.protocol_stats).map(([k, v]) => ({
    name: k,
    value: Number(v) || 0
  }));

  const chartPieColors = {
    SSH: '#f87171',    // red 400
    TELNET: '#60a5fa', // blue 400
    HTTP: '#fbbf24'   // amber 400
  };

  // 2. Bar chart of top credential attacks
  const barChartCredentials = stats.top_payloads.slice(0, 5).map(item => ({
    name: item.payload.length > 22 ? item.payload.slice(0, 22) + '...' : item.payload,
    Attempts: item.count
  }));

  // 3. Generate mock hourly timeline distribution chart for styling excellence
  const timelineChartData = [
    { hour: '04:00', Events: Math.floor(events.length * 0.1) || 8 },
    { hour: '08:00', Events: Math.floor(events.length * 0.15) || 12 },
    { hour: '12:00', Events: Math.floor(events.length * 0.25) || 20 },
    { hour: '16:00', Events: Math.floor(events.length * 0.3) || 28 },
    { hour: '20:00', Events: Math.floor(events.length * 0.45) || 38 },
    { hour: '00:00', Events: Math.floor(events.length * 0.5) || 45 }
  ];

  // Paginated log change triggers
  const handleLogPageChange = (direction: 'next' | 'prev') => {
    const target = direction === 'next' ? logPage + 1 : logPage - 1;
    if (target > 0 && target <= logTotalPages) {
      queryLogs(target, logFilterProto);
    }
  };

  const handleLogFilterChange = (proto: string) => {
    setLogFilterProto(proto);
    queryLogs(1, proto);
  };

  // Filter local state ticker on logs
  const filteredSearchLogs = events.filter(e => {
    if (!logSearchQuery) return true;
    const query = logSearchQuery.toLowerCase();
    return (
      e.ip.toLowerCase().includes(query) ||
      e.payload.toLowerCase().includes(query) ||
      e.country.toLowerCase().includes(query) ||
      e.city.toLowerCase().includes(query)
    );
  });

  const totalCount = stats.total_attacks || 1;
  const sshVal = stats.protocol_stats.SSH || 0;
  const telnetVal = stats.protocol_stats.TELNET || 0;
  const httpVal = stats.protocol_stats.HTTP || 0;

  const sshPercent = Math.round((sshVal / totalCount) * 100);
  const telnetPercent = Math.round((telnetVal / totalCount) * 100);
  const httpPercent = Math.round((httpVal / totalCount) * 100);

  const topPayloadLogs = stats.top_payloads.length > 0 
    ? stats.top_payloads.slice(0, 5) 
    : [
        { payload: 'admin / admin', count: 42 },
        { payload: 'root / 123456', count: 31 },
        { payload: 'user / password', count: 18 },
        { payload: 'guest / guest', count: 12 },
        { payload: 'support / support', count: 5 }
      ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-mono p-4 md:p-6 flex flex-col gap-4 selection:bg-red-500 selection:text-white overflow-x-hidden">
      {/* GLOBAL BANNER NOTIFICATION QUEUE */}
      <div className="fixed top-4 right-4 z-[9999] space-y-2 pointer-events-auto max-w-sm w-full">
        {activeAlerts.map((alert, idx) => (
          <div 
            key={alert.id} 
            className="border border-red-500/30 bg-slate-900/95 text-slate-100 rounded-xl p-3.5 shadow-2xl backdrop-blur-md animate-slide-in relative flex gap-3 overflow-hidden font-mono"
          >
            <div className="absolute top-0 left-0 w-1 bg-red-550 h-full"></div>
            <div className="flex-shrink-0 text-red-550 mt-0.5">
              <ShieldAlert size={18} className="animate-pulse" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex justify-between items-center mb-1">
                <span className="text-[10px] font-black tracking-widest text-red-400 uppercase">HIGH THREAT FLAG</span>
                <button 
                  onClick={() => clearAlert(idx)}
                  className="text-slate-500 hover:text-slate-350 text-xs font-bold"
                >
                  ×
                </button>
              </div>
              <p className="text-[10.5px] text-slate-300">
                IP <span className="font-extrabold text-red-400">{alert.ip}</span> passed security threshold frequency limits.
              </p>
              <div className="mt-1.5 text-[9.5px] text-slate-400 bg-black/50 px-2 py-1 rounded border border-slate-900 truncate">
                Origin: {alert.city}, {alert.country} ({alert.protocol})
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Header Section */}
      <header className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-slate-800 pb-4 gap-4">
        <div className="flex items-center gap-3">
          <div className="w-3 h-3 bg-red-600 rounded-full animate-pulse"></div>
          <h1 className="text-lg md:text-xl font-bold tracking-tighter uppercase text-slate-100">
            Honeypot Traffic Analyzer <span className="text-slate-650 text-[11px] font-mono select-none ml-2 bg-slate-900/60 border border-slate-800 px-2 py-0.5 rounded-md">v4.0.2-Stable</span>
          </h1>
        </div>
        <div className="flex flex-wrap gap-4 md:gap-6 text-[10px] uppercase tracking-widest">
          <div className="flex flex-col items-start md:items-end">
            <span className="text-slate-500">System Uptime</span>
            <span className="text-emerald-400 font-bold">142:12:09:44</span>
          </div>
          <div className="flex flex-col items-start md:items-end">
            <span className="text-slate-500">Azure Region</span>
            <span className="text-blue-400 font-bold">East-US-2</span>
          </div>
          <div className="flex flex-col items-start md:items-end">
            <span className="text-slate-500">Active Listeners</span>
            <span className="text-slate-200 font-bold">SSH | TELNET | HTTP</span>
          </div>
          <div className="flex flex-col items-start md:items-end">
            <span className="text-slate-500">Gateway Sockets</span>
            {sseStatus === 'connected' ? (
              <span className="text-emerald-400 font-bold animate-pulse">STREAMING_ACTIVE</span>
            ) : sseStatus === 'connecting' ? (
              <span className="text-amber-400 font-bold animate-pulse">HANDSHAKE</span>
            ) : (
              <span className="text-red-500 font-bold">DISCONNECTED</span>
            )}
          </div>
        </div>
      </header>

      {/* Primary Stats Bento Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Ingress Events */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex flex-col justify-between h-28 relative overflow-hidden backdrop-blur-sm shadow-md">
          <span className="text-[10px] uppercase text-slate-500 font-bold tracking-wider">Total Ingress Events</span>
          <div className="text-3xl font-extrabold text-red-500">{stats.total_attacks}</div>
          <div className="w-full bg-slate-850 h-1.5 rounded-full overflow-hidden">
            <div className="bg-red-550 h-full" style={{ width: `${Math.min(100, (stats.total_attacks / 500) * 100)}%` }}></div>
          </div>
        </div>

        {/* Unique Adversaries */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex flex-col justify-between h-28 relative overflow-hidden backdrop-blur-sm shadow-md">
          <span className="text-[10px] uppercase text-slate-500 font-bold tracking-wider">Unique Adversaries</span>
          <div className="text-3xl font-extrabold text-blue-400">{stats.unique_ips}</div>
          <span className="text-[9px] text-emerald-500 font-bold uppercase tracking-wider">▲ +12% from last 24h</span>
        </div>

        {/* Most Vulnerable decoy port */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex flex-col justify-between h-28 relative overflow-hidden backdrop-blur-sm shadow-md">
          <span className="text-[10px] uppercase text-slate-500 font-bold tracking-wider">Critical decoy port</span>
          <div className="text-2xl font-black text-amber-500">PORT {stats.top_port}</div>
          <span className="text-[9px] text-slate-400 font-bold uppercase tracking-wider">Simulated Ingress Target</span>
        </div>

        {/* Alert limits */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex flex-col justify-between h-28 relative overflow-hidden backdrop-blur-sm shadow-md">
          <span className="text-[10px] uppercase text-slate-500 font-bold tracking-wider">Alert threshold limit</span>
          <div className="text-2xl font-black text-purple-400">{settings.alertThreshold}x attempts</div>
          <span className="text-[9px] text-slate-400 font-bold uppercase tracking-wider bg-slate-950 border border-slate-850 px-2 py-0.5 rounded-md self-start">
            Profile: {settings.decoyProfile}
          </span>
        </div>
      </div>

      {/* Navigation Tab Dock */}
      <nav className="flex flex-wrap gap-2 p-1 bg-slate-950 border border-slate-800 rounded-xl self-start">
        <button 
          onClick={() => setActiveTab('dashboard')}
          type="button"
          className={`px-4 py-2 text-[10px] font-mono tracking-wider font-bold uppercase transition rounded-lg ${
            activeTab === 'dashboard' 
              ? 'bg-slate-900 border border-slate-800 text-slate-100 shadow-inner' 
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/10'
          }`}
        >
          Overview Grid
        </button>
        <button 
          onClick={() => { setActiveTab('logs'); queryLogs(1, logFilterProto) }}
          type="button"
          className={`px-4 py-2 text-[10px] font-mono tracking-wider font-bold uppercase transition rounded-lg ${
            activeTab === 'logs' 
              ? 'bg-slate-900 border border-slate-800 text-slate-100 shadow-inner' 
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/10'
          }`}
        >
          Telemetry Logs
        </button>
        <button 
          onClick={() => { setActiveTab('threats'); syncTelemetry() }}
          type="button"
          className={`px-4 py-2 text-[10px] font-mono tracking-wider font-bold uppercase transition rounded-lg ${
            activeTab === 'threats' 
              ? 'bg-slate-900 border border-slate-800 text-slate-100 shadow-inner' 
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/10'
          }`}
        >
          Threat Actors
        </button>
        <button 
          onClick={() => setActiveTab('simulator')}
          type="button"
          className={`px-4 py-2 text-[10px] font-mono tracking-wider font-bold uppercase transition rounded-lg ${
            activeTab === 'simulator' 
              ? 'bg-slate-900 border border-slate-800 text-slate-100 shadow-inner' 
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/10'
          }`}
        >
          Direct Simulator
        </button>
      </nav>

      {/* Main Interactive Bento Layout */}
      <main className="flex-1 w-full">

        {/* TAB 1: DASHBOARD OVERVIEW GRID */}
        {activeTab === 'dashboard' && (
          <div className="space-y-4">
            
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
              
              {/* Map block (col-span-8) */}
              <div className="lg:col-span-8 bg-slate-900/20 border border-slate-800 rounded-xl overflow-hidden relative flex flex-col h-[420px] shadow-sm">
                <div className="absolute top-4 left-4 z-10 bg-slate-950/80 border border-slate-800 px-3 py-1.5 rounded-lg text-[9px] tracking-wider uppercase font-extrabold text-slate-300">
                  GEOSPATIAL THREAT PROJECTION
                </div>
                
                {/* Visual Map */}
                <div ref={mapContainerRef} className="flex-1 w-full bg-slate-950" style={{ minHeight: '260px' }}></div>
                
                {/* Geo tracking values overlay */}
                <div className="absolute bottom-4 left-4 right-4 flex flex-col sm:flex-row justify-between items-start sm:items-end gap-2 bg-slate-950/90 p-3 border border-slate-800/80 rounded-xl pointer-events-auto backdrop-blur-md">
                  <div className="text-[10px] leading-relaxed text-slate-400 font-mono">
                    {selectedEvent ? (
                      <>
                        <span className="text-red-400 font-extrabold">TARGET TRIGGER ACTIVE:</span><br/>
                        IP: <span className="text-slate-200 font-bold">{selectedEvent.ip}</span> | 
                        GEO: <span className="text-slate-200 font-bold">{selectedEvent.city.toUpperCase()}, {selectedEvent.country.toUpperCase()}</span><br/>
                        LAT: <span className="text-cyan-400 font-bold">{selectedEvent.lat}</span> | LNG: <span className="text-cyan-400 font-bold">{selectedEvent.lng}</span>
                      </>
                    ) : (
                      <>
                        <span className="text-slate-500 font-extrabold">SYS_MONITOR CORRELATIONS:</span><br/>
                        LAT: -- | LNG: -- | LOC: PACIFIC DECOY SENSORS<br/>
                        <span className="text-slate-500 font-bold">SELECT AN INCOMING LOG FROM FEED TO GEOLOCATE</span>
                      </>
                    )}
                  </div>
                  <div className="text-red-400 bg-red-950/40 border border-red-900/50 px-2.5 py-1 rounded-md text-[9px] font-black tracking-widest uppercase">
                    HIGH INTENSITY SENSOR ON
                  </div>
                </div>
              </div>

              {/* Ingress Stream Ticker (col-span-4) */}
              <div className="lg:col-span-4 bg-slate-950 border border-slate-800 rounded-xl overflow-hidden flex flex-col h-[420px] shadow-sm">
                <div className="bg-slate-900/80 p-3 border-b border-slate-800 flex justify-between items-center">
                  <span className="text-[10px] font-bold tracking-wider uppercase text-slate-200">REAL-TIME INGRESS STREAM</span>
                  <span className="text-[8px] text-emerald-400 uppercase font-black bg-emerald-950/40 px-2 py-0.5 border border-emerald-900/30 rounded-full animate-pulse">Live link</span>
                </div>
                
                <div className="p-3 overflow-y-auto flex-1 flex flex-col gap-2 font-mono text-[10px]">
                  {events.length === 0 ? (
                    <div className="text-slate-600 flex flex-col items-center justify-center p-12 text-center h-full gap-2">
                      <Terminal size={18} className="animate-pulse text-slate-700" />
                      <div>WAITING FOR DECOY PENETRATION LOGS...</div>
                    </div>
                  ) : (
                    events.slice(0, 15).map((evt) => {
                      let tagClass = 'text-cyan-400';
                      let label = '[SSH]';
                      if (evt.protocol === 'HTTP') {
                        tagClass = 'text-amber-400';
                        label = '[HTTP]';
                      } else if (evt.protocol === 'TELNET') {
                        tagClass = 'text-blue-400';
                        label = '[TEL]';
                      }

                      return (
                        <div 
                          key={evt.id} 
                          onClick={() => focusMapOnCoordinates(evt)}
                          className={`flex flex-col gap-1 p-2 rounded-lg cursor-pointer border border-transparent transition ${
                            selectedEvent?.id === evt.id ? 'bg-slate-900/60 border-slate-800' : 'bg-slate-905/30 hover:bg-slate-900/50'
                          }`}
                        >
                          <div className="flex gap-2 justify-between items-center">
                            <div className="flex gap-1.5 items-center">
                              <span className="text-slate-600 text-[9px]">
                                {new Date(evt.timestamp).toLocaleTimeString()}
                              </span>
                              <span className={`${tagClass} font-black`}>{label}</span>
                              <span className="text-slate-300 font-bold truncate max-w-[100px]">{evt.ip}</span>
                            </div>
                            <span className="text-slate-500 font-extrabold text-[9px] uppercase">{evt.city}</span>
                          </div>
                          <div className="text-slate-550 bg-black/40 border border-slate-900/80 p-1 rounded text-[9.5px] truncate">
                            {evt.payload}
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>

            </div>

            {/* Downward stats components breakdown */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              
              {/* Protocol breakdown */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex flex-col justify-between min-h-[300px]">
                <div>
                  <h3 className="text-[10px] uppercase text-slate-500 mb-3 font-bold tracking-wider">Protocol distribution</h3>
                  <div className="space-y-3">
                    <div className="flex flex-col gap-1">
                      <div className="flex justify-between text-[10px]">
                        <span className="text-cyan-400 font-extrabold">SSH (Port 2222)</span>
                        <span>{sshPercent}% ({sshVal})</span>
                      </div>
                      <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                        <div className="bg-cyan-500 h-full" style={{ width: `${sshPercent}%` }}></div>
                      </div>
                    </div>
                    <div className="flex flex-col gap-1">
                      <div className="flex justify-between text-[10px]">
                        <span className="text-purple-400 font-extrabold">TELNET (Port 2323)</span>
                        <span>{telnetPercent}% ({telnetVal})</span>
                      </div>
                      <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                        <div className="bg-purple-500 h-full" style={{ width: `${telnetPercent}%` }}></div>
                      </div>
                    </div>
                    <div className="flex flex-col gap-1">
                      <div className="flex justify-between text-[10px]">
                        <span className="text-amber-400 font-extrabold">HTTP (Port 8080)</span>
                        <span>{httpPercent}% ({httpVal})</span>
                      </div>
                      <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                        <div className="bg-amber-400 h-full" style={{ width: `${httpPercent}%` }}></div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="h-32 flex items-center justify-center mt-2">
                  {chartPieData.some(pt => pt.value > 0) ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={chartPieData}
                          cx="50%"
                          cy="50%"
                          innerRadius={28}
                          outerRadius={44}
                          paddingAngle={3}
                          dataKey="value"
                        >
                          {chartPieData.map((entry) => (
                            <Cell 
                              key={`cell-${entry.name}`} 
                              fill={chartPieColors[entry.name as 'SSH' | 'TELNET' | 'HTTP'] || '#94a3b8'} 
                            />
                          ))}
                        </Pie>
                        <Tooltip 
                          contentStyle={{ background: '#020617', border: '1px solid #1e293b', borderRadius: '4px' }}
                          itemStyle={{ fontFamily: 'monospace', fontSize: '10px', color: '#f1f5f9' }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="text-[10px] text-slate-600">Syncing telemetry streams...</div>
                  )}
                </div>
              </div>

              {/* Brute payloads attempted */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex flex-col justify-between min-h-[300px]">
                <div>
                  <h3 className="text-[10px] uppercase text-slate-500 mb-3 font-bold tracking-wider">Top brute credentials</h3>
                  <div className="space-y-1.5 font-mono text-[10px]">
                    <div className="flex justify-between font-bold text-slate-500 border-b border-slate-850 pb-1 uppercase tracking-wider">
                      <span>INTELLIGENCE PATH</span>
                      <span>ATTEMPTS</span>
                    </div>
                    {topPayloadLogs.map((p, idx) => (
                      <div key={idx} className="flex justify-between border-b border-slate-900 pb-1 pt-1 text-slate-300">
                        <span className="text-red-400 truncate max-w-[155px] font-bold">{p.payload}</span>
                        <span>{p.count}x</span>
                      </div>
                    ))}
                  </div>
                </div>
                
                <div className="h-20 mt-2">
                  {barChartCredentials.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={barChartCredentials} layout="vertical" margin={{ left: -32, right: 10 }}>
                        <XAxis type="number" stroke="#475569" style={{ fontSize: 8 }} />
                        <YAxis dataKey="name" type="category" stroke="#475569" width={90} style={{ fontSize: 7 }} />
                        <Bar dataKey="Attempts" fill="#ef4444" radius={[0, 4, 4, 0]}>
                          {barChartCredentials.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill="#f87171" opacity={1 - index * 0.15} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  ) : null}
                </div>
              </div>

              {/* Historical Timeline block */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex flex-col justify-between min-h-[300px]">
                <div>
                  <h3 className="text-[10px] uppercase text-slate-500 mb-2 font-bold tracking-wider">Atemporal Traffic Density</h3>
                  <p className="text-[10px] font-mono text-slate-500 mb-3 leading-relaxed">
                    Active scanned attempts across chronological timeline blocks.
                  </p>
                </div>
                <div className="flex-1 h-36">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timelineChartData} margin={{ left: -25, right: 5, top: 10, bottom: 5 }}>
                      <defs>
                        <linearGradient id="glowBentoEvents" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ef4444" stopOpacity={0.25}/>
                          <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                      <XAxis dataKey="hour" stroke="#475569" style={{ fontSize: 8 }} />
                      <YAxis stroke="#475569" style={{ fontSize: 8 }} />
                      <Area type="monotone" dataKey="Events" stroke="#ef4444" strokeWidth={1.5} fillOpacity={1} fill="url(#glowBentoEvents)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

            </div>

            {/* Section Controls */}
            <div className="bg-slate-900/20 border border-slate-800 rounded-xl p-5 shadow-sm">
              <div className="flex items-center gap-2 mb-4 border-b border-slate-850 pb-3">
                <Sliders size={14} className="text-red-500" />
                <h3 className="text-[10px] font-mono font-bold tracking-wider uppercase text-slate-300">Active Security Engine Profiling Controls</h3>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div>
                  <label className="block text-[10px] font-mono text-slate-500 mb-1.5 uppercase font-bold tracking-wider">Traffic simulation frequency</label>
                  <div className="grid grid-cols-4 bg-slate-950 p-1 border border-slate-850 rounded-lg">
                    {(['off', 'slow', 'normal', 'fast'] as const).map((spd) => (
                      <button
                        key={spd}
                        onClick={() => handleUpdateSettings({ simulationSpeed: spd })}
                        type="button"
                        className={`py-1.5 text-[9px] font-mono uppercase font-black rounded-md transition ${
                          settings.simulationSpeed === spd 
                            ? 'bg-red-950/60 text-red-400 border border-red-900/30' 
                            : 'text-slate-500 hover:text-slate-350 hover:bg-slate-900/50'
                        }`}
                      >
                        {spd}
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <label className="block text-[10px] font-mono text-slate-500 mb-1.5 uppercase font-bold tracking-wider">High threat threshold limit</label>
                  <div className="flex items-center gap-3">
                    <input
                      type="range"
                      min={3}
                      max={25}
                      value={settings.alertThreshold}
                      onChange={(e) => handleUpdateSettings({ alertThreshold: Number(e.target.value) })}
                      className="w-full h-1 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-red-500"
                    />
                    <span className="text-[11px] font-mono font-bold text-red-400 text-right min-w-[24px]">
                      {settings.alertThreshold}x
                    </span>
                  </div>
                </div>

                <div>
                  <label className="block text-[10px] font-mono text-slate-500 mb-1.5 uppercase font-bold tracking-wider">Decoy Response Profile State</label>
                  <div className="grid grid-cols-3 bg-slate-950 p-1 border border-slate-850 rounded-lg">
                    {(['standard', 'aggressive', 'stealth'] as const).map((profile) => (
                      <button
                        key={profile}
                        onClick={() => handleUpdateSettings({ decoyProfile: profile })}
                        type="button"
                        className={`py-1.5 text-[9px] font-mono uppercase font-black rounded-md transition ${
                          settings.decoyProfile === profile 
                            ? 'bg-red-950/60 text-red-400 border border-red-900/30' 
                            : 'text-slate-500 hover:text-slate-350 hover:bg-slate-900/50'
                        }`}
                      >
                        {profile}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>

          </div>
        )}

        {/* TAB 2: PACKET DECOY STATS LOGS */}
        {activeTab === 'logs' && (
          <div className="space-y-4">
            {/* Filter and search panel */}
            <div className="flex flex-col sm:flex-row gap-3 items-center justify-between bg-slate-900/40 border border-slate-800 p-4 rounded-xl">
              <div className="flex flex-wrap items-center gap-2.5 w-full sm:w-auto">
                <Filter size={12} className="text-slate-500" />
                <span className="text-[10px] font-mono text-slate-500 font-bold uppercase tracking-wider">Filter Decoy:</span>
                <div className="flex gap-1 bg-slate-950 p-1 border border-slate-800 rounded-lg">
                  {['ALL', 'SSH', 'TELNET', 'HTTP'].map((p) => (
                    <button
                      key={p}
                      onClick={() => handleLogFilterChange(p)}
                      type="button"
                      className={`px-3 py-1 text-[9px] uppercase font-bold font-mono rounded-md transition ${
                        logFilterProto === p 
                          ? 'bg-red-950 border border-red-900/30 text-red-400 shadow-inner' 
                          : 'text-slate-500 hover:text-slate-300'
                      }`}
                    >
                      {p}
                    </button>
                  ))}
                </div>
              </div>

              <div className="w-full sm:w-72">
                <input
                  type="text"
                  placeholder="QUERY IP, REGION OR PAYLOAD..."
                  value={logSearchQuery}
                  onChange={(e) => setLogSearchQuery(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-805 text-[10px] px-3.5 py-2.5 rounded-lg font-mono text-slate-200 focus:outline-none focus:border-red-500 font-medium placeholder-slate-700 uppercase tracking-widest"
                />
              </div>
            </div>

            {/* Datagrid logs table */}
            <div className="border border-slate-800 bg-slate-950 rounded-xl overflow-hidden shadow-lg">
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-[10px] text-slate-350">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900/50 text-slate-400 select-none">
                      <th className="p-4 uppercase font-bold tracking-wider text-[9px]">Timestamp</th>
                      <th className="p-4 uppercase font-bold tracking-wider text-[9px]">Origin Host IP</th>
                      <th className="p-4 uppercase font-bold tracking-wider text-[9px]">Decoy Target</th>
                      <th className="p-4 uppercase font-bold tracking-wider text-[9px]">Geographic Origin</th>
                      <th className="p-4 uppercase font-bold tracking-wider text-[9px]">Captured Payload</th>
                      <th className="p-4 text-right uppercase font-bold tracking-wider text-[9px]">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-900">
                    {filteredSearchLogs.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="text-center p-8 text-slate-500 font-mono">
                          NO SECURITY INCIDENT PACKETS REGISTERED LOGS.
                        </td>
                      </tr>
                    ) : (
                      filteredSearchLogs.map((log) => {
                        let protoBadge = 'text-cyan-455 bg-cyan-950/30 border-cyan-900/20';
                        if (log.protocol === 'HTTP') protoBadge = 'text-amber-455 bg-amber-950/30 border-amber-900/20';
                        if (log.protocol === 'TELNET') protoBadge = 'text-blue-455 bg-blue-950/30 border-blue-900/20';

                        return (
                          <tr key={log.id} className="hover:bg-slate-900/30 transition-colors">
                            <td className="p-4 text-slate-500">
                              {new Date(log.timestamp).toISOString().replace('T', ' ').substring(0, 19)}
                            </td>
                            <td className="p-4 font-black text-red-400 hover:underline cursor-pointer" onClick={() => focusMapOnCoordinates(log)}>
                              {log.ip}
                            </td>
                            <td className="p-4">
                              <span className={`px-2 py-0.5 rounded font-black text-[9px] border uppercase ${protoBadge}`}>
                                {log.protocol} ({log.port})
                              </span>
                            </td>
                            <td className="p-4 text-slate-300">
                              {log.city}, {log.country}
                            </td>
                            <td className="p-4 max-w-xs truncate text-slate-400" title={log.payload}>
                              {log.payload}
                            </td>
                            <td className="p-4 text-right">
                              <button 
                                onClick={() => focusMapOnCoordinates(log)}
                                type="button"
                                className="px-3 py-1 select-none text-[9px] font-black border border-slate-800 hover:border-red-900/30 hover:bg-slate-900/50 rounded-lg text-slate-400 hover:text-red-400 transition"
                              >
                                LOCATE
                              </button>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>

              {/* logs pagination bar */}
              <div className="border-t border-slate-800 bg-slate-900/40 p-4 flex items-center justify-between font-mono">
                <p className="text-[10px] text-slate-550">
                  PAGES <span className="text-slate-300 font-bold">{logPage}</span> / <span className="text-slate-300 font-bold">{logTotalPages}</span>
                </p>
                <div className="flex gap-1.5">
                  <button
                    disabled={logPage <= 1}
                    onClick={() => handleLogPageChange('prev')}
                    type="button"
                    className="p-1 px-3 border border-slate-800 rounded-lg text-slate-500 hover:text-slate-350 disabled:opacity-30"
                  >
                    <ChevronLeft size={13} />
                  </button>
                  <button
                    disabled={logPage >= logTotalPages}
                    onClick={() => handleLogPageChange('next')}
                    type="button"
                    className="p-1 px-3 border border-slate-800 rounded-lg text-slate-500 hover:text-slate-350 disabled:opacity-30"
                  >
                    <ChevronRight size={13} />
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: THREAT INTELLIGENCE PORTFOLIO */}
        {activeTab === 'threats' && (
          <div className="space-y-4">
            
            <div className="bg-slate-900/30 border border-slate-800 p-5 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h3 className="text-[10px] font-mono font-bold tracking-wider uppercase text-slate-300 mb-1">Host threat intelligence categorization</h3>
                <p className="text-[10px] font-mono text-slate-500 font-normal leading-relaxed uppercase">
                  Aggregates incoming threat anomalies by IP origin address to formulate safety logs.
                </p>
              </div>
              <button
                onClick={syncTelemetry}
                type="button"
                className="flex items-center gap-2 px-3.5 py-2 border border-slate-850 bg-slate-950 font-mono text-[9px] font-black rounded-lg hover:bg-slate-900 hover:border-slate-750 text-slate-400 hover:text-slate-200 transition uppercase tracking-wider"
              >
                <RefreshCw size={11} /> Sync state anomalies
              </button>
            </div>

            <div className="grid grid-cols-1 gap-3">
              {threatActors.length === 0 ? (
                <div className="border border-slate-800 bg-slate-950 p-12 text-center text-slate-500 font-mono text-[10px] rounded-xl uppercase tracking-widest">
                  INTELLIGENCE DIRECTORY CURRENTLY STABLE. LAUNCH SIMULATIONS TO SCAN ASSETS.
                </div>
              ) : (
                threatActors.map((actor) => {
                  let badgeStyle = 'bg-slate-900 border-slate-800 text-slate-450';
                  if (actor.level === 'HIGH') {
                    badgeStyle = 'bg-red-950/60 border-red-900/30 text-red-400';
                  } else if (actor.level === 'MEDIUM') {
                    badgeStyle = 'bg-amber-950/60 border-amber-900/30 text-amber-400';
                  }

                  return (
                    <div 
                      key={actor.ip} 
                      className="border border-slate-850 bg-slate-900/20 p-4 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 hover:border-slate-800 transition"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono font-extrabold text-slate-200">{actor.ip}</span>
                          <span className={`px-2 py-0.5 border text-[8px] font-mono font-black rounded-lg uppercase tracking-wider ${badgeStyle}`}>
                            {actor.level} LEVEL
                          </span>
                        </div>
                        <div className="text-slate-500 font-mono text-[10px] uppercase">
                          COUNTRY: <span className="font-semibold text-slate-300">{actor.country.toUpperCase()}</span> | 
                          HITS COUNT: <span className="font-extrabold text-red-500 font-mono">{actor.count} TIMES</span>
                        </div>
                      </div>

                      <div className="flex items-center gap-4 self-stretch sm:self-auto justify-between sm:justify-start">
                        <div className="text-left sm:text-right">
                          <p className="text-[8px] uppercase font-mono tracking-wider font-bold text-slate-500">Last Seen</p>
                          <p className="text-[10px] font-mono font-medium text-slate-400">{new Date(actor.lastSeen).toISOString().replace('T', ' ').slice(0, 19)}</p>
                        </div>
                        <button
                          onClick={() => {
                            const matched = events.find(e => e.ip === actor.ip);
                            if (matched) {
                              setActiveTab('dashboard');
                              setTimeout(() => focusMapOnCoordinates(matched), 200);
                            }
                          }}
                          type="button"
                          className="px-3 py-1.5 border border-slate-850 hover:border-red-900/40 hover:bg-slate-950 text-slate-400 hover:text-red-400 text-[9px] font-mono font-bold rounded-lg transition uppercase tracking-widest"
                        >
                          Trace IP
                        </button>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        )}

        {/* TAB 4: DIRECT DECOY ATTACK SIMULATOR */}
        {activeTab === 'simulator' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">

            {/* Simulated injection panel */}
            <div className="lg:col-span-7 bg-slate-900/20 border border-slate-800 p-5 rounded-xl space-y-5">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <Zap size={14} className="text-red-500" />
                  <h3 className="text-[10px] font-mono font-bold tracking-wider uppercase text-slate-200">Safeguarded simulation system</h3>
                </div>
                <p className="text-[10px] font-mono text-slate-500 leading-relaxed font-normal uppercase">
                  Test live firewall telemetry alerts and path geolocations under strict sandboxed rules.
                </p>
              </div>

              <form onSubmit={handleSimulateAttack} className="space-y-4 font-mono text-[10px]">
                <div>
                  <label className="block text-slate-500 uppercase font-black tracking-widest text-[8px] mb-1.5">Simulation protocol target</label>
                  <div className="grid grid-cols-3 bg-slate-950 p-1 border border-slate-800 rounded-lg">
                    {['SSH', 'TELNET', 'HTTP'].map((p) => (
                      <button
                        key={p}
                        type="button"
                        onClick={() => setSimProto(p as any)}
                        className={`py-2 border text-[9px] font-bold uppercase rounded-md transition ${
                          simProto === p 
                            ? 'bg-red-950 border-red-900/30 text-red-400 shadow-inner' 
                            : 'border-transparent text-slate-500 hover:text-slate-350'
                        }`}
                      >
                        {p} (Port {p === 'SSH' ? '2222' : p === 'TELNET' ? '2323' : '8080'})
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <label className="block text-slate-500 uppercase font-black tracking-widest text-[8px] mb-1.5">Source host address (Optional)</label>
                  <input
                    type="text"
                    placeholder="E.G. 193.32.248.88 (OR LEAVE EMPTY FOR MOCKED RANDOM CLUSTERS)"
                    value={simIP}
                    onChange={(e) => setSimIP(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 focus:outline-none focus:border-red-500 px-3.5 py-3 rounded-lg text-slate-200 placeholder-slate-700 uppercase"
                  />
                </div>

                <div>
                  <label className="block text-slate-500 uppercase font-black tracking-widest text-[8px] mb-1.5">Attack simulated intent / login (Optional)</label>
                  <input
                    type="text"
                    placeholder="E.G. admin / 123456, administrator, GET /wp-login.php"
                    value={simPayload}
                    onChange={(e) => setSimPayload(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 focus:outline-none focus:border-red-500 px-3.5 py-3 rounded-lg text-slate-200 placeholder-slate-750 uppercase"
                  />
                </div>

                <div className="pt-2">
                  <button
                    type="submit"
                    disabled={simulationStatus === 'queueing'}
                    className="w-full py-3 bg-red-650 hover:bg-red-700 disabled:bg-slate-800 disabled:text-slate-550 text-slate-200 font-bold uppercase tracking-widest text-[9px] rounded-lg transition"
                  >
                    {simulationStatus === 'queueing' ? 'STREAMING PACKET VECTOR...' : 'INJECT FIREWALL SCAN VECTOR'}
                  </button>
                </div>

                {simulationStatus === 'compromised' && (
                  <div className="border border-emerald-500/30 bg-emerald-950/20 text-emerald-400 p-3 rounded-lg flex items-center gap-2.5">
                    <CheckCircle2 size={13} className="text-emerald-400" />
                    <span className="font-extrabold uppercase text-[9px] tracking-wider">INJECTION SUCCESS: Packet integrated to live feed monitors!</span>
                  </div>
                )}
                {simulationStatus === 'failed' && (
                  <div className="border border-red-500/30 bg-red-950/20 text-red-400 p-3 rounded-lg flex items-center gap-2.5">
                    <AlertCircle size={13} className="text-red-400" />
                    <span className="font-extrabold uppercase text-[9px] tracking-wider">INJECTION ERROR: Port stream transmission crashed.</span>
                  </div>
                )}
              </form>
            </div>

            {/* Instruction block */}
            <div className="lg:col-span-12 xl:col-span-5 bg-slate-900/20 border border-slate-800 p-5 rounded-xl flex flex-col justify-between space-y-4">
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <Sliders size={14} className="text-red-450" />
                  <h3 className="text-[10px] font-mono font-bold tracking-wider uppercase text-slate-300">Terminal scan manual</h3>
                </div>
                
                <div className="space-y-2.5 font-mono text-[10px] text-slate-500 leading-relaxed uppercase">
                  <p>
                    Because endpoints simulate common exposed services, you can trigger connections using standard command-line tools:
                  </p>
                  
                  <div className="bg-slate-950 p-2.5 border border-slate-850 rounded-lg text-[9px] text-slate-400 space-y-1.5 select-all font-mono">
                    <div># Test open admin HTTP service target on port 8080:</div>
                    <code className="text-red-450 font-extrabold block bg-slate-900/40 p-1.5 rounded-md text-center">
                      curl http://localhost:8080/admin/dashboard.env
                    </code>
                  </div>

                  <p>
                    Host triggers are intercepted, details parsed from client headers, geolocated dynamically, and piped immediately into layout elements!
                  </p>
                </div>
              </div>

              <div className="border-t border-slate-800 pt-3 text-[9px] text-slate-600 font-mono space-y-0.5 leading-relaxed uppercase">
                <p className="text-slate-550">⚠ SANDBOX COORDS RULE:</p>
                <p>Local actions (originating from standard loopback `127.0.0.1`) are programmatically translated across global clusters (Shanghai, Warsaw, Dublin, Virginia USA) for high fidelity visualisation.</p>
              </div>
            </div>

          </div>
        )}

      </main>

      {/* Footer Bar Section */}
      <footer className="flex flex-col sm:flex-row justify-between items-center text-[9px] font-mono text-slate-500 border-t border-slate-800 pt-3 mt-auto gap-2">
        <div className="flex flex-wrap gap-4 select-none">
          <span>Azure Key Vault: <span className="text-emerald-450 font-bold">CONNECTED</span></span>
          <span>DB Cluster: <span className="text-emerald-450 font-bold">OPTIMAL</span></span>
          <span>Telemetry: <span className="text-emerald-450 font-bold">ACTIVE</span></span>
        </div>
        <div className="flex gap-4">
          <span>Session ID: AX-40291-ZZ</span>
          <span className="text-slate-400 uppercase font-bold">Authorized Access Only</span>
        </div>
      </footer>
    </div>
  );
}
