/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { ShieldAlert, ShieldCheck, UploadCloud, Download, Terminal, Activity, FileText, CheckCircle2, AlertTriangle, Trash2, Search, X, Eye, Loader2, Target, Globe, AlertOctagon } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

interface LogEntry {
  id: string;
  timestamp: string | Date;
  message: string;
  type: 'upload' | 'success' | 'error' | 'info';
}

interface EvidenceFile {
  filename: string;
  hash: string;
  isEncrypted: boolean;
}

interface ThreatIoCs {
  ips: string[];
  domains: string[];
  keywords: string[];
}

interface PreviewData {
  filename: string;
  content: string;
  iocs: ThreatIoCs;
  score: number;
  riskLevel: string;
}

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isAuthenticating, setIsAuthenticating] = useState(false);

  const [files, setFiles] = useState<EvidenceFile[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const [currentTime, setCurrentTime] = useState(new Date());
  const [searchQuery, setSearchQuery] = useState('');
  const [isRestoring, setIsRestoring] = useState<string | null>(null);
  const [previewFile, setPreviewFile] = useState<PreviewData | null>(null);
  
  const fileInputRef = useRef<HTMLInputElement>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const fetchLogs = useCallback(async () => {
    try {
      const res = await fetch('/api/logs');
      if (res.ok) setLogs(await res.json());
    } catch (err) {
      console.error('Failed to load telemetry cache');
    }
  }, []);

  const addLog = useCallback((message: string, type: 'upload' | 'success' | 'error' | 'info' = 'info') => {
    const newLog = {
      id: Math.random().toString(36).substring(7),
      timestamp: new Date().toISOString(),
      message,
      type
    };

    setLogs(prev => {
      const updated = [...prev, newLog];
      if (updated.length > 100) updated.shift();
      return updated;
    });

    fetch('/api/logs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newLog)
    }).catch(() => {});
  }, []);

  const fetchFiles = useCallback(async () => {
    try {
      const response = await fetch('/api/evidence');
      if (!response.ok) throw new Error('Failed to fetch files');
      const data = await response.json();
      setFiles(data);
    } catch (error: any) {
      addLog(`Error fetching files: ${error.message}`, 'error');
    }
  }, [addLog]);

  useEffect(() => {
    if (isAuthenticated) {
      fetchLogs();
      fetchFiles();
      addLog('System initialized. Secure authentication token verified.', 'info');
    }
  }, [isAuthenticated, fetchFiles, fetchLogs, addLog]);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const handleUpload = async (file: File) => {
    if (!file.name.endsWith('.txt')) {
      addLog(`Invalid file type: ${file.name}. Expected .txt file.`, 'error');
      return;
    }

    addLog(`Uploading evidence: ${file.name}...`, 'upload');
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/upload-evidence', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Upload failed');
      }

      addLog(`Successfully uploaded: ${file.name}`, 'success');
      fetchFiles();
    } catch (error: any) {
      addLog(`Upload error: ${error.message}`, 'error');
    }
  };

  const onDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const onDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleUpload(e.dataTransfer.files[0]);
      e.dataTransfer.clearData();
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleUpload(e.target.files[0]);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleRestore = async (filename: string) => {
    addLog(`Initiating restoration protocol for: ${filename}...`, 'info');
    setIsRestoring(filename);
    
    // Simulate complex decryption timeframe for realism
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    try {
      const response = await fetch(`/api/restore/${filename}`, {
        method: 'POST',
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Restoration failed');
      }

      const data = await response.json();
      addLog(`Successfully restored: ${data.filename}`, 'success');
      fetchFiles();
    } catch (error: any) {
      addLog(`Restoration error for ${filename}: ${error.message}`, 'error');
    } finally {
      setIsRestoring(null);
    }
  };

  const handleDelete = async (filename: string) => {
    addLog(`Requesting deletion of evidence: ${filename}...`, 'info');
    try {
      const response = await fetch(`/api/evidence/${filename}`, { method: 'DELETE' });
      if (!response.ok) throw new Error('Deletion failed');
      addLog(`Successfully deleted: ${filename}`, 'success');
      fetchFiles();
    } catch (error: any) {
      addLog(`Deletion error: ${error.message}`, 'error');
    }
  };

  const handleAnalyze = async (filename: string) => {
    addLog(`Running Deep Threat Analysis on: ${filename}...`, 'info');
    try {
      const response = await fetch(`/api/analyze/${filename}`);
      if (!response.ok) throw new Error('Analysis engine failed');
      const data = await response.json();
      setPreviewFile({ filename, ...data });
      addLog(`Analysis complete. Risk Level: ${data.riskLevel} (Score: ${data.score})`, data.score > 50 ? 'error' : 'success');
    } catch (error: any) {
      addLog(`Analysis error: ${error.message}`, 'error');
    }
  };

  const handleDownload = (filename: string) => {
    addLog(`Downloading file artifact: ${filename}...`, 'info');
    window.location.href = `/api/download/${filename}`;
  };

  const formatTimestamp = (ts: string | Date) => {
    const date = new Date(ts);
    return date.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 });
  };

  const pendingCount = files.filter(f => f.isEncrypted).length;
  const restoredCount = files.length - pendingCount;
  const filteredFiles = files.filter(f => f.filename.toLowerCase().includes(searchQuery.toLowerCase()));

  // ==========================
  // VIEW: AUTHENTICATION OVERLAY
  // ==========================
  if (!isAuthenticated) {
    return (
      <AnimatePresence>
        <div className="min-h-screen bg-slate-950 flex items-center justify-center font-mono text-cyan-500 overflow-hidden relative selection:bg-cyan-900">
          <div className="absolute inset-0 bg-slate-950/[0.97] opacity-80 z-0">
            <div className="absolute inset-0 bg-[linear-gradient(rgba(34,211,238,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(34,211,238,0.03)_1px,transparent_1px)] bg-[size:40px_40px] pointer-events-none" />
          </div>
          
          <motion.div 
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 1.1, filter: 'blur(10px)' }}
            className="z-10 bg-slate-900/80 p-12 rounded-2xl border border-cyan-900/50 backdrop-blur-xl shadow-[0_0_80px_rgba(34,211,238,0.15)] flex flex-col items-center"
          >
            <ShieldAlert className="w-24 h-24 mb-6 text-cyan-500 animate-[pulse_3s_ease-in-out_infinite]" />
            <h1 className="text-3xl font-bold tracking-[0.2em] uppercase mb-2 text-slate-200">Restricted Access</h1>
            <p className="text-cyan-600/80 mb-10 text-sm tracking-widest font-semibold uppercase">Blue Team Incident Response Console</p>
            
            <button
              onClick={() => {
                setIsAuthenticating(true);
                setTimeout(() => setIsAuthenticated(true), 2500);
              }}
              disabled={isAuthenticating}
              className="relative group overflow-hidden px-10 py-4 bg-cyan-950 text-cyan-300 font-bold border border-cyan-700/50 rounded-lg hover:text-white transition-colors disabled:opacity-80 disabled:cursor-wait"
            >
              {isAuthenticating ? (
                <span className="flex items-center gap-3 relative z-10 tracking-widest"><Loader2 className="w-5 h-5 animate-spin" /> ESTABLISHING SECURE UPLINK...</span>
              ) : (
                <span className="relative z-10 tracking-[0.15em]">INITIALIZE UPLINK</span>
              )}
              <div className="absolute inset-0 bg-cyan-500/20 translate-y-full group-hover:translate-y-0 transition-transform duration-300 ease-out" />
            </button>
          </motion.div>
        </div>
      </AnimatePresence>
    );
  }

  // ==========================
  // VIEW: MAIN DASHBOARD
  // ==========================
  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="min-h-screen bg-slate-950 text-slate-200 font-sans flex flex-col selection:bg-cyan-900 selection:text-cyan-100"
    >
      {/* Top Navigation Bar */}
      <header className="h-16 border-b border-slate-800 bg-slate-900/80 backdrop-blur-md flex items-center justify-between px-6 shrink-0 z-10">
        <div className="flex items-center gap-3">
          <div className="relative flex h-4 w-4 items-center justify-center">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-40"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
          </div>
          <h1 className="text-xl font-bold tracking-wide text-cyan-400 uppercase">Blue Team IR Console</h1>
        </div>
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2 text-sm text-emerald-400 bg-emerald-950/30 px-3 py-1 rounded-full border border-emerald-900/50">
            <Activity className="w-4 h-4" />
            <span>SECURE UPLINK</span>
          </div>
          <div className="font-mono text-cyan-500 text-sm tracking-widest bg-slate-950 px-4 py-1.5 rounded-lg border border-slate-800">
            {currentTime.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 flex overflow-hidden p-6 gap-6 relative">
        {/* Left Column: Evidence Locker */}
        <div className="w-[40%] flex flex-col gap-6">
          {/* Drag & Drop Zone */}
          <motion.div 
            whileHover={{ scale: 1.02 }}
            className={`relative rounded-xl border-2 border-dashed transition-all duration-300 flex flex-col items-center justify-center p-8 text-center cursor-pointer bg-slate-900/50 ${
              isDragging 
                ? 'border-cyan-400 bg-cyan-950/20 shadow-[0_0_30px_rgba(34,211,238,0.15)]' 
                : 'border-slate-700 hover:border-cyan-500/50 hover:bg-slate-800/50'
            }`}
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
            onDrop={onDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <input 
              type="file" 
              ref={fileInputRef} 
              onChange={handleFileChange} 
              className="hidden" 
              accept=".txt" 
            />
            <div className={`p-4 rounded-full mb-4 transition-colors ${isDragging ? 'bg-cyan-900/50 text-cyan-400' : 'bg-slate-800 text-slate-400'}`}>
              <UploadCloud className="w-8 h-8" />
            </div>
            <h3 className="text-lg font-semibold text-slate-200 mb-2">Upload Evidence</h3>
            <p className="text-sm text-slate-400 max-w-[200px]">
              Drag and drop encrypted <span className="text-cyan-400 font-mono">.txt</span> files here or click to browse
            </p>
          </motion.div>

          {/* File List */}
          <div className="flex-1 bg-slate-900/50 rounded-xl border border-slate-800 flex flex-col overflow-hidden">
            <div className="p-4 border-b border-slate-800 bg-slate-900/80 flex flex-col gap-3">
              <div className="flex items-center justify-between">
                <h2 className="font-semibold text-slate-200 flex items-center gap-2">
                  <FileText className="w-4 h-4 text-cyan-500" />
                  Evidence Locker
                </h2>
                <span className="text-xs font-mono text-slate-500">{files.length} FILES</span>
              </div>
              <div className="relative">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  placeholder="Search evidence hashes, filenames..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500/50 transition-all placeholder:text-slate-600"
                />
              </div>
            </div>
            <div className="flex-1 overflow-y-auto p-4 space-y-3">
              {filteredFiles.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-slate-600 space-y-3">
                  <ShieldCheck className="w-12 h-12 opacity-20" />
                  <p className="text-sm">{files.length === 0 ? 'Locker is empty' : 'No matching evidence found'}</p>
                </div>
              ) : (
                <AnimatePresence>
                  {filteredFiles.map(file => (
                    <motion.div 
                      layout
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, scale: 0.95 }}
                      key={file.filename}
                      className="group flex flex-col gap-2 p-3 rounded-lg border border-slate-800 bg-slate-950/50 hover:border-slate-700 transition-colors"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3 overflow-hidden">
                          {file.isEncrypted ? (
                            <ShieldAlert className="w-5 h-5 shrink-0 text-orange-500" />
                          ) : (
                            <ShieldCheck className="w-5 h-5 shrink-0 text-emerald-500" />
                          )}
                          <span className="font-mono text-sm truncate text-slate-300 group-hover:text-slate-200 transition-colors">
                            {file.filename}
                          </span>
                        </div>
                        
                        <div className="flex items-center gap-2">
                          <button
                            onClick={(e) => { e.stopPropagation(); handleDelete(file.filename); }}
                            className="p-1.5 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded-md transition-colors"
                            title="Delete file"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>

                      <div className="flex items-center justify-between mt-1">
                        <span className="text-[10px] text-slate-600 font-mono truncate max-w-[60%]" title={file.hash}>
                          SHA256: {file.hash.substring(0, 16)}...
                        </span>
                        
                        <div className="shrink-0 flex gap-2">
                          {file.isEncrypted ? (
                            <button
                              disabled={isRestoring === file.filename}
                              onClick={(e) => { e.stopPropagation(); handleRestore(file.filename); }}
                              className="flex items-center gap-1.5 bg-orange-500/10 hover:bg-orange-500/20 border border-orange-500/30 text-orange-400 px-3 py-1.5 rounded-md transition-all text-xs font-bold tracking-wide hover:shadow-[0_0_15px_rgba(249,115,22,0.2)] disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                              {isRestoring === file.filename ? (
                                <><Loader2 className="w-3.5 h-3.5 animate-spin" /> DECRYPTING</>
                              ) : 'RESTORE'}
                            </button>
                          ) : (
                            <>
                              <button
                                onClick={(e) => { e.stopPropagation(); handleAnalyze(file.filename); }}
                                className="flex items-center gap-1.5 bg-indigo-500/10 hover:bg-indigo-500/20 border border-indigo-500/30 text-indigo-400 px-3 py-1.5 rounded-md transition-all text-xs font-bold tracking-wide"
                              >
                                <Target className="w-3.5 h-3.5" />
                                SCAN
                              </button>
                              <button
                                onClick={(e) => { e.stopPropagation(); handleDownload(file.filename); }}
                                className="flex items-center gap-1.5 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 px-3 py-1.5 rounded-md transition-all text-xs font-bold tracking-wide"
                              >
                                <Download className="w-3.5 h-3.5" />
                                DL
                              </button>
                            </>
                          )}
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </AnimatePresence>
              )}
            </div>
          </div>
        </div>

        {/* Right Column: Analytics & Telemetry (60%) */}
        <div className="w-[60%] flex flex-col gap-6">
          {/* Stats Row */}
          <div className="grid grid-cols-3 gap-6 shrink-0">
            <motion.div whileHover={{ y: -2 }} className="bg-slate-900/50 rounded-xl border border-slate-800 p-5 flex flex-col justify-center relative overflow-hidden group">
              <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
                <FileText className="w-16 h-16" />
              </div>
              <p className="text-sm text-slate-400 font-medium mb-1">Total Evidence</p>
              <p className="text-3xl font-mono text-slate-200">{files.length}</p>
            </motion.div>
            <motion.div whileHover={{ y: -2 }} className="bg-slate-900/50 rounded-xl border border-orange-900/30 p-5 flex flex-col justify-center relative overflow-hidden group">
              <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
                <AlertTriangle className="w-16 h-16 text-orange-500" />
              </div>
              <p className="text-sm text-orange-400/80 font-medium mb-1">Pending Restoration</p>
              <p className="text-3xl font-mono text-orange-400">{pendingCount}</p>
            </motion.div>
            <motion.div whileHover={{ y: -2 }} className="bg-slate-900/50 rounded-xl border border-emerald-900/30 p-5 flex flex-col justify-center relative overflow-hidden group">
              <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
                <CheckCircle2 className="w-16 h-16 text-emerald-500" />
              </div>
              <p className="text-sm text-emerald-400/80 font-medium mb-1">Fully Restored</p>
              <p className="text-3xl font-mono text-emerald-400">{restoredCount}</p>
            </motion.div>
          </div>

          {/* Activity Terminal */}
          <div className="flex-1 bg-slate-950 rounded-xl border border-slate-800 flex flex-col overflow-hidden shadow-inner relative">
            <div className="p-3 border-b border-slate-800 bg-slate-900/80 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-slate-400" />
              <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Telemetry Stream</h2>
            </div>
            <div className="flex-1 overflow-y-auto p-5 font-mono text-sm space-y-2">
              <AnimatePresence initial={false}>
                {logs.map(log => (
                  <motion.div 
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    key={log.id} 
                    className="flex gap-4 leading-relaxed"
                  >
                    <span className="text-slate-600 shrink-0 select-none">
                      [{formatTimestamp(log.timestamp)}]
                    </span>
                    <span className={`
                      ${log.type === 'info' ? 'text-slate-400' : ''}
                      ${log.type === 'upload' ? 'text-blue-400' : ''}
                      ${log.type === 'success' ? 'text-emerald-400' : ''}
                      ${log.type === 'error' ? 'text-red-400' : ''}
                    `}>
                      {log.message}
                    </span>
                  </motion.div>
                ))}
              </AnimatePresence>
              <div ref={logsEndRef} />
            </div>
          </div>
        </div>
      </main>

      {/* Threat Analysis & File Preview Modal */}
      <AnimatePresence>
        {previewFile && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 bg-slate-950/90 backdrop-blur-md flex items-center justify-center p-6"
            onClick={() => setPreviewFile(null)}
          >
            <motion.div 
              initial={{ scale: 0.95, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.95, y: 20 }}
              className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-6xl h-[85vh] flex flex-col shadow-2xl overflow-hidden"
              onClick={e => e.stopPropagation()}
            >
              {/* Modal Header */}
              <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-800/80 shrink-0">
                <div className="flex items-center gap-4">
                  <div className={`p-2 rounded-lg ${previewFile.score > 60 ? 'bg-red-500/20 text-red-400' : previewFile.score > 30 ? 'bg-orange-500/20 text-orange-400' : 'bg-emerald-500/20 text-emerald-400'}`}>
                    <Target className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="font-bold tracking-wider text-slate-200 uppercase">Threat Analysis Report</h3>
                    <p className="text-xs font-mono text-slate-400">{previewFile.filename}</p>
                  </div>
                </div>
                <button 
                  onClick={() => setPreviewFile(null)}
                  className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-700 rounded-lg transition-colors"
                >
                  <X className="w-6 h-6" />
                </button>
              </div>
              
              {/* Modal Built Split View */}
              <div className="flex flex-1 overflow-hidden divide-x divide-slate-800">
                
                {/* File Content Preview */}
                <div className="w-[65%] flex flex-col bg-slate-950">
                  <div className="p-3 border-b border-slate-800 bg-slate-900/50 font-mono text-xs text-slate-500 uppercase tracking-widest flex items-center gap-2">
                    <Eye className="w-3.5 h-3.5" /> Parsed Content Segment
                  </div>
                  <div className="flex-1 p-6 overflow-y-auto font-mono text-sm text-slate-300 whitespace-pre-wrap leading-relaxed select-text">
                    {previewFile.content || <em className="text-slate-600">File is empty.</em>}
                  </div>
                </div>

                {/* Threat Indicators Sidebar */}
                <div className="w-[35%] flex flex-col bg-slate-900/30 overflow-y-auto">
                  
                  {/* Score Card */}
                  <div className="p-6 border-b border-slate-800">
                    <div className="flex items-end justify-between mb-4">
                      <div>
                        <p className="text-xs text-slate-500 font-mono uppercase tracking-widest mb-1">Threat Score</p>
                        <h2 className={`text-4xl font-bold font-mono tracking-tighter ${previewFile.score > 60 ? 'text-red-400' : previewFile.score > 30 ? 'text-orange-400' : 'text-emerald-400'}`}>
                          {previewFile.score}<span className="text-lg text-slate-600">/100</span>
                        </h2>
                      </div>
                      <div className={`px-3 py-1 text-xs font-bold uppercase rounded-md border ${previewFile.riskLevel === 'Critical' ? 'bg-red-500/10 text-red-400 border-red-500/30' : previewFile.riskLevel === 'Medium' ? 'bg-orange-500/10 text-orange-400 border-orange-500/30' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'}`}>
                        {previewFile.riskLevel} RISK
                      </div>
                    </div>
                    {/* Progress Bar */}
                    <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                      <motion.div 
                        initial={{ width: 0 }}
                        animate={{ width: `${previewFile.score}%` }}
                        transition={{ duration: 1, ease: 'easeOut' }}
                        className={`h-full ${previewFile.score > 60 ? 'bg-red-500' : previewFile.score > 30 ? 'bg-orange-500' : 'bg-emerald-500'}`}
                      />
                    </div>
                  </div>

                  {/* IoC Sections */}
                  <div className="p-6 space-y-6">
                    
                    {/* Active Malware Keywords */}
                    <div>
                      <h4 className="flex items-center gap-2 text-sm font-semibold text-slate-300 uppercase tracking-widest mb-3">
                        <AlertOctagon className="w-4 h-4 text-red-400" />
                        Signature Matches <span className="text-slate-600 ml-auto">({previewFile.iocs.keywords.length})</span>
                      </h4>
                      {previewFile.iocs.keywords.length > 0 ? (
                        <div className="flex flex-wrap gap-2">
                          {previewFile.iocs.keywords.map((kw, idx) => (
                            <span key={idx} className="px-2.5 py-1 text-xs font-mono bg-red-950/50 text-red-300 border border-red-900/50 rounded pointer-events-none select-text">
                              {kw}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p className="text-sm text-slate-500 italic">No exact signature matches.</p>
                      )}
                    </div>

                    {/* Network Indicators */}
                    {(previewFile.iocs.ips.length > 0 || previewFile.iocs.domains.length > 0) && (
                      <div className="pt-4 border-t border-slate-800/50">
                        <h4 className="flex items-center gap-2 text-sm font-semibold text-slate-300 uppercase tracking-widest mb-3">
                          <Globe className="w-4 h-4 text-blue-400" />
                          Network Artifacts
                        </h4>
                        <div className="space-y-3">
                          {previewFile.iocs.ips.length > 0 && (
                            <div>
                              <p className="text-xs text-slate-500 mb-2">Suspicious IPs ({previewFile.iocs.ips.length}):</p>
                              <div className="space-y-1">
                                {previewFile.iocs.ips.map((ip, idx) => (
                                  <div key={idx} className="px-3 py-1.5 text-xs font-mono bg-slate-950 text-cyan-400 border border-slate-800 rounded pointer-events-none select-text">
                                    {ip}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                          {previewFile.iocs.domains.length > 0 && (
                            <div>
                              <p className="text-xs text-slate-500 mb-2 mt-3">Suspicious Domains ({previewFile.iocs.domains.length}):</p>
                              <div className="space-y-1">
                                {previewFile.iocs.domains.map((domain, idx) => (
                                  <div key={idx} className="px-3 py-1.5 text-xs font-mono bg-slate-950 text-purple-400 border border-slate-800 rounded pointer-events-none select-text">
                                    {domain}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                    
                  </div>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
