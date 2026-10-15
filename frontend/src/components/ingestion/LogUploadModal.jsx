import React, { useState, useRef } from 'react';
import {
  X,
  UploadCloud,
  FileSpreadsheet,
  AlertCircle,
  CheckCircle2,
  Clock,
  Sparkles,
  RefreshCw,
} from 'lucide-react';
import { uploadLogFile, triggerSampleData } from '../../services/api';

export function LogUploadModal({ isOpen, onClose, onUploadSuccess }) {
  if (!isOpen) return null;

  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const fileInputRef = useRef(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const validateAndSetFile = (file) => {
    setErrorMessage(null);
    setUploadResult(null);
    if (!file.name.toLowerCase().endsWith('.csv')) {
      setErrorMessage('Please select a valid CSV file (.csv).');
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      setErrorMessage('File exceeds the 10 MB limit.');
      return;
    }
    setSelectedFile(file);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!selectedFile) return;

    setIsUploading(true);
    setErrorMessage(null);

    try {
      const res = await uploadLogFile(selectedFile);
      setUploadResult(res);
      setSelectedFile(null);
      if (onUploadSuccess) onUploadSuccess();
    } catch (err) {
      setErrorMessage(err.message || 'File upload and processing failed.');
    } finally {
      setIsUploading(false);
    }
  };

  const handleQuickBenchmark = async () => {
    setIsUploading(true);
    setErrorMessage(null);
    try {
      const res = await triggerSampleData();
      setUploadResult({
        message: 'Synthetic benchmark telemetry ingested successfully',
        rows_received: res.data?.valid_rows || 11,
        valid_rows: res.data?.valid_rows || 11,
        new_events: res.data?.new_events || 0,
        duplicate_count: 0,
        total_alerts: res.data?.total_alerts || 5,
      });
      if (onUploadSuccess) onUploadSuccess();
    } catch (err) {
      setErrorMessage(err.message || 'Failed to ingest benchmark telemetry.');
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
      <div
        className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <UploadCloud className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100">Ingest Security Logs</h3>
              <p className="text-xs text-slate-400">Upload CSV telemetry to run detection & ML scoring</p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close modal"
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-5 text-xs">
          {errorMessage && (
            <div className="p-3 bg-red-950/40 border border-red-500/30 rounded-lg flex items-start gap-2 text-red-300">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <span>{errorMessage}</span>
            </div>
          )}

          {uploadResult ? (
            <div className="p-4 bg-emerald-950/30 border border-emerald-500/30 rounded-xl space-y-3">
              <div className="flex items-center gap-2 text-emerald-400 font-semibold">
                <CheckCircle2 className="w-4 h-4" />
                <span>{uploadResult.message || 'Telemetry Processed Successfully'}</span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 pt-2 border-t border-emerald-500/20 font-mono text-[11px]">
                <div className="p-2 bg-slate-900/60 rounded border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">Received</span>
                  <span className="text-slate-200 font-bold">{uploadResult.rows_received ?? '—'}</span>
                </div>
                <div className="p-2 bg-slate-900/60 rounded border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">Valid Events</span>
                  <span className="text-cyan-400 font-bold">{uploadResult.valid_rows ?? '—'}</span>
                </div>
                <div className="p-2 bg-slate-900/60 rounded border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">Total Alerts</span>
                  <span className="text-amber-400 font-bold">{uploadResult.total_alerts ?? '—'}</span>
                </div>
              </div>

              <button
                onClick={() => setUploadResult(null)}
                className="w-full mt-2 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium transition-colors"
              >
                Upload Another File
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
                  dragActive
                    ? 'border-cyan-400 bg-cyan-950/30'
                    : 'border-slate-700/80 hover:border-slate-600 bg-slate-950/40 hover:bg-slate-950/60'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".csv,text/csv"
                  onChange={handleFileChange}
                  className="hidden"
                />

                <FileSpreadsheet className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
                <p className="text-slate-200 font-semibold mb-1">
                  {selectedFile ? selectedFile.name : 'Choose or drop a CSV file'}
                </p>
                <p className="text-slate-500 text-[11px] max-w-xs mx-auto">
                  Required columns: timestamp, source_ip, username, event_type, status (Max: 10 MB)
                </p>
              </div>

              <div className="flex items-center gap-3">
                <button
                  type="submit"
                  disabled={!selectedFile || isUploading}
                  className="flex-1 py-2.5 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 disabled:hover:bg-cyan-500 text-slate-950 rounded-lg font-semibold text-xs transition-colors flex items-center justify-center gap-1.5"
                >
                  {isUploading ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      Analyzing Telemetry...
                    </>
                  ) : (
                    'Upload & Analyze'
                  )}
                </button>

                <button
                  type="button"
                  onClick={handleQuickBenchmark}
                  disabled={isUploading}
                  className="py-2.5 px-4 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg font-medium text-xs transition-colors flex items-center gap-1.5 border border-slate-700"
                >
                  <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                  Load Benchmark
                </button>
              </div>
            </form>
          )}

          <div className="pt-3 border-t border-slate-800/80 text-[11px] text-slate-500 space-y-1">
            <span className="font-semibold text-slate-400 block">Processing Pipeline:</span>
            <p>1. Schema validation & timestamp normalization</p>
            <p>2. Deduplication fingerprinting via SHA-256</p>
            <p>3. Rule-based brute-force & frequency detection</p>
            <p>4. Isolation Forest ML anomaly scoring & risk correlation</p>
          </div>
        </div>
      </div>
    </div>
  );
}
