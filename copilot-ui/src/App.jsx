/**
 * Malcolm Copilot — Dual-Persona Demonstration UI
 * =================================================
 * 
 * PURPOSE:
 *   Interactive demo of an LLM copilot for Malcolm (https://github.com/cisagov/Malcolm).
 *   Two analyst personas view the SAME network capture data through different lenses:
 *     - SOC Analyst: network forensics, alert triage, threat hunting
 *     - System Engineer: process state, control loops, digital control surface exposure
 *
 * ARCHITECTURE:
 *   - Single-page React app (runs in Claude artifact or standalone Vite project)
 *   - Talks to malcolm-llm-gateway via REST (GET /health, POST /chat, POST /tools/{name})
 *   - Falls back to built-in mock data when gateway is unavailable (demo mode)
 *   - All mock data models a midstream gas compressor station:
 *       Solar Mars 100-16000S turbine + C65 centrifugal compressor
 *       Turbotronic 5 controller + Rockwell ControlLogix station PLC
 *       EtherNet/IP (CIP) as primary OT protocol
 *
 * TAKING THIS TO PRODUCTION:
 *   1. Extract mock data into gateway replay handlers
 *   2. Replace GATEWAY_URL with env var: import.meta.env.VITE_GATEWAY_URL
 *   3. Break into component files: Theme.tsx, Evidence.tsx, MarkdownRenderer.tsx, etc.
 *   4. Add streaming support for POST /chat (SSE or WebSocket)
 *   5. Wire asset inventory to Malcolm's Zeek logs + device profiling
 *   6. Wire process state to Malcolm's Arkime sessions + OT protocol parsers
 *   7. Control path analysis becomes a first-class Malcolm analytic
 *
 * STYLING:
 *   INL.gov-inspired palette. Light/dark toggle. Source Sans 3 + Source Code Pro fonts.
 */

import { useState, useEffect, useCallback, useRef, createContext, useContext } from "react";

/* ============================================================================
 * THEME SYSTEM
 * Two complete palettes — every color used in the UI is defined here.
 * To customize for your org, edit these objects only.
 * ========================================================================= */

const THEMES = {
  light: {
    bg: "#f5f6f8",
    bgPanel: "#ffffff",
    bgPanel2: "#fafbfc",
    bgEvidence: "#f0f2f5",
    bgCode: "#f5f6f8",
    bgHeader: "#003b71",         // INL navy
    bgHeaderText: "#ffffff",
    text: "#1a2332",
    textSecondary: "#4a5568",
    textMuted: "#8896a4",
    border: "#d8dde4",
    borderLight: "#e8ecf0",
    accent: "#003b71",           // INL navy — SOC color
    accentBg: "#e8f0fa",
    green: "#5b9a40",            // INL green — System Engineer color
    greenBg: "#ecf5e8",
    greenText: "#3d7028",
    red: "#c62828",
    redBg: "#fce8e8",
    redText: "#a21c1c",
    yellow: "#e8a317",
    yellowBg: "#fef8e8",
    yellowText: "#a17210",
    pillBg: "#e8ecf0",
    pillBorder: "#d0d8e0",
    tableAlt: "#f0f2f5",
    tableHeader: "#f5f6f8",
    btnPrimary: "#003b71",
    btnPrimaryText: "#fff",
    btnSecondary: "#f0f2f5",
    btnSecondaryText: "#1a2332",
    btnSecondaryBorder: "#d0d8e0",
    evidenceHeader: "#f5f7fa",
    shadow: "0 1px 3px rgba(0,0,0,0.08)",
  },
  dark: {
    bg: "#0f1419",
    bgPanel: "#1a2332",
    bgPanel2: "#151d2b",
    bgEvidence: "#111927",
    bgCode: "#0d1117",
    bgHeader: "#0d1117",
    bgHeaderText: "#e2e8f0",
    text: "#e2e8f0",
    textSecondary: "#94a3b8",
    textMuted: "#5a6b7f",
    border: "#2d3a4d",
    borderLight: "#243044",
    accent: "#4a9eff",
    accentBg: "#1a2d45",
    green: "#6dbe4b",
    greenBg: "#1a2d1a",
    greenText: "#7dd65a",
    red: "#ef5350",
    redBg: "#2d1a1a",
    redText: "#ff7070",
    yellow: "#ffc107",
    yellowBg: "#2d2a1a",
    yellowText: "#ffd54f",
    pillBg: "#1e2d40",
    pillBorder: "#2d3a4d",
    tableAlt: "#111927",
    tableHeader: "#0d1117",
    btnPrimary: "#4a9eff",
    btnPrimaryText: "#0f1419",
    btnSecondary: "#1e2d40",
    btnSecondaryText: "#e2e8f0",
    btnSecondaryBorder: "#2d3a4d",
    evidenceHeader: "#131b28",
    shadow: "0 1px 3px rgba(0,0,0,0.3)",
  },
};

const ThemeContext = createContext(THEMES.light);
function useTheme() {
  return useContext(ThemeContext);
}

/* ============================================================================
 * CONFIGURATION
 * ========================================================================= */

/** Set to gateway URL when connected; empty string = mock demo mode */
const GATEWAY_URL = "";

/** Health check polling interval (ms) */
const HEALTH_INTERVAL = 10000;

/** Time window presets shown in the left panel */
const TIME_PRESETS = [
  { value: "last_15m", label: "Last 15m" },
  { value: "last_60m", label: "Last 60m" },
  { value: "last_4h",  label: "Last 4h" },
  { value: "custom",   label: "Custom" },
];

/* ============================================================================
 * DEMO QUERIES — one set per persona
 * These pre-fill the textarea and auto-submit when clicked.
 * In production, GET /demo/questions would supply these per-view.
 * ========================================================================= */

const SOC_DEMOS = [
  { label: "Top Talkers",     prompt: "Show me the top talkers by volume in the last hour. Which source IPs are generating the most traffic?" },
  { label: "Beaconing Check", prompt: "Are there any hosts exhibiting beaconing-like behavior? Look for regular interval connections to external IPs." },
  { label: "Suricata Triage", prompt: "Triage the latest Suricata alerts. Group by severity and signature, and highlight any critical findings." },
  { label: "OT Segmentation", prompt: "Check OT network segmentation. Are there any unexpected connections crossing IT/OT boundaries?" },
];

const SYS_DEMOS = [
  { label: "Process State",         prompt: "Show me the current compressor station process state. What are the key operating parameters?" },
  { label: "Asset Inventory",       prompt: "What assets are on the OT network and what protocols are they using? Show me the full inventory." },
  { label: "Exposed Control Paths", prompt: "Which control paths to safety-critical functions lack independent non-digital safety barriers?" },
  { label: "Correlate SSH + Process", prompt: "Correlate the anomalous SSH session to 10.50.20.10 with any process value changes or control loop deviations." },
];

/* ============================================================================
 * MOCK HEALTH RESPONSE
 * Mirrors GET /health from the gateway.
 * ========================================================================= */

const MOCK_HEALTH = {
  status: "ok",
  backend_mode: "replay",
  model: "ollama:qwen2.5:7b-instruct",
  opensearch: { reachable: false },
  arkime: { reachable: false },
  replay_data_loaded: true,
  version: "0.1.0",
};

/* ============================================================================
 * OT DOMAIN DATA
 * Models a midstream gas compressor station. This data feeds the System
 * Engineer view's mock responses.
 * ========================================================================= */

/** Asset inventory — would come from Malcolm's Zeek device profiling in production */
const ASSETS = [
  { ip: "10.50.20.10", name: "Turbotronic 5 Controller", zone: "OT-Field",   type: "Turbine Controller", protocols: "EtherNet/IP, CIP",           vendor: "Solar Turbines", criticality: "Safety-Critical" },
  { ip: "10.50.20.15", name: "ControlLogix Station PLC", zone: "OT-Field",   type: "Station PLC",        protocols: "EtherNet/IP, CIP",           vendor: "Rockwell",       criticality: "Safety-Critical" },
  { ip: "10.50.20.20", name: "Bently Nevada 3500",       zone: "OT-Field",   type: "Vibration Monitor",  protocols: "Modbus TCP",                 vendor: "Baker Hughes",   criticality: "Protective" },
  { ip: "10.50.10.21", name: "HMI Workstation",          zone: "OT-Control", type: "HMI",                protocols: "CIP, RDP",                   vendor: "Rockwell/Win",   criticality: "Operational" },
  { ip: "10.50.10.5",  name: "Historian Server",         zone: "OT-Control", type: "Historian",          protocols: "Modbus TCP, SQL",             vendor: "OSIsoft PI",     criticality: "Operational" },
  { ip: "10.50.10.8",  name: "Engineering Workstation",  zone: "OT-Control", type: "EWS",                protocols: "CIP, SSH, SolConnect",        vendor: "Windows",        criticality: "High" },
  { ip: "10.50.30.1",  name: "DMZ Historian Relay",      zone: "DMZ",        type: "Data Relay",         protocols: "Modbus TCP, HTTPS",           vendor: "Linux",          criticality: "Low" },
  { ip: "10.50.40.30", name: "IT Workstation (suspect)",  zone: "IT",         type: "Workstation",        protocols: "SSH, HTTP",                  vendor: "Windows",        criticality: "Under Investigation" },
];

/**
 * Process state snapshot — would come from historian replay or Zeek OT protocol parsing.
 * Models the Solar Mars 100-16000S + C65 at a typical midstream operating point.
 */
const PROCESS_VALUES = [
  { tag: "PT-1001",  desc: "Suction Pressure",    value: 650,   unit: "psig",  lo: 600,  hi: 720,   status: "NORMAL" },
  { tag: "PT-1002",  desc: "Discharge Pressure",  value: 1170,  unit: "psig",  lo: 1000, hi: 1250,  status: "NORMAL" },
  { tag: "CR-CALC",  desc: "Compression Ratio",   value: 1.80,  unit: "",      lo: 1.5,  hi: 2.0,   status: "NORMAL" },
  { tag: "ST-2001",  desc: "GG Turbine Speed",    value: 9800,  unit: "RPM",   lo: 8000, hi: 10200, status: "NORMAL" },
  { tag: "ST-2002",  desc: "Power Turbine Speed",  value: 6198,  unit: "RPM",   lo: 5500, hi: 6500,  status: "NORMAL" },
  { tag: "TT-2001",  desc: "Turbine Inlet Temp",  value: 1680,  unit: "\u00B0F", lo: 1400, hi: 1750,  status: "NORMAL" },
  { tag: "TT-1002",  desc: "Discharge Temp",      value: 185,   unit: "\u00B0F", lo: 140,  hi: 220,   status: "NORMAL" },
  { tag: "FT-1001",  desc: "Gas Flow Rate",       value: 42,    unit: "MMSCFD", lo: 30,   hi: 55,    status: "NORMAL" },
  { tag: "SURGE-M",  desc: "Surge Margin",        value: 12,    unit: "%",     lo: 5,    hi: 25,    status: "NORMAL" },
];

/** Control loop health — would come from historian + controller status polling */
const CONTROL_LOOPS = [
  { loop: "Speed Governor",     setpoint: 6200,  actual: 6198,         deviation_pct: 0.03, status: "HEALTHY",  controller: "T5" },
  { loop: "Suction Pressure",   setpoint: 650,   actual: 650,          deviation_pct: 0.0,  status: "HEALTHY",  controller: "CLX" },
  { loop: "Anti-Surge Control", setpoint: "Auto", actual: "12% margin", deviation_pct: null, status: "WATCHING", controller: "CLX" },
  { loop: "TIT Limit",          setpoint: 1750,  actual: 1680,         deviation_pct: 4.0,  status: "HEALTHY",  controller: "T5" },
];

/**
 * CONTROL PATH ANALYSIS
 * This is the core System Engineer insight: which digital control paths
 * to safety-critical functions lack independent non-digital safety barriers?
 *
 * In production, this would be a Malcolm analytic combining:
 *   - Zeek CIP/Modbus protocol logs (observed command paths)
 *   - Asset configuration database (what functions each controller manages)
 *   - Safety system audit data (which paths have mechanical/analog backups)
 */
const CONTROL_PATHS = [
  {
    id: "CP-1",
    path: "HMI \u2192 CIP Write \u2192 T5 Controller \u2192 Speed Governor",
    target: "Gas Turbine Speed Setpoint",
    digital_protection: "T5 firmware overspeed trip",
    non_digital_protection: "NONE \u2014 mechanical overspeed trip removed during retrofit",
    risk: "HIGH",
    consequence: "CIP write could exceed safe RPM before digital trip engages",
    affected_asset: "10.50.20.10",
    protocol: "EtherNet/IP (CIP)",
  },
  {
    id: "CP-2",
    path: "ControlLogix \u2192 CIP \u2192 Anti-Surge Valve",
    target: "Anti-Surge Recycle Valve Position",
    digital_protection: "Anti-surge algorithm in PLC",
    non_digital_protection: "NONE \u2014 no mechanical surge relief valve",
    risk: "HIGH",
    consequence: "Closing anti-surge valve during high flow causes compressor surge",
    affected_asset: "10.50.20.15",
    protocol: "EtherNet/IP (CIP)",
  },
  {
    id: "CP-3",
    path: "Any OT device \u2192 Modbus FC6 \u2192 Historian",
    target: "Historian Tag Values (operator display)",
    digital_protection: "NONE \u2014 Modbus has no authentication",
    non_digital_protection: "N/A (data integrity, not safety-critical)",
    risk: "MEDIUM",
    consequence: "Spoofed historian hides real process state from operators",
    affected_asset: "10.50.10.5",
    protocol: "Modbus TCP",
  },
  {
    id: "CP-4",
    path: "CIP \u2192 Fuel Gas Valve Command",
    target: "Fuel Gas Shutoff Valve",
    digital_protection: "T5 flame-out detection",
    non_digital_protection: "Mechanical spring-return shutoff (fail-closed)",
    risk: "LOW",
    consequence: "Mechanical valve provides independent non-digital protection",
    affected_asset: "10.50.20.10",
    protocol: "EtherNet/IP (CIP)",
  },
];

/* ============================================================================
 * UTILITY FUNCTIONS
 * ========================================================================= */

function generateSessionId() {
  return "s-" + Math.random().toString(36).slice(2, 10);
}

function copyToClipboard(data) {
  const text = typeof data === "string" ? data : JSON.stringify(data, null, 2);
  navigator.clipboard.writeText(text);
}

function formatTimestamp(ts) {
  if (!ts) return "\u2014";
  try {
    return new Date(ts).toLocaleTimeString("en-US", {
      hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  } catch {
    return String(ts);
  }
}
/* ============================================================================
 * MOCK RESPONSES — SOC ANALYST VIEW
 *
 * Each response mirrors the POST /chat response schema:
 *   { answer: string, evidence: Evidence[], suggested_pivots: Pivot[] }
 *
 * Evidence objects follow the gateway contract:
 *   { evidence_id, tool, source, time_range, query, summary, exemplars }
 * ========================================================================= */

const SOC_MOCKS = {
  default: {
    answer: "## Analysis Complete\n\nBased on the replay dataset:\n\n- **12 unique source IPs** observed in the capture window\n- **3 hosts** account for **78%** of all traffic volume\n- Top talker `10.50.10.21` sent **42 sessions** using CIP (Common Industrial Protocol)\n- Secondary talker `10.50.40.30` connects to `10.50.20.10:2222` \u2014 non-standard SSH in OT zone\n\n**Recommendation:** Investigate SSH on port 2222 crossing OT segments. Atypical for ICS networks.",
    evidence: [
      {
        evidence_id: "ev-001", tool: "os_top_values", source: "replay",
        time_range: { start: "2025-02-25T10:00:00Z", end: "2025-02-25T11:00:00Z" },
        query: { field: "source.ip", filter: null, size: 10 },
        summary: {
          total_docs: 120,
          top_values: [
            { value: "10.50.10.21", count: 42 }, { value: "10.50.40.30", count: 28 },
            { value: "10.50.10.5", count: 23 },  { value: "10.50.20.10", count: 15 },
            { value: "10.50.30.1", count: 12 },
          ],
        },
        exemplars: [
          { "@timestamp": "2025-02-25T10:45:12Z", "source.ip": "10.50.10.21", "destination.ip": "10.50.20.10", "destination.port": 44818, "network.protocol": "cip" },
          { "@timestamp": "2025-02-25T10:44:58Z", "source.ip": "10.50.10.21", "destination.ip": "10.50.20.15", "destination.port": 44818, "network.protocol": "cip" },
          { "@timestamp": "2025-02-25T10:43:30Z", "source.ip": "10.50.40.30", "destination.ip": "10.50.20.10", "destination.port": 2222, "network.protocol": "ssh" },
          { "@timestamp": "2025-02-25T10:42:11Z", "source.ip": "10.50.10.5", "destination.ip": "10.50.30.1", "destination.port": 502, "network.protocol": "modbus" },
          { "@timestamp": "2025-02-25T10:41:05Z", "source.ip": "10.50.40.30", "destination.ip": "10.50.20.10", "destination.port": 2222, "network.protocol": "ssh" },
        ],
      },
      {
        evidence_id: "ev-002", tool: "os_query_logs", source: "replay",
        time_range: { start: "2025-02-25T10:00:00Z", end: "2025-02-25T11:00:00Z" },
        query: { query_string: "destination.port:2222", size: 5 },
        summary: { total_docs: 8, note: "SSH on non-standard port 2222 in OT zone" },
        exemplars: [
          { "@timestamp": "2025-02-25T10:43:30Z", "source.ip": "10.50.40.30", "destination.ip": "10.50.20.10", "destination.port": 2222, "network.protocol": "ssh", "event.duration": 45200 },
          { "@timestamp": "2025-02-25T10:41:05Z", "source.ip": "10.50.40.30", "destination.ip": "10.50.20.10", "destination.port": 2222, "network.protocol": "ssh", "event.duration": 32100 },
          { "@timestamp": "2025-02-25T10:38:22Z", "source.ip": "10.50.40.30", "destination.ip": "10.50.20.10", "destination.port": 2222, "network.protocol": "ssh", "event.duration": 28900 },
        ],
      },
    ],
    suggested_pivots: [
      { pivot_id: "pv-001", label: "Arkime sessions for 10.50.40.30 \u2192 10.50.20.10:2222", action: { type: "tool", tool: "arkime_sessions", args: { expression: "ip==10.50.40.30 && ip==10.50.20.10 && port==2222", size: 20 } } },
      { pivot_id: "pv-002", label: "Suricata alerts for 10.50.40.30", action: { type: "chat", question: "Show all Suricata alerts for source IP 10.50.40.30 in the last hour." } },
      { pivot_id: "pv-003", label: "Beaconing analysis for this pair", action: { type: "chat", question: "Analyze connection timing between 10.50.40.30 and 10.50.20.10:2222. Regular interval = beaconing?" } },
    ],
  },

  suricata: {
    answer: "## Suricata Alert Triage\n\n**4 signatures** across **23 alerts**.\n\n| Severity | Count | Top Signature |\n|----------|-------|---------------|\n| Critical | 2 | ET POLICY SSH on Non-Standard Port |\n| High | 8 | ET SCAN Potential SSH Scan |\n| Medium | 9 | ET INFO CIP Read Request |\n| Low | 4 | ET INFO Modbus Read Coils |\n\n**Key concern:** SSH-on-non-standard-port correlates with `10.50.40.30 \u2192 10.50.20.10:2222`. Suggests lateral movement.",
    evidence: [{
      evidence_id: "ev-s01", tool: "os_suricata_alerts", source: "replay",
      time_range: { start: "2025-02-25T10:00:00Z", end: "2025-02-25T11:00:00Z" },
      query: { agg_field: "alert.signature", size: 20 },
      summary: {
        total_alerts: 23,
        severities: { critical: 2, high: 8, medium: 9, low: 4 },
        top_signatures: [
          { signature: "ET INFO CIP Read Request", count: 9 },
          { signature: "ET SCAN Potential SSH Scan", count: 8 },
          { signature: "ET INFO Modbus Read Coils", count: 4 },
          { signature: "ET POLICY SSH on Non-Standard Port", count: 2 },
        ],
      },
      exemplars: [
        { "@timestamp": "2025-02-25T10:43:31Z", "alert.signature": "ET POLICY SSH on Non-Standard Port", "alert.severity": 1, "source.ip": "10.50.40.30", "destination.ip": "10.50.20.10", "destination.port": 2222 },
        { "@timestamp": "2025-02-25T10:41:06Z", "alert.signature": "ET POLICY SSH on Non-Standard Port", "alert.severity": 1, "source.ip": "10.50.40.30", "destination.ip": "10.50.20.10", "destination.port": 2222 },
        { "@timestamp": "2025-02-25T10:40:00Z", "alert.signature": "ET SCAN Potential SSH Scan", "alert.severity": 2, "source.ip": "10.50.40.30", "destination.ip": "10.50.20.0/24", "destination.port": 22 },
        { "@timestamp": "2025-02-25T10:45:00Z", "alert.signature": "ET INFO CIP Read Request", "alert.severity": 3, "source.ip": "10.50.10.21", "destination.ip": "10.50.20.10", "destination.port": 44818 },
      ],
    }],
    suggested_pivots: [
      { pivot_id: "pv-s01", label: "Full PCAP for critical alerts", action: { type: "tool", tool: "arkime_sessions", args: { expression: "tags==suricata && ip==10.50.40.30", size: 10 } } },
      { pivot_id: "pv-s02", label: "Timeline of 10.50.40.30 activity", action: { type: "chat", question: "Build a timeline of all network activity from 10.50.40.30 in the last 4 hours." } },
    ],
  },

  beaconing: {
    answer: "## Beaconing Analysis\n\n**1 pair** with strong beaconing:\n\n- **10.50.40.30 \u2192 10.50.20.10:2222**\n  - Mean interval: **148.3s** (\u03c3 = 3.2s)\n  - Regularity score: **0.97** (1.0 = perfect)\n  - Sessions: **8**\n\nHigh-confidence beacon. Low jitter = automated tooling, not human SSH.",
    evidence: [{
      evidence_id: "ev-b01", tool: "os_connection_intervals", source: "replay",
      time_range: { start: "2025-02-25T10:00:00Z", end: "2025-02-25T11:00:00Z" },
      query: { source_ip: "10.50.40.30", destination_ip: "10.50.20.10", destination_port: 2222 },
      summary: { session_count: 8, mean_interval_sec: 148.3, std_dev_sec: 3.2, regularity_score: 0.97 },
      exemplars: [
        { "@timestamp": "2025-02-25T10:20:00Z", "source.ip": "10.50.40.30", "destination.ip": "10.50.20.10", "destination.port": 2222, interval_sec: null },
        { "@timestamp": "2025-02-25T10:22:25Z", "source.ip": "10.50.40.30", "destination.ip": "10.50.20.10", "destination.port": 2222, interval_sec: 145.1 },
        { "@timestamp": "2025-02-25T10:24:55Z", "source.ip": "10.50.40.30", "destination.ip": "10.50.20.10", "destination.port": 2222, interval_sec: 149.8 },
        { "@timestamp": "2025-02-25T10:27:22Z", "source.ip": "10.50.40.30", "destination.ip": "10.50.20.10", "destination.port": 2222, interval_sec: 147.2 },
        { "@timestamp": "2025-02-25T10:29:53Z", "source.ip": "10.50.40.30", "destination.ip": "10.50.20.10", "destination.port": 2222, interval_sec: 151.0 },
      ],
    }],
    suggested_pivots: [
      { pivot_id: "pv-b01", label: "DNS lookups from 10.50.40.30", action: { type: "chat", question: "What DNS queries has 10.50.40.30 made?" } },
      { pivot_id: "pv-b02", label: "Payload size analysis", action: { type: "tool", tool: "os_query_logs", args: { query_string: "source.ip:10.50.40.30 AND destination.port:2222", size: 20 } } },
    ],
  },

  segmentation: {
    answer: "## OT Segmentation Analysis\n\n**Zones:** IT (10.50.40.0/24), OT-Ctrl (10.50.10.0/24), OT-Field (10.50.20.0/24), DMZ (10.50.30.0/24)\n\n**Violations: 1 critical, 2 informational**\n\n| Severity | Source | Destination | Protocol | Notes |\n|----------|--------|-------------|----------|-------|\n| CRITICAL | 10.50.40.30 (IT) | 10.50.20.10 (OT) | SSH:2222 | IT\u2192OT bypassing jump host |\n| INFO | 10.50.10.21 (Ctrl) | 10.50.20.10 (Field) | CIP | Expected HMI\u2192PLC |\n| INFO | 10.50.10.5 (Ctrl) | 10.50.30.1 (DMZ) | Modbus | Historian push |",
    evidence: [{
      evidence_id: "ev-o01", tool: "os_cross_zone_traffic", source: "replay",
      time_range: { start: "2025-02-25T10:00:00Z", end: "2025-02-25T11:00:00Z" },
      query: { zones: ["10.50.40.0/24", "10.50.10.0/24", "10.50.20.0/24", "10.50.30.0/24"], check_policy: true },
      summary: { total_cross_zone_flows: 3, violations: 1, informational: 2 },
      exemplars: [
        { "@timestamp": "2025-02-25T10:43:30Z", "source.ip": "10.50.40.30", "source.zone": "IT", "destination.ip": "10.50.20.10", "destination.zone": "OT-Field", "destination.port": 2222, "network.protocol": "ssh", violation: true },
        { "@timestamp": "2025-02-25T10:45:12Z", "source.ip": "10.50.10.21", "source.zone": "OT-Control", "destination.ip": "10.50.20.10", "destination.zone": "OT-Field", "destination.port": 44818, "network.protocol": "cip", violation: false },
        { "@timestamp": "2025-02-25T10:42:11Z", "source.ip": "10.50.10.5", "source.zone": "OT-Control", "destination.ip": "10.50.30.1", "destination.zone": "DMZ", "destination.port": 502, "network.protocol": "modbus", violation: false },
      ],
    }],
    suggested_pivots: [
      { pivot_id: "pv-o01", label: "Historical IT\u2192OT connections (4h)", action: { type: "chat", question: "Show all connections from 10.50.40.0/24 to 10.50.20.0/24 in the last 4 hours." } },
    ],
  },
};

/* ============================================================================
 * MOCK RESPONSES — SYSTEM ENGINEER VIEW
 *
 * Same network data, different lens. The System Engineer cares about:
 *   1. Is the physical process healthy?
 *   2. What assets exist and how do they communicate?
 *   3. Which digital control paths lack non-digital safety barriers?
 *   4. Does this network anomaly threaten my process?
 * ========================================================================= */

const SYS_MOCKS = {
  process: {
    answer: "## Compressor Station #7 \u2014 Process State\n\n**Unit:** Solar Mars 100-16000S gas turbine driving C65 centrifugal compressor\n\n**Operating Point:** All parameters within normal bounds. Compression ratio 1.80 at 42 MMSCFD.\n\n- GG Speed: **9,800 RPM** (limit 10,200)\n- PT Speed: **6,198 RPM** (setpoint 6,200 \u2014 0.03% deviation)\n- TIT: **1,680\u00B0F** (limit 1,750\u00B0F \u2014 70\u00B0F margin)\n- Surge Margin: **12%** (trip at 5%)\n\n**Control Loops:** All healthy. Anti-surge controller in WATCHING state (normal above 10% margin).\n\n**Note:** No process anomalies detected during this capture window, but digital pathway analysis should be reviewed \u2014 see \"Exposed Control Paths\" query.",
    evidence: [
      {
        evidence_id: "ev-p01", tool: "process_state", source: "historian_replay",
        time_range: { start: "2025-02-25T10:00:00Z", end: "2025-02-25T11:00:00Z" },
        query: { type: "process_snapshot", unit: "CS-7" },
        summary: { unit: "CS-7 Mars 100 / C65", status: "RUNNING", operating_hours: 14832, values_count: 9, loops_count: 4, all_normal: true },
        exemplars: PROCESS_VALUES.map(function(v) { return { tag: v.tag, description: v.desc, value: v.value, unit: v.unit, lo_limit: v.lo, hi_limit: v.hi, status: v.status }; }),
      },
      {
        evidence_id: "ev-p02", tool: "control_loops", source: "historian_replay",
        time_range: { start: "2025-02-25T10:00:00Z", end: "2025-02-25T11:00:00Z" },
        query: { type: "loop_health", unit: "CS-7" },
        summary: { healthy: 3, watching: 1, alarming: 0, tripped: 0 },
        exemplars: CONTROL_LOOPS,
      },
    ],
    suggested_pivots: [
      { pivot_id: "pv-p01", label: "Show exposed digital control paths", action: { type: "chat", question: "Which control paths to safety-critical functions lack independent non-digital safety barriers?" } },
      { pivot_id: "pv-p02", label: "Trend key values over capture window", action: { type: "tool", tool: "historian_trend", args: { tags: ["ST-2002", "SURGE-M", "TT-2001"], range: "last_60m" } } },
    ],
  },

  assets: {
    answer: "## OT Asset Inventory\n\n**8 assets** identified across 4 zones.\n\n| Zone | Assets | Key Protocols |\n|------|--------|-----------|\n| OT-Field | 3 | EtherNet/IP, CIP, Modbus TCP |\n| OT-Control | 3 | CIP, RDP, Modbus TCP, SQL, SSH |\n| DMZ | 1 | Modbus TCP, HTTPS |\n| IT | 1 | SSH, HTTP (under investigation) |\n\n**Safety-Critical Assets:** Turbotronic 5 controller (`10.50.20.10`) and ControlLogix PLC (`10.50.20.15`) are both CIP-accessible. The T5 controller is the target of the anomalous SSH session from IT zone.\n\n**Protocol Concern:** Modbus TCP (no authentication) used for historian collection. CIP connections carry safety-critical control commands.",
    evidence: [{
      evidence_id: "ev-a01", tool: "asset_inventory", source: "network_scan",
      time_range: { start: "2025-02-25T10:00:00Z", end: "2025-02-25T11:00:00Z" },
      query: { type: "full_inventory" },
      summary: { total_assets: 8, zones: 4, safety_critical: 2, protocols_observed: "EtherNet/IP, CIP, Modbus TCP, SSH, RDP, HTTP, HTTPS, SQL, SolConnect" },
      exemplars: ASSETS,
    }],
    suggested_pivots: [
      { pivot_id: "pv-a01", label: "Connections to safety-critical assets", action: { type: "chat", question: "Show all connections to 10.50.20.10 and 10.50.20.15 in the last hour. Who is talking to the controllers?" } },
      { pivot_id: "pv-a02", label: "Protocol breakdown by zone", action: { type: "tool", tool: "os_protocol_stats", args: { group_by: "zone" } } },
    ],
  },

  paths: {
    answer: "## Digital Control Surface Analysis\n\n**4 control paths** analyzed. **2 lack independent non-digital safety barriers.**\n\nThese are paths where a cyber compromise of the digital control channel is the ONLY thing between an attacker and a physical safety consequence:\n\n- **CP-1: Speed Governor** \u2014 CIP write to T5 speed setpoint. Mechanical overspeed trip was **removed during retrofit**. Only firmware digital trip remains. **Risk: HIGH**\n- **CP-2: Anti-Surge Valve** \u2014 CIP command to recycle valve. **No mechanical surge relief** installed. PLC algorithm is sole protection. **Risk: HIGH**\n- **CP-3: Historian Spoofing** \u2014 Modbus write to historian tags. No authentication. Operators could be blinded. **Risk: MEDIUM**\n- **CP-4: Fuel Gas Valve** \u2014 CIP command path exists but mechanical spring-return valve provides **independent non-digital protection**. **Risk: LOW**\n\n**Critical Finding:** The anomalous SSH session targets `10.50.20.10` (T5 Controller). If the attacker pivots from SSH to CIP, they reach CP-1 (Speed Governor) with NO non-digital backstop.",
    evidence: [{
      evidence_id: "ev-cp01", tool: "control_path_analysis", source: "config_audit",
      time_range: { start: "2025-02-25T10:00:00Z", end: "2025-02-25T11:00:00Z" },
      query: { type: "safety_barrier_assessment" },
      summary: { paths_analyzed: 4, no_non_digital_barrier: 2, has_non_digital_barrier: 1, data_integrity_only: 1 },
      exemplars: CONTROL_PATHS,
    }],
    suggested_pivots: [
      { pivot_id: "pv-cp01", label: "CIP writes to T5 in capture window", action: { type: "tool", tool: "os_query_logs", args: { query_string: "destination.ip:10.50.20.10 AND cip.service:write", size: 20 } } },
      { pivot_id: "pv-cp02", label: "Cross-reference SSH anomaly with T5", action: { type: "chat", question: "Correlate the anomalous SSH session to 10.50.20.10 with any process value changes or control loop deviations." } },
    ],
  },

  correlate: {
    answer: "## SSH Anomaly \u2194 Process Correlation\n\n**Timeline:** Correlating `10.50.40.30 \u2192 10.50.20.10:2222` with historian data.\n\n**Finding:** No process value changes detected **yet**. However, the attack posture is concerning:\n\n- SSH beaconing at **~148s intervals** to T5 controller IP\n- T5 hosts the **speed governor** (CP-1) and **fuel gas valve** (CP-4) control paths\n- CP-1 has **no non-digital overspeed protection** \u2014 mechanical trip removed\n- If attacker achieves CIP access via SSH pivot, they can write to speed setpoint\n\n**Process Impact Assessment:**\n- Current PT speed: 6,198 RPM (setpoint 6,200)\n- Firmware overspeed trip: 6,500 RPM\n- Mechanical trip: **NONE** (removed)\n- A CIP write of +400 RPM to setpoint exceeds firmware trip by ~98 RPM if ramped gradually\n\n**Recommendation:** Pre-positioning pattern detected. Immediately isolate `10.50.40.30`. Inform operations to prepare for manual turbine trip if control loop deviation is observed.",
    evidence: [
      {
        evidence_id: "ev-cr01", tool: "timeline_correlation", source: "replay+historian",
        time_range: { start: "2025-02-25T10:00:00Z", end: "2025-02-25T11:00:00Z" },
        query: { network_filter: "source.ip:10.50.40.30", process_tags: ["ST-2002", "SURGE-M", "TT-2001"] },
        summary: { ssh_sessions: 8, process_deviations: 0, correlation: "No process impact yet \u2014 pre-positioning phase", risk_if_pivot: "HIGH \u2014 direct path to speed governor, no mechanical backstop" },
        exemplars: [
          { "@timestamp": "2025-02-25T10:20:00Z", event: "SSH session", source: "10.50.40.30", target: "10.50.20.10:2222", "PT_Speed_RPM": 6198, "Surge_Margin_%": 12.1, "TIT_\u00B0F": 1679 },
          { "@timestamp": "2025-02-25T10:22:25Z", event: "SSH session", source: "10.50.40.30", target: "10.50.20.10:2222", "PT_Speed_RPM": 6199, "Surge_Margin_%": 12.0, "TIT_\u00B0F": 1680 },
          { "@timestamp": "2025-02-25T10:24:55Z", event: "SSH session", source: "10.50.40.30", target: "10.50.20.10:2222", "PT_Speed_RPM": 6198, "Surge_Margin_%": 11.9, "TIT_\u00B0F": 1681 },
          { "@timestamp": "2025-02-25T10:27:22Z", event: "SSH session", source: "10.50.40.30", target: "10.50.20.10:2222", "PT_Speed_RPM": 6197, "Surge_Margin_%": 12.0, "TIT_\u00B0F": 1680 },
          { "@timestamp": "2025-02-25T10:29:53Z", event: "SSH session", source: "10.50.40.30", target: "10.50.20.10:2222", "PT_Speed_RPM": 6199, "Surge_Margin_%": 12.1, "TIT_\u00B0F": 1679 },
        ],
      },
      {
        evidence_id: "ev-cr02", tool: "control_path_risk", source: "config_audit",
        time_range: { start: "2025-02-25T10:00:00Z", end: "2025-02-25T11:00:00Z" },
        query: { asset: "10.50.20.10", scenario: "ssh_to_cip_pivot" },
        summary: { attack_path: "SSH:2222 \u2192 local pivot \u2192 CIP:44818", target_function: "Speed Governor setpoint", current_speed: 6198, trip_threshold: 6500, mechanical_backup: "NONE", max_ramp_before_trip: "~302 RPM" },
        exemplars: [],
      },
    ],
    suggested_pivots: [
      { pivot_id: "pv-cr01", label: "Generate firewall isolation rule", action: { type: "tool", tool: "generate_acl", args: { action: "block", source: "10.50.40.30", destination: "10.50.20.0/24" } } },
      { pivot_id: "pv-cr02", label: "Check for CIP write attempts in PCAP", action: { type: "tool", tool: "arkime_sessions", args: { expression: "ip==10.50.20.10 && protocols==cip && cip.service==write", size: 50 } } },
    ],
  },
};

/**
 * Route a question to the appropriate mock response based on keywords and current view.
 * In production, the gateway handles this routing via the LLM's tool selection.
 */
function getMockResponse(question, currentView) {
  const q = question.toLowerCase();
  if (currentView === "system") {
    if (q.includes("process") || q.includes("state") || q.includes("operating")) return SYS_MOCKS.process;
    if (q.includes("asset") || q.includes("inventory") || q.includes("protocol")) return SYS_MOCKS.assets;
    if (q.includes("control path") || q.includes("barrier") || q.includes("non-digital") || q.includes("exposed")) return SYS_MOCKS.paths;
    if (q.includes("correlat") || q.includes("ssh") || q.includes("process value")) return SYS_MOCKS.correlate;
    return SYS_MOCKS.process; // default for system view
  }
  // SOC view routing
  if (q.includes("suricata") || q.includes("alert")) return SOC_MOCKS.suricata;
  if (q.includes("beacon")) return SOC_MOCKS.beaconing;
  if (q.includes("segmentation") || q.includes("ot ") || q.includes("boundary")) return SOC_MOCKS.segmentation;
  return SOC_MOCKS.default;
}
/* ============================================================================
 * REUSABLE COMPONENTS
 * ========================================================================= */

/**
 * MarkdownRenderer — Renders a subset of Markdown sufficient for LLM output.
 * Supports: ## headings, **bold**, `code`, bullet lists, tables, code blocks.
 * Does NOT use dangerouslySetInnerHTML — all output is React elements.
 */
function MarkdownRenderer({ text }) {
  const t = useTheme();
  if (!text) return null;

  const lines = text.split("\n");
  const elements = [];
  let inCode = false;
  let codeLines = [];
  let inTable = false;
  let tableRows = [];

  /** Format inline markup: **bold** and `code` */
  function formatInline(str) {
    const parts = [];
    let key = 0;
    let lastIndex = 0;
    const regex = /(`[^`]+`|\*\*[^*]+\*\*)/g;
    let match;
    while ((match = regex.exec(str)) !== null) {
      if (match.index > lastIndex) {
        parts.push(<span key={key++}>{str.slice(lastIndex, match.index)}</span>);
      }
      const val = match[0];
      if (val[0] === "`") {
        parts.push(
          <code key={key++} style={{
            background: t.bgCode, padding: "1px 5px", borderRadius: "3px",
            fontSize: "12px", color: t.accent, fontFamily: "'Source Code Pro', monospace",
          }}>
            {val.slice(1, -1)}
          </code>
        );
      } else {
        parts.push(
          <strong key={key++} style={{ color: t.text, fontWeight: 600 }}>
            {val.slice(2, -2)}
          </strong>
        );
      }
      lastIndex = match.index + val.length;
    }
    if (lastIndex < str.length) {
      parts.push(<span key={key++}>{str.slice(lastIndex)}</span>);
    }
    return parts.length > 0 ? parts : str;
  }

  /** Flush accumulated table rows into a rendered table */
  function flushTable() {
    if (tableRows.length === 0) return;
    const headers = tableRows[0].split("|").filter(function(c) { return c.trim(); }).map(function(c) { return c.trim(); });
    const dataRows = tableRows.slice(2); // skip header + separator rows

    elements.push(
      <div key={"tbl-" + elements.length} style={{ overflowX: "auto", margin: "12px 0", border: "1px solid " + t.border, borderRadius: "6px" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
          <thead>
            <tr style={{ background: t.tableHeader }}>
              {headers.map(function(cell, i) {
                return <th key={i} style={{ padding: "8px 12px", borderBottom: "2px solid " + t.border, textAlign: "left", color: t.accent, fontWeight: 600, fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.04em" }}>{cell}</th>;
              })}
            </tr>
          </thead>
          <tbody>
            {dataRows.map(function(row, ri) {
              var cells = row.split("|").filter(function(c) { return c.trim(); }).map(function(c) { return c.trim(); });
              return (
                <tr key={ri} style={{ background: ri % 2 ? t.tableAlt : "transparent" }}>
                  {cells.map(function(cell, ci) {
                    var isAlert = cell.includes("CRITICAL") || cell.includes("HIGH");
                    var isOk = cell.includes("LOW");
                    return <td key={ci} style={{ padding: "7px 12px", borderBottom: "1px solid " + t.borderLight, color: isAlert ? t.redText : isOk ? t.greenText : t.text, fontWeight: isAlert ? 600 : 400 }}>{formatInline(cell)}</td>;
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    );
    tableRows = [];
    inTable = false;
  }

  // Parse each line
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];

    // Code block toggle
    if (line.startsWith("```")) {
      if (inTable) flushTable();
      if (inCode) {
        elements.push(<pre key={"code-" + i} style={{ background: t.bgCode, padding: "12px 14px", borderRadius: "6px", overflow: "auto", fontSize: "12px", color: t.green, margin: "8px 0", border: "1px solid " + t.border, fontFamily: "'Source Code Pro', monospace" }}>{codeLines.join("\n")}</pre>);
        codeLines = [];
        inCode = false;
      } else {
        inCode = true;
      }
      continue;
    }
    if (inCode) { codeLines.push(line); continue; }

    // Table detection
    if (line.includes("|") && line.trim().startsWith("|")) {
      if (!inTable) inTable = true;
      tableRows.push(line);
      continue;
    } else if (inTable) {
      flushTable();
    }

    // Headings, bullets, paragraphs
    if (line.startsWith("## ")) {
      elements.push(<h3 key={i} style={{ color: t.accent, margin: "18px 0 8px", fontSize: "15px", fontWeight: 700, borderBottom: "2px solid " + t.accentBg, paddingBottom: "6px" }}>{line.slice(3)}</h3>);
    } else if (line.startsWith("  - ")) {
      elements.push(<div key={i} style={{ paddingLeft: "28px", margin: "3px 0", color: t.textSecondary, fontSize: "13px", lineHeight: 1.5 }}><span style={{ color: t.green, marginRight: "8px", fontWeight: 700 }}>{"\u2022"}</span>{formatInline(line.slice(4))}</div>);
    } else if (line.startsWith("- ")) {
      elements.push(<div key={i} style={{ paddingLeft: "16px", margin: "4px 0", color: t.text, fontSize: "13px", lineHeight: 1.5 }}><span style={{ color: t.accent, marginRight: "8px", fontWeight: 700 }}>{"\u2022"}</span>{formatInline(line.slice(2))}</div>);
    } else if (line.trim() === "") {
      elements.push(<div key={i} style={{ height: "8px" }} />);
    } else {
      elements.push(<p key={i} style={{ margin: "4px 0", color: t.text, lineHeight: 1.6, fontSize: "13px" }}>{formatInline(line)}</p>);
    }
  }
  if (inTable) flushTable();

  return <div>{elements}</div>;
}

/**
 * StatusPill — Small indicator chip shown in the header.
 * @param {string} label - Short label text (e.g., "GW", "Mode")
 * @param {string} value - Display value
 * @param {boolean|undefined} ok - true=green dot, false=red dot, undefined=no dot
 */
function StatusPill({ label, value, ok }) {
  const t = useTheme();
  var dotColor = ok === true ? t.green : ok === false ? t.red : t.textMuted;

  return (
    <div style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "4px 10px", background: t.pillBg, borderRadius: "20px", fontSize: "11px", border: "1px solid " + t.pillBorder }}>
      {ok !== undefined && (
        <span style={{ width: 7, height: 7, borderRadius: "50%", background: dotColor, display: "inline-block" }} />
      )}
      <span style={{ color: t.textMuted, fontWeight: 500 }}>{label}</span>
      <span style={{ color: ok === false ? t.redText : ok === true ? t.greenText : t.text, fontFamily: "'Source Code Pro', monospace", fontWeight: 600, fontSize: "10.5px" }}>{value}</span>
    </div>
  );
}

/**
 * EvidenceBlock — Collapsible accordion block for one evidence object.
 * Shows: tool name, source, time range, query (with copy), summary, exemplar table.
 * The evidence panel is the "trust layer" — raw data backing the LLM answer.
 */
function EvidenceBlock({ ev, showRaw }) {
  const t = useTheme();
  const [open, setOpen] = useState(true);
  const [copied, setCopied] = useState(null);

  function handleCopy(label, data) {
    copyToClipboard(data);
    setCopied(label);
    setTimeout(function() { setCopied(null); }, 1500);
  }

  var cols = (ev.exemplars && ev.exemplars.length > 0) ? Object.keys(ev.exemplars[0]) : [];

  /** Determine if a row should be highlighted based on risk/criticality/status columns */
  var riskCol = cols.find(function(c) { return c === "risk" || c === "criticality" || c === "status"; });

  function cellColor(col, value) {
    var s = String(value || "").toUpperCase();
    if (col === "@timestamp") return t.textMuted;
    if (value === true) return t.redText;
    if (s.includes("HIGH") || s.includes("CRITICAL") || s.includes("SAFETY-CRITICAL") || s.includes("NONE")) return t.redText;
    if (s.includes("MEDIUM") || s.includes("WATCHING") || s.includes("PROTECTIVE")) return t.yellowText;
    if (s.includes("LOW") || s.includes("HEALTHY")) return t.greenText;
    return t.text;
  }

  var copyBtnStyle = {
    background: "none", border: "1px solid " + t.border, color: t.textMuted,
    fontSize: "10px", padding: "2px 8px", borderRadius: "4px", cursor: "pointer",
    fontFamily: "'Source Code Pro', monospace",
  };

  return (
    <div style={{ background: t.bgPanel, border: "1px solid " + t.border, borderRadius: "8px", marginBottom: "10px", overflow: "hidden", boxShadow: t.shadow }}>
      {/* Header row — click to toggle */}
      <div onClick={function() { setOpen(!open); }} style={{ display: "flex", alignItems: "center", gap: "10px", padding: "10px 14px", cursor: "pointer", background: t.evidenceHeader, borderBottom: open ? "1px solid " + t.borderLight : "none" }}>
        <span style={{ color: t.accent, fontSize: "10px", transform: open ? "rotate(90deg)" : "rotate(0)", display: "inline-block", transition: "transform 0.15s" }}>{"\u25B6"}</span>
        <span style={{ color: t.green, fontFamily: "'Source Code Pro', monospace", fontSize: "12.5px", fontWeight: 700 }}>{ev.tool}</span>
        <span style={{ color: t.borderLight }}>|</span>
        <span style={{ color: t.textMuted, fontSize: "11px" }}>{ev.source}</span>
        {ev.time_range && (
          <span style={{ color: t.textMuted, fontSize: "10px", fontFamily: "'Source Code Pro', monospace" }}>
            {formatTimestamp(ev.time_range.start) + " \u2192 " + formatTimestamp(ev.time_range.end)}
          </span>
        )}
        <span style={{ flex: 1 }} />
        <span style={{ color: t.textMuted, fontSize: "10px", fontFamily: "monospace" }}>{ev.evidence_id}</span>
      </div>

      {/* Expanded content */}
      {open && (
        <div style={{ padding: "14px" }}>
          {/* Query section */}
          <div style={{ marginBottom: "14px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
              <span style={{ color: t.textMuted, fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600 }}>Query</span>
              <button onClick={function() { handleCopy("q", ev.query); }} style={copyBtnStyle}>{copied === "q" ? "\u2713 Copied" : "Copy"}</button>
            </div>
            <pre style={{ background: t.bgCode, padding: "10px 12px", borderRadius: "6px", fontSize: "11.5px", color: t.textSecondary, overflow: "auto", margin: 0, border: "1px solid " + t.borderLight, fontFamily: "'Source Code Pro', monospace" }}>
              {JSON.stringify(ev.query, null, 2)}
            </pre>
          </div>

          {/* Summary section */}
          {ev.summary && (
            <div style={{ marginBottom: "14px" }}>
              <span style={{ color: t.textMuted, fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600 }}>Summary</span>
              {showRaw ? (
                <pre style={{ background: t.bgCode, padding: "10px 12px", borderRadius: "6px", fontSize: "11.5px", color: t.textSecondary, overflow: "auto", margin: "6px 0 0", border: "1px solid " + t.borderLight, fontFamily: "'Source Code Pro', monospace" }}>
                  {JSON.stringify(ev.summary, null, 2)}
                </pre>
              ) : (
                <div style={{ marginTop: "8px" }}>
                  {Object.entries(ev.summary).filter(function(entry) {
                    return entry[0] !== "top_values" && entry[0] !== "top_signatures";
                  }).map(function(entry) {
                    var k = entry[0], v = entry[1];
                    var displayVal = Array.isArray(v) ? "[" + v.length + " items]" : typeof v === "object" ? JSON.stringify(v) : String(v);
                    var valColor = (typeof v === "string" && (v.includes("HIGH") || v.includes("NONE"))) ? t.redText : t.text;
                    return (
                      <div key={k} style={{ display: "flex", gap: "8px", padding: "3px 0", fontSize: "12.5px" }}>
                        <span style={{ color: t.textMuted, minWidth: "140px", fontWeight: 500 }}>{k}:</span>
                        <span style={{ color: valColor, fontFamily: "'Source Code Pro', monospace" }}>{displayVal}</span>
                      </div>
                    );
                  })}
                  {/* Top values bar chart */}
                  {ev.summary.top_values && (
                    <div style={{ marginTop: "10px" }}>
                      {ev.summary.top_values.map(function(tv, i) {
                        var pct = Math.min(100, (tv.count / ev.summary.top_values[0].count) * 100);
                        return (
                          <div key={i} style={{ display: "flex", alignItems: "center", gap: "10px", padding: "3px 0" }}>
                            <div style={{ width: pct + "%", minWidth: "8px", height: "22px", background: t.accentBg, borderRadius: "4px", display: "flex", alignItems: "center", paddingLeft: "8px", border: "1px solid " + t.accent + "20" }}>
                              <span style={{ color: t.accent, fontFamily: "'Source Code Pro', monospace", fontSize: "11.5px", fontWeight: 600, whiteSpace: "nowrap" }}>{tv.value}</span>
                            </div>
                            <span style={{ color: t.textMuted, fontSize: "11.5px", fontFamily: "monospace", fontWeight: 600, minWidth: "30px" }}>{tv.count}</span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                  {/* Top signatures bar chart */}
                  {ev.summary.top_signatures && (
                    <div style={{ marginTop: "10px" }}>
                      {ev.summary.top_signatures.map(function(ts, i) {
                        var isCritical = ts.signature.includes("POLICY");
                        var pct = Math.min(100, (ts.count / ev.summary.top_signatures[0].count) * 100);
                        return (
                          <div key={i} style={{ display: "flex", alignItems: "center", gap: "10px", padding: "3px 0" }}>
                            <div style={{ width: pct + "%", minWidth: "8px", height: "22px", background: isCritical ? t.redBg : t.accentBg, borderRadius: "4px", display: "flex", alignItems: "center", paddingLeft: "8px", border: "1px solid " + (isCritical ? t.red : t.accent) + "20" }}>
                              <span style={{ color: isCritical ? t.redText : t.accent, fontFamily: "'Source Code Pro', monospace", fontSize: "10.5px", fontWeight: 600, whiteSpace: "nowrap" }}>{ts.signature}</span>
                            </div>
                            <span style={{ color: t.textMuted, fontSize: "11.5px", fontFamily: "monospace", fontWeight: 600 }}>{ts.count}</span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Exemplars table */}
          {ev.exemplars && ev.exemplars.length > 0 && (
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                <span style={{ color: t.textMuted, fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600 }}>Exemplars ({ev.exemplars.length})</span>
                <button onClick={function() { handleCopy("rows", ev.exemplars); }} style={copyBtnStyle}>{copied === "rows" ? "\u2713 Copied" : "Copy JSON"}</button>
              </div>
              {showRaw ? (
                <pre style={{ background: t.bgCode, padding: "10px 12px", borderRadius: "6px", fontSize: "11.5px", color: t.textSecondary, overflow: "auto", margin: 0, maxHeight: "300px", border: "1px solid " + t.borderLight, fontFamily: "'Source Code Pro', monospace" }}>
                  {JSON.stringify(ev.exemplars, null, 2)}
                </pre>
              ) : (
                <div style={{ overflowX: "auto", border: "1px solid " + t.border, borderRadius: "6px" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11.5px" }}>
                    <thead>
                      <tr style={{ background: t.tableHeader }}>
                        {cols.map(function(c) {
                          return <th key={c} style={{ padding: "7px 10px", textAlign: "left", color: t.accent, borderBottom: "2px solid " + t.border, fontWeight: 600, whiteSpace: "nowrap", fontSize: "10.5px", textTransform: "uppercase", letterSpacing: "0.03em" }}>{c}</th>;
                        })}
                      </tr>
                    </thead>
                    <tbody>
                      {ev.exemplars.slice(0, 10).map(function(row, ri) {
                        return (
                          <tr key={ri} style={{ background: ri % 2 ? t.tableAlt : "transparent" }}>
                            {cols.map(function(c) {
                              var val = row[c];
                              var display = c === "@timestamp" ? formatTimestamp(val) : val === null ? "\u2014" : val === true ? "\u26A0 YES" : val === false ? "no" : String(val);
                              return <td key={c} style={{ padding: "6px 10px", color: cellColor(c, val), fontFamily: "'Source Code Pro', monospace", whiteSpace: "nowrap", borderBottom: "1px solid " + t.borderLight, fontSize: "11px", fontWeight: (String(val || "").toUpperCase().includes("HIGH") || val === true || String(val || "").includes("NONE")) ? 700 : 400 }}>{display}</td>;
                            })}
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
/* ============================================================================
 * MAIN APPLICATION COMPONENT
 *
 * Layout: Header > Context Bar > [Left Panel | Evidence Panel | Answer Panel] > Footer
 *
 * State management:
 *   - view: "soc" | "system" — switches persona, demo queries, and response routing
 *   - dark: boolean — toggles light/dark theme
 *   - turns: array — session transcript of {question, answer, evidence, pivots, view}
 *   - health: object — last /health response from gateway
 *
 * Interaction flows:
 *   A. Ask question: textarea submit -> POST /chat -> append turn
 *   B. Run pivot: click pivot button -> POST /chat or POST /tools/{tool} -> append turn
 *   C. Demo button: fill textarea + auto-submit
 *   D. Export: download last turn as JSON
 *   E. Health: poll GET /health every 10s
 * ========================================================================= */

export default function MalcolmCopilot() {
  // Theme state
  const [dark, setDark] = useState(false);
  const theme = dark ? THEMES.dark : THEMES.light;

  // Persona state
  const [view, setView] = useState("soc"); // "soc" | "system"

  // Gateway health
  const [health, setHealth] = useState(null);
  const [healthOk, setHealthOk] = useState(null);

  // Input state
  const [question, setQuestion] = useState("");
  const [timePreset, setTimePreset] = useState("last_60m");
  const [showRaw, setShowRaw] = useState(false);

  // Session state
  const [loading, setLoading] = useState(false);
  const [sessionId, setSessionId] = useState(generateSessionId);
  const [turns, setTurns] = useState([]);
  const [error, setError] = useState(null);

  // Scroll refs
  const evidenceRef = useRef(null);
  const answerRef = useRef(null);

  // Derived values
  var demos = view === "soc" ? SOC_DEMOS : SYS_DEMOS;
  var viewLabel = view === "soc" ? "SOC Analyst" : "System Engineer";
  var viewColor = view === "soc" ? theme.accent : theme.green;
  var lastTurn = turns.length > 0 ? turns[turns.length - 1] : null;

  /* ── Health polling ──────────────────────────────────────────────────── */
  var checkHealth = useCallback(function() {
    if (GATEWAY_URL) {
      fetch(GATEWAY_URL + "/health")
        .then(function(r) { return r.json(); })
        .then(function(d) { setHealth(d); setHealthOk(d.status === "ok"); })
        .catch(function() { setHealthOk(false); setHealth(null); });
    } else {
      setHealth(MOCK_HEALTH);
      setHealthOk(true);
    }
  }, []);

  useEffect(function() {
    checkHealth();
    var interval = setInterval(checkHealth, HEALTH_INTERVAL);
    return function() { clearInterval(interval); };
  }, [checkHealth]);

  /* ── Ask question (Flow A / C) ───────────────────────────────────────── */
  var askQuestion = useCallback(function(q) {
    if (!q || !q.trim() || loading) return;
    setLoading(true);
    setError(null);
    var asked = q.trim();

    function handleResponse(data) {
      setTurns(function(prev) {
        return prev.concat({
          question: asked,
          answer: data.answer,
          evidence: data.evidence || [],
          pivots: data.suggested_pivots || [],
          timestamp: new Date().toISOString(),
          view: view,
        });
      });
      setQuestion("");
      setTimeout(function() {
        if (evidenceRef.current) evidenceRef.current.scrollTo({ top: evidenceRef.current.scrollHeight, behavior: "smooth" });
        if (answerRef.current) answerRef.current.scrollTo({ top: answerRef.current.scrollHeight, behavior: "smooth" });
      }, 100);
    }

    if (GATEWAY_URL) {
      fetch(GATEWAY_URL + "/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          session_id: sessionId,
          question: asked,
          time_window: { preset: timePreset },
          ui_options: { include_raw: showRaw, view: view },
        }),
      })
        .then(function(res) {
          if (!res.ok) throw new Error("Gateway error: " + res.status);
          return res.json();
        })
        .then(handleResponse)
        .catch(function(e) { setError(e.message); })
        .finally(function() { setLoading(false); });
    } else {
      // Mock mode — simulate network delay
      setTimeout(function() {
        var mockData = getMockResponse(asked, view);
        handleResponse({
          session_id: sessionId,
          question: asked,
          answer: mockData.answer,
          evidence: mockData.evidence,
          suggested_pivots: mockData.suggested_pivots,
        });
        setLoading(false);
      }, 600 + Math.random() * 500);
    }
  }, [loading, sessionId, timePreset, showRaw, view]);

  /* ── Run pivot (Flow B) ──────────────────────────────────────────────── */
  var runPivot = useCallback(function(pivot) {
    if (pivot.action.type === "chat") {
      setQuestion(pivot.action.question);
      askQuestion(pivot.action.question);
      return;
    }

    // Tool-type pivot
    setLoading(true);
    function handleToolResult(summary, exemplars) {
      setTurns(function(prev) {
        return prev.concat({
          question: "[Pivot] " + pivot.label,
          answer: "Tool `" + pivot.action.tool + "` executed." + (GATEWAY_URL ? "" : "\n\nConnect gateway for real results."),
          evidence: [{
            evidence_id: "ep-" + Date.now(),
            tool: pivot.action.tool,
            source: "replay",
            time_range: { start: "2025-02-25T10:00:00Z", end: "2025-02-25T11:00:00Z" },
            query: pivot.action.args,
            summary: summary,
            exemplars: exemplars,
          }],
          pivots: [],
          timestamp: new Date().toISOString(),
          view: view,
        });
      });
    }

    if (GATEWAY_URL) {
      fetch(GATEWAY_URL + "/tools/" + pivot.action.tool, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(pivot.action.args),
      })
        .then(function(r) { return r.json(); })
        .then(function(d) { handleToolResult(d.summary || d, d.exemplars || []); })
        .catch(function(e) { setError(e.message); })
        .finally(function() { setLoading(false); });
    } else {
      setTimeout(function() {
        handleToolResult({ note: "Mock pivot \u2014 connect gateway for live data" }, []);
        setLoading(false);
      }, 400);
    }
  }, [askQuestion, view]);

  /* ── Session management (Flow D, Clear) ──────────────────────────────── */
  function clearSession() {
    setTurns([]);
    setSessionId(generateSessionId());
    setQuestion("");
    setError(null);
  }

  function exportEvidence() {
    if (turns.length === 0) return;
    var last = turns[turns.length - 1];
    var payload = JSON.stringify({
      question: last.question,
      timestamp: last.timestamp,
      view: last.view,
      answer: last.answer,
      evidence: last.evidence,
      suggested_pivots: last.pivots,
    }, null, 2);
    var blob = new Blob([payload], { type: "application/json" });
    var anchor = document.createElement("a");
    anchor.href = URL.createObjectURL(blob);
    anchor.download = "malcolm-evidence-" + Date.now() + ".json";
    anchor.click();
  }

  /* ── Render ──────────────────────────────────────────────────────────── */
  return (
    <ThemeContext.Provider value={theme}>
      <div style={{ height: "100vh", display: "flex", flexDirection: "column", background: theme.bg, color: theme.text, fontFamily: "'Source Sans 3', 'Segoe UI', system-ui, sans-serif", overflow: "hidden" }}>

        {/* Google Fonts + global styles */}
        <style>{
          "@import url('https://fonts.googleapis.com/css2?family=Source+Sans+3:wght@400;500;600;700&family=Source+Code+Pro:wght@400;500;600&display=swap');" +
          "*{box-sizing:border-box;margin:0;padding:0}" +
          "::-webkit-scrollbar{width:6px;height:6px}" +
          "::-webkit-scrollbar-track{background:" + theme.bg + "}" +
          "::-webkit-scrollbar-thumb{background:" + theme.border + ";border-radius:3px}" +
          "textarea:focus,select:focus{outline:none;border-color:" + theme.accent + "!important;box-shadow:0 0 0 2px " + theme.accent + "20}" +
          "button{transition:all .1s ease;font-family:inherit}" +
          "button:hover:not(:disabled){opacity:0.85}" +
          "button:active:not(:disabled){transform:scale(0.98)}" +
          "button:disabled{opacity:.4;cursor:not-allowed}"
        }</style>

        {/* Error banner */}
        {(healthOk === false || error) && (
          <div style={{ background: theme.redBg, borderBottom: "1px solid " + theme.red + "40", padding: "8px 20px", display: "flex", alignItems: "center", gap: "10px", fontSize: "13px" }}>
            <span style={{ color: theme.red, fontWeight: 700 }}>!</span>
            <span style={{ color: theme.redText }}>{error || "Gateway unreachable \u2014 running in mock demo mode"}</span>
            {error && <button onClick={function() { setError(null); }} style={{ background: "none", border: "1px solid " + theme.red + "40", color: theme.redText, fontSize: "11px", padding: "2px 10px", borderRadius: "4px", cursor: "pointer" }}>Dismiss</button>}
          </div>
        )}

        {/* ── HEADER ───────────────────────────────────────────────────── */}
        <header style={{ display: "flex", alignItems: "center", gap: "16px", padding: "0 20px", height: "54px", borderBottom: "1px solid " + theme.border, background: theme.bgHeader, flexShrink: 0 }}>
          {/* Brand */}
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <span style={{ fontSize: "18px", fontWeight: 700, color: theme.bgHeaderText }}>Malcolm</span>
            <span style={{ fontSize: "18px", fontWeight: 300, color: theme.bgHeaderText, opacity: 0.7 }}>Copilot</span>
            <div style={{ height: "20px", width: "1px", background: theme.bgHeaderText, opacity: 0.2 }} />
            <span style={{ fontSize: "11px", fontWeight: 600, color: theme.bgHeaderText, opacity: 0.6, letterSpacing: "0.08em", textTransform: "uppercase" }}>Replay</span>
          </div>

          {/* View toggle — SOC Analyst / System Engineer */}
          <div style={{ display: "flex", background: dark ? "#1a2332" : "#002a55", borderRadius: "8px", overflow: "hidden", marginLeft: "16px", border: "1px solid " + (dark ? "#2d3a4d" : "#004488") }}>
            <button onClick={function() { setView("soc"); }} style={{
              padding: "6px 16px", fontSize: "11.5px", fontWeight: view === "soc" ? 700 : 500,
              cursor: "pointer", border: "none", letterSpacing: "0.02em",
              background: view === "soc" ? (dark ? "#4a9eff" : "#ffffff") : "transparent",
              color: view === "soc" ? (dark ? "#0f1419" : "#003b71") : (dark ? "#94a3b8" : "#ffffffaa"),
              borderRadius: view === "soc" ? "6px" : "0",
            }}>SOC Analyst</button>
            <button onClick={function() { setView("system"); }} style={{
              padding: "6px 16px", fontSize: "11.5px", fontWeight: view === "system" ? 700 : 500,
              cursor: "pointer", border: "none", letterSpacing: "0.02em",
              background: view === "system" ? (dark ? "#6dbe4b" : "#ffffff") : "transparent",
              color: view === "system" ? (dark ? "#0f1419" : "#3d7028") : (dark ? "#94a3b8" : "#ffffffaa"),
              borderRadius: view === "system" ? "6px" : "0",
            }}>System Engineer</button>
          </div>

          {/* Status pills */}
          <div style={{ display: "flex", gap: "6px", marginLeft: "auto", flexWrap: "wrap" }}>
            <StatusPill label="GW" value={healthOk ? "OK" : "DOWN"} ok={healthOk} />
            <StatusPill label="Mode" value={(health && health.backend_mode) || "\u2014"} />
            <StatusPill label="Model" value={health && health.model ? health.model.split(":").slice(-1)[0] : "\u2014"} />
          </div>

          {/* Action buttons */}
          <div style={{ display: "flex", gap: "6px", marginLeft: "12px", alignItems: "center" }}>
            <button onClick={function() { setDark(!dark); }} style={{ background: theme.pillBg, border: "1px solid " + theme.pillBorder, color: theme.text, padding: "5px 10px", borderRadius: "20px", fontSize: "11px", cursor: "pointer", display: "flex", alignItems: "center", gap: "5px" }}>
              <span style={{ fontSize: "13px" }}>{dark ? "\u2600\uFE0F" : "\uD83C\uDF19"}</span>
              {dark ? "Light" : "Dark"}
            </button>
            <button onClick={clearSession} style={{ background: theme.btnSecondary, border: "1px solid " + theme.btnSecondaryBorder, color: theme.btnSecondaryText, padding: "5px 14px", borderRadius: "6px", fontSize: "11.5px", cursor: "pointer", fontWeight: 500 }}>Clear</button>
            <button onClick={exportEvidence} disabled={turns.length === 0} style={{ background: theme.btnPrimary, border: "none", color: theme.btnPrimaryText, padding: "5px 14px", borderRadius: "6px", fontSize: "11.5px", cursor: "pointer", fontWeight: 600 }}>Export</button>
          </div>
        </header>

        {/* ── VIEW CONTEXT BAR ─────────────────────────────────────────── */}
        <div style={{ padding: "6px 20px", background: view === "soc" ? theme.accentBg : theme.greenBg, borderBottom: "1px solid " + viewColor + "30", display: "flex", alignItems: "center", gap: "12px", fontSize: "12px", flexShrink: 0 }}>
          <span style={{ fontWeight: 700, color: viewColor }}>
            {view === "soc" ? "\uD83D\uDEE1\uFE0F" : "\u2699\uFE0F"} {viewLabel} View
          </span>
          <span style={{ color: theme.textMuted }}>|</span>
          <span style={{ color: theme.textSecondary }}>
            {view === "soc"
              ? "Network threats, alert triage, connection forensics"
              : "Process state, control loops, digital control surface exposure"}
          </span>
          {view === "system" && (
            <span style={{ marginLeft: "auto", background: theme.yellowBg, color: theme.yellowText, padding: "2px 10px", borderRadius: "4px", fontSize: "11px", fontWeight: 600, border: "1px solid " + theme.yellow + "30" }}>
              Focus: digitally-exposed paths without non-digital barriers
            </span>
          )}
        </div>

        {/* ── THREE-PANEL LAYOUT ───────────────────────────────────────── */}
        <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>

          {/* ── LEFT PANEL: Input + Demos + Options + Session History ── */}
          <div style={{ width: "280px", flexShrink: 0, borderRight: "1px solid " + theme.border, display: "flex", flexDirection: "column", background: theme.bgPanel2 }}>
            <div style={{ padding: "16px", flex: 1, overflowY: "auto" }}>
              <label style={{ color: theme.textMuted, fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, display: "block", marginBottom: "6px" }}>Ask a question</label>
              <textarea
                value={question}
                onChange={function(e) { setQuestion(e.target.value); }}
                onKeyDown={function(e) { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); askQuestion(question); } }}
                placeholder={view === "soc" ? "e.g. Show me the top talkers..." : "e.g. What is the current process state?"}
                rows={3}
                style={{ width: "100%", background: theme.bgPanel, border: "1px solid " + theme.border, borderRadius: "6px", padding: "10px 12px", color: theme.text, fontSize: "13px", fontFamily: "inherit", resize: "vertical", lineHeight: 1.5 }}
              />
              <button
                onClick={function() { askQuestion(question); }}
                disabled={!question.trim() || loading || healthOk === false}
                style={{ width: "100%", marginTop: "8px", padding: "10px", background: view === "soc" ? theme.btnPrimary : theme.green, border: "none", borderRadius: "6px", color: "#fff", fontSize: "13px", fontWeight: 600, cursor: "pointer" }}
              >
                {loading ? "Analyzing\u2026" : "Ask Malcolm"}
              </button>

              {/* Demo queries */}
              <div style={{ marginTop: "20px" }}>
                <label style={{ color: theme.textMuted, fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, display: "block", marginBottom: "8px" }}>{viewLabel} Queries</label>
                {demos.map(function(dq) {
                  return (
                    <button key={dq.label} onClick={function() { setQuestion(dq.prompt); askQuestion(dq.prompt); }} disabled={loading} style={{ display: "block", width: "100%", textAlign: "left", background: theme.bgPanel, border: "1px solid " + theme.border, borderRadius: "6px", padding: "9px 12px", color: viewColor, fontSize: "12.5px", cursor: "pointer", marginBottom: "6px", fontWeight: 500 }}>
                      {dq.label}
                    </button>
                  );
                })}
              </div>

              {/* Options */}
              <div style={{ marginTop: "20px" }}>
                <label style={{ color: theme.textMuted, fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, display: "block", marginBottom: "8px" }}>Options</label>
                <select value={timePreset} onChange={function(e) { setTimePreset(e.target.value); }} style={{ width: "100%", background: theme.bgPanel, border: "1px solid " + theme.border, borderRadius: "6px", padding: "7px 10px", color: theme.text, fontSize: "12px", marginBottom: "10px" }}>
                  {TIME_PRESETS.map(function(tp) { return <option key={tp.value} value={tp.value}>{tp.label}</option>; })}
                </select>
                <label style={{ display: "flex", alignItems: "center", gap: "8px", cursor: "pointer", fontSize: "12px", color: theme.textSecondary, padding: "4px 0" }}>
                  <input type="checkbox" checked={showRaw} onChange={function(e) { setShowRaw(e.target.checked); }} style={{ accentColor: viewColor }} />
                  Show raw JSON
                </label>
              </div>

              {/* Session history */}
              {turns.length > 0 && (
                <div style={{ marginTop: "20px" }}>
                  <label style={{ color: theme.textMuted, fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, display: "block", marginBottom: "6px" }}>
                    Session {"\u00B7"} {turns.length} turn{turns.length > 1 ? "s" : ""}
                  </label>
                  {turns.map(function(turn, i) {
                    var turnColor = turn.view === "soc" ? theme.accent : theme.green;
                    var isLast = i === turns.length - 1;
                    return (
                      <div key={i} style={{ padding: "6px 10px", borderLeft: "3px solid " + (isLast ? turnColor : theme.borderLight), marginBottom: "4px", fontSize: "11.5px", background: isLast ? (turn.view === "soc" ? theme.accentBg : theme.greenBg) : "transparent", borderRadius: "0 4px 4px 0" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                          <span style={{ fontSize: "9px", color: turnColor, fontWeight: 700 }}>{turn.view === "soc" ? "SOC" : "SYS"}</span>
                          <span style={{ color: isLast ? turnColor : theme.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontWeight: isLast ? 600 : 400, flex: 1 }}>
                            {turn.question.substring(0, 32)}{turn.question.length > 32 ? "\u2026" : ""}
                          </span>
                        </div>
                        <div style={{ fontSize: "10px", color: theme.textMuted, marginTop: "2px" }}>
                          {turn.evidence.length} ev {"\u00B7"} {turn.pivots.length} piv
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* ── MIDDLE PANEL: Evidence (Trust Layer) ────────────────── */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", borderRight: "1px solid " + theme.border, minWidth: 0 }}>
            <div style={{ padding: "10px 16px", borderBottom: "1px solid " + theme.border, background: theme.bgPanel, display: "flex", alignItems: "center", gap: "10px" }}>
              <span style={{ color: viewColor, fontSize: "12px", fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase" }}>Evidence</span>
              <span style={{ color: theme.textMuted, fontSize: "11px" }}>
                {view === "soc" ? "\u2014 Network Trust Layer" : "\u2014 Process Trust Layer"}
              </span>
              {lastTurn && <span style={{ marginLeft: "auto", color: theme.textMuted, fontSize: "10.5px", fontFamily: "'Source Code Pro', monospace" }}>{lastTurn.evidence.length} block{lastTurn.evidence.length !== 1 ? "s" : ""}</span>}
            </div>
            <div ref={evidenceRef} style={{ flex: 1, overflowY: "auto", padding: "12px 16px", background: theme.bgEvidence }}>
              {turns.length === 0 ? (
                <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", flexDirection: "column", gap: "16px" }}>
                  <div style={{ width: "64px", height: "64px", borderRadius: "50%", background: view === "soc" ? theme.accentBg : theme.greenBg, display: "flex", alignItems: "center", justifyContent: "center", border: "2px solid " + viewColor + "30" }}>
                    <span style={{ fontSize: "28px", color: viewColor, fontWeight: 700 }}>{view === "soc" ? "M" : "\u2699"}</span>
                  </div>
                  <div style={{ fontSize: "16px", fontWeight: 600, color: theme.text }}>{viewLabel} View</div>
                  <div style={{ color: theme.textMuted, fontSize: "13px", textAlign: "center", lineHeight: 1.6, maxWidth: "380px" }}>
                    {view === "soc"
                      ? "Ask about network threats, connections, alerts, and forensic artifacts. Evidence shows packets, sessions, and signatures."
                      : "Ask about process state, control loops, asset inventory, and digital control surface exposure. Evidence shows historian data, controller comms, and safety barrier assessments."}
                  </div>
                </div>
              ) : (
                turns.map(function(turn, ti) {
                  var turnColor = turn.view === "soc" ? theme.accent : theme.green;
                  var turnBg = turn.view === "soc" ? theme.accentBg : theme.greenBg;
                  return (
                    <div key={ti} style={{ marginBottom: "16px" }}>
                      <div style={{ fontSize: "11px", color: theme.textMuted, marginBottom: "8px", padding: "4px 0", borderBottom: "1px solid " + theme.borderLight, display: "flex", alignItems: "center", gap: "8px" }}>
                        <span style={{ background: turnBg, color: turnColor, padding: "2px 8px", borderRadius: "4px", fontFamily: "'Source Code Pro', monospace", fontSize: "10px", fontWeight: 700, border: "1px solid " + turnColor + "20" }}>
                          {turn.view === "soc" ? "SOC" : "SYS"} T{ti + 1}
                        </span>
                        <span style={{ color: theme.textSecondary, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{turn.question}</span>
                        <span style={{ color: theme.textMuted, fontSize: "10px" }}>{formatTimestamp(turn.timestamp)}</span>
                      </div>
                      {turn.evidence.length === 0 ? (
                        <div style={{ padding: "24px", textAlign: "center", color: theme.textMuted, fontSize: "13px", borderRadius: "8px", border: "1px dashed " + theme.border, background: theme.bgPanel }}>No evidence returned</div>
                      ) : (
                        turn.evidence.map(function(ev) { return <EvidenceBlock key={ev.evidence_id} ev={ev} showRaw={showRaw} />; })
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* ── RIGHT PANEL: Answer + Suggested Pivots ─────────────── */}
          <div style={{ width: "380px", flexShrink: 0, display: "flex", flexDirection: "column", background: theme.bgPanel2 }}>
            <div style={{ padding: "10px 16px", borderBottom: "1px solid " + theme.border, background: theme.bgPanel }}>
              <span style={{ color: viewColor, fontSize: "12px", fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase" }}>Answer</span>
            </div>
            <div ref={answerRef} style={{ flex: 1, overflowY: "auto", padding: "16px" }}>
              {turns.length === 0 ? (
                <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", flexDirection: "column", gap: "12px" }}>
                  <div style={{ fontSize: "32px", opacity: 0.15 }}>?</div>
                  <div style={{ color: theme.textMuted, fontSize: "13px" }}>Answers will appear here</div>
                </div>
              ) : (
                turns.map(function(turn, ti) {
                  var turnColor = turn.view === "soc" ? theme.accent : theme.green;
                  var turnBg = turn.view === "soc" ? theme.accentBg : theme.greenBg;
                  var isLast = ti === turns.length - 1;
                  return (
                    <div key={ti} style={{ marginBottom: "24px", paddingBottom: "16px", borderBottom: !isLast ? "1px solid " + theme.borderLight : "none" }}>
                      <div style={{ fontSize: "11px", marginBottom: "10px", display: "flex", alignItems: "center", gap: "6px" }}>
                        <span style={{ background: turnBg, color: turnColor, padding: "2px 8px", borderRadius: "4px", fontFamily: "'Source Code Pro', monospace", fontSize: "10px", fontWeight: 700, border: "1px solid " + turnColor + "20" }}>
                          {turn.view === "soc" ? "SOC" : "SYS"} T{ti + 1}
                        </span>
                        <span style={{ color: theme.textMuted }}>{formatTimestamp(turn.timestamp)}</span>
                      </div>
                      <div style={{ lineHeight: 1.6 }}>
                        <MarkdownRenderer text={turn.answer} />
                      </div>
                      {/* Suggested pivots — only shown on the latest turn */}
                      {turn.pivots.length > 0 && isLast && (
                        <div style={{ marginTop: "18px" }}>
                          <div style={{ color: theme.textMuted, fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, marginBottom: "8px" }}>Suggested Pivots</div>
                          {turn.pivots.map(function(pv) {
                            return (
                              <button key={pv.pivot_id} onClick={function() { runPivot(pv); }} disabled={loading} style={{ display: "block", width: "100%", textAlign: "left", background: theme.bgPanel, border: "1px solid " + theme.border, borderRadius: "6px", padding: "10px 12px", color: theme.text, fontSize: "12px", cursor: "pointer", marginBottom: "6px", lineHeight: 1.4 }}>
                                <span style={{ color: pv.action.type === "tool" ? theme.yellow : viewColor, marginRight: "8px", fontWeight: 700 }}>
                                  {pv.action.type === "tool" ? "\u2699" : "\u2197"}
                                </span>
                                {pv.label}
                                <div style={{ color: theme.textMuted, fontSize: "10.5px", marginTop: "3px", fontFamily: "'Source Code Pro', monospace" }}>
                                  {"\u2192 "}{pv.action.type === "tool" ? pv.action.tool : "follow-up question"}
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>

        {/* ── FOOTER ───────────────────────────────────────────────── */}
        <div style={{ borderTop: "1px solid " + theme.border, padding: "4px 20px", background: theme.bgPanel, display: "flex", alignItems: "center", gap: "12px", fontSize: "10.5px", color: theme.textMuted, flexShrink: 0, fontFamily: "'Source Code Pro', monospace" }}>
          <span style={{ fontWeight: 600 }}>Malcolm Copilot</span>
          <span style={{ opacity: 0.3 }}>|</span>
          <span>v{(health && health.version) || "0.1.0"}</span>
          <span style={{ opacity: 0.3 }}>|</span>
          <span style={{ color: viewColor, fontWeight: 600 }}>{viewLabel}</span>
          <span style={{ opacity: 0.3 }}>|</span>
          <span>{sessionId}</span>
          <span style={{ marginLeft: "auto" }}>{GATEWAY_URL || "Mock Mode"}</span>
        </div>
      </div>
    </ThemeContext.Provider>
  );
}
