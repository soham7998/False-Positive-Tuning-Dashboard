'use client';

import { useState, useEffect } from 'react';
import {
  Shield, TrendingDown, Clock, AlertTriangle, CheckCircle, XCircle,
  Loader2, ExternalLink, Activity, Zap, Target, ChevronRight, RefreshCw,
  AlertCircle, FileText, Filter
} from 'lucide-react';
import {
  BarChart, Bar, PieChart, Pie, Cell, ResponsiveContainer,
  XAxis, YAxis, Tooltip, CartesianGrid, Legend
} from 'recharts';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';

interface Metrics {
  total_alerts: number;
  false_positives: number;
  true_positives: number;
  pending: number;
  fp_rate: number;
  tp_rate: number;
  suggested_rules: number;
  applied_rules: number;
  time_saved_weekly_hours: number;
  fp_reduction_weekly: number;
  top_fp_rules: { rule: string; count: number; percentage: number }[];
  severity_distribution: Record<string, number>;
  decision_distribution: Record<string, number>;
}

interface Alert {
  alert_id: string;
  timestamp: string;
  rule_name: string;
  severity: string;
  source_ip: string;
  user: string;
  host: string;
  process: string;
  description: string;
  analyst_decision: string | null;
}

interface TuningRule {
  rule_id: string;
  name: string;
  description: string;
  pattern: Record<string, any>;
  fp_count: number;
  confidence: number;
  estimated_fp_reduction: number;
  estimated_time_saved_minutes: number;
  suggested_action: string;
  status: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
};

const CHART_COLORS = ['#3b82f6', '#ef4444', '#f59e0b', '#10b981', '#8b5cf6'];

export default function Dashboard() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [rules, setRules] = useState<TuningRule[]>([]);
  const [activeTab, setActiveTab] = useState<'overview' | 'triage' | 'rules'>('overview');
  const [alertFilter, setAlertFilter] = useState<'pending' | 'fp' | 'tp' | 'all'>('pending');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAll = async () => {
    try {
      setError(null);
      const [mRes, aRes, rRes] = await Promise.all([
        fetch(`${API_URL}/api/metrics`),
        fetch(`${API_URL}/api/alerts?status=${alertFilter}`),
        fetch(`${API_URL}/api/rules?status=pending`),
      ]);
      
      if (!mRes.ok) throw new Error('Backend unreachable');
      
      setMetrics(await mRes.json());
      const alertsData = await aRes.json();
      setAlerts(alertsData.alerts || []);
      const rulesData = await rRes.json();
      setRules(rulesData.rules || []);
    } catch (e: any) {
      setError(`Cannot connect to API at ${API_URL}. Is the backend running?`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchAll(); }, [alertFilter]);

  const decideAlert = async (alertId: string, decision: 'true_positive' | 'false_positive') => {
    try {
      await fetch(`${API_URL}/api/alerts/${alertId}/decision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision, notes: '' }),
      });
      await fetchAll();
    } catch (e) {
      console.error(e);
    }
  };

  const applyRule = async (ruleId: string) => {
    try {
      await fetch(`${API_URL}/api/rules/${ruleId}/apply`, { method: 'POST' });
      await fetchAll();
    } catch (e) { console.error(e); }
  };

  const rejectRule = async (ruleId: string) => {
    try {
      await fetch(`${API_URL}/api/rules/${ruleId}/reject`, { method: 'POST' });
      await fetchAll();
    } catch (e) { console.error(e); }
  };

  const resetData = async () => {
    setLoading(true);
    try {
      await fetch(`${API_URL}/api/seed`, { method: 'POST' });
      await fetchAll();
    } catch (e) { console.error(e); }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-blue-600" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center p-6">
        <div className="bg-white border border-red-200 rounded-xl p-8 max-w-md text-center">
          <AlertCircle className="w-12 h-12 text-red-600 mx-auto mb-4" />
          <h2 className="text-lg font-semibold mb-2">Backend Unreachable</h2>
          <p className="text-sm text-slate-600 mb-4">{error}</p>
          <p className="text-xs text-slate-500 mb-4 font-mono">{API_URL}</p>
          <button
            onClick={fetchAll}
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="bg-white border-b border-slate-200 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-purple-600 rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-slate-900">FP Tuning Dashboard</h1>
              <p className="text-xs text-slate-500">Automated SOC alert optimization</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={resetData}
              className="text-sm text-slate-600 hover:text-slate-900 flex items-center gap-1.5"
            >
              <RefreshCw className="w-4 h-4" /> Reset Demo Data
            </button>
            <a
              href="https://github.com/soham7998/FP_Tuning_Dashboard"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-slate-600 hover:text-slate-900 flex items-center gap-1.5 font-medium"
            >
              GitHub <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>

        {/* Tabs */}
        <div className="max-w-7xl mx-auto px-6 flex gap-1 -mb-px">
          {[
            { id: 'overview', label: 'Overview', icon: Activity },
            { id: 'triage', label: 'Alert Triage', icon: Target },
            { id: 'rules', label: 'Tuning Rules', icon: Zap },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-slate-600 hover:text-slate-900'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
              {tab.id === 'rules' && rules.length > 0 && (
                <span className="bg-blue-100 text-blue-700 text-xs px-1.5 py-0.5 rounded">
                  {rules.length}
                </span>
              )}
            </button>
          ))}
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* OVERVIEW TAB */}
        {activeTab === 'overview' && metrics && (
          <div className="space-y-6">
            {/* Hero Stats */}
            <div className="grid grid-cols-4 gap-4">
              <StatCard
                icon={Clock}
                label="Time Saved / Week"
                value={`${metrics.time_saved_weekly_hours}h`}
                subtext={`${metrics.fp_reduction_weekly} FPs reduced`}
                color="green"
              />
              <StatCard
                icon={TrendingDown}
                label="FP Rate"
                value={`${metrics.fp_rate}%`}
                subtext={`${metrics.false_positives} of ${metrics.total_alerts}`}
                color="red"
              />
              <StatCard
                icon={Zap}
                label="Suggested Rules"
                value={metrics.suggested_rules}
                subtext={`${metrics.applied_rules} applied`}
                color="purple"
              />
              <StatCard
                icon={CheckCircle}
                label="True Positives"
                value={metrics.true_positives}
                subtext={`${metrics.tp_rate}% accuracy`}
                color="blue"
              />
            </div>

            {/* Charts */}
            <div className="grid grid-cols-2 gap-6">
              {/* Decision Distribution */}
              <div className="bg-white border border-slate-200 rounded-xl p-6">
                <h3 className="font-semibold text-slate-900 mb-4">Alert Decisions</h3>
                <ResponsiveContainer width="100%" height={250}>
                  <PieChart>
                    <Pie
                      data={[
                        { name: 'True Positives', value: metrics.decision_distribution.true_positive },
                        { name: 'False Positives', value: metrics.decision_distribution.false_positive },
                        { name: 'Pending', value: metrics.decision_distribution.pending },
                      ]}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {[0, 1, 2].map((idx) => (
                        <Cell key={idx} fill={['#10b981', '#ef4444', '#94a3b8'][idx]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              {/* Top FP Rules */}
              <div className="bg-white border border-slate-200 rounded-xl p-6">
                <h3 className="font-semibold text-slate-900 mb-4">Top FP Generators</h3>
                {metrics.top_fp_rules.length > 0 ? (
                  <ResponsiveContainer width="100%" height={250}>
                    <BarChart data={metrics.top_fp_rules} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                      <XAxis type="number" stroke="#64748b" fontSize={12} />
                      <YAxis dataKey="rule" type="category" stroke="#64748b" fontSize={11} width={120} />
                      <Tooltip />
                      <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="text-center text-slate-500 py-12">No FP data yet</div>
                )}
              </div>
            </div>

            {/* CTA */}
            <div className="bg-gradient-to-r from-blue-600 to-purple-600 rounded-xl p-6 text-white">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-semibold text-lg mb-1">Ready to reduce alert fatigue?</h3>
                  <p className="text-blue-100 text-sm">
                    {rules.length} tuning rules waiting for review — could save {metrics.time_saved_weekly_hours}+ hours weekly
                  </p>
                </div>
                <button
                  onClick={() => setActiveTab('rules')}
                  className="bg-white text-blue-600 px-4 py-2 rounded-lg font-medium text-sm hover:bg-blue-50"
                >
                  Review Rules <ChevronRight className="w-4 h-4 inline" />
                </button>
              </div>
            </div>
          </div>
        )}

        {/* TRIAGE TAB */}
        {activeTab === 'triage' && (
          <div className="space-y-4">
            <div className="bg-white border border-slate-200 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-3">
                <Filter className="w-4 h-4 text-slate-500" />
                <span className="text-sm font-medium text-slate-700">Filter:</span>
                {[
                  { id: 'pending', label: 'Pending', color: 'slate' },
                  { id: 'fp', label: 'False Positives', color: 'red' },
                  { id: 'tp', label: 'True Positives', color: 'green' },
                  { id: 'all', label: 'All', color: 'blue' },
                ].map((f) => (
                  <button
                    key={f.id}
                    onClick={() => setAlertFilter(f.id as any)}
                    className={`px-3 py-1 rounded text-xs font-medium ${
                      alertFilter === f.id
                        ? 'bg-blue-600 text-white'
                        : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                    }`}
                  >
                    {f.label}
                  </button>
                ))}
              </div>
            </div>

            {alerts.length === 0 ? (
              <div className="bg-white border border-slate-200 rounded-xl p-12 text-center">
                <CheckCircle className="w-12 h-12 text-green-500 mx-auto mb-3" />
                <p className="text-slate-600">No alerts in this category</p>
              </div>
            ) : (
              <div className="space-y-2">
                {alerts.slice(0, 20).map((alert) => (
                  <div key={alert.alert_id} className="bg-white border border-slate-200 rounded-lg p-4 hover:border-blue-300 transition-colors">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium border ${SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.medium}`}>
                            {alert.severity.toUpperCase()}
                          </span>
                          <span className="text-sm font-semibold text-slate-900">{alert.rule_name}</span>
                          <span className="text-xs text-slate-500 font-mono">{alert.alert_id}</span>
                        </div>
                        <p className="text-sm text-slate-600 mb-2">{alert.description}</p>
                        <div className="flex items-center gap-3 text-xs text-slate-500 flex-wrap">
                          <span className="font-mono">{alert.source_ip}</span>
                          <span>•</span>
                          <span>{alert.user}</span>
                          <span>•</span>
                          <span>{alert.host}</span>
                          <span>•</span>
                          <span className="font-mono">{alert.process}</span>
                        </div>
                      </div>
                      {!alert.analyst_decision && (
                        <div className="flex gap-2 flex-shrink-0">
                          <button
                            onClick={() => decideAlert(alert.alert_id, 'true_positive')}
                            className="px-3 py-1.5 bg-red-50 text-red-700 hover:bg-red-100 rounded text-xs font-medium flex items-center gap-1"
                          >
                            <AlertTriangle className="w-3.5 h-3.5" /> True Positive
                          </button>
                          <button
                            onClick={() => decideAlert(alert.alert_id, 'false_positive')}
                            className="px-3 py-1.5 bg-slate-100 text-slate-700 hover:bg-slate-200 rounded text-xs font-medium flex items-center gap-1"
                          >
                            <XCircle className="w-3.5 h-3.5" /> False Positive
                          </button>
                        </div>
                      )}
                      {alert.analyst_decision === 'true_positive' && (
                        <span className="text-xs font-medium text-red-700 bg-red-50 px-2 py-1 rounded flex items-center gap-1">
                          <AlertTriangle className="w-3.5 h-3.5" /> TP
                        </span>
                      )}
                      {alert.analyst_decision === 'false_positive' && (
                        <span className="text-xs font-medium text-slate-700 bg-slate-100 px-2 py-1 rounded flex items-center gap-1">
                          <XCircle className="w-3.5 h-3.5" /> FP
                        </span>
                      )}
                    </div>
                  </div>
                ))}
                {alerts.length > 20 && (
                  <p className="text-center text-sm text-slate-500 py-3">
                    Showing 20 of {alerts.length} alerts
                  </p>
                )}
              </div>
            )}
          </div>
        )}

        {/* RULES TAB */}
        {activeTab === 'rules' && (
          <div className="space-y-4">
            {rules.length === 0 ? (
              <div className="bg-white border border-slate-200 rounded-xl p-12 text-center">
                <Zap className="w-12 h-12 text-slate-300 mx-auto mb-3" />
                <p className="text-slate-600 mb-1">No tuning rules suggested yet</p>
                <p className="text-sm text-slate-500">Triage more alerts to detect FP patterns</p>
              </div>
            ) : (
              rules.map((rule) => (
                <div key={rule.rule_id} className="bg-white border border-slate-200 rounded-xl p-5">
                  <div className="flex items-start justify-between gap-4 mb-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-2 flex-wrap">
                        <span className="text-xs font-mono text-slate-500">{rule.rule_id}</span>
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                          rule.confidence >= 0.8 ? 'bg-green-100 text-green-800' :
                          rule.confidence >= 0.6 ? 'bg-yellow-100 text-yellow-800' :
                          'bg-orange-100 text-orange-800'
                        }`}>
                          {Math.round(rule.confidence * 100)}% confidence
                        </span>
                        <span className="px-2 py-0.5 bg-purple-100 text-purple-800 rounded text-xs font-medium">
                          {rule.suggested_action}
                        </span>
                      </div>
                      <h3 className="font-semibold text-slate-900 mb-1">{rule.name}</h3>
                      <p className="text-sm text-slate-600">{rule.description}</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-3 mb-4">
                    <MiniStat icon={AlertTriangle} label="Existing FPs" value={rule.fp_count} />
                    <MiniStat icon={TrendingDown} label="FP Reduction" value={`${rule.estimated_fp_reduction}/wk`} />
                    <MiniStat icon={Clock} label="Time Saved" value={`${rule.estimated_time_saved_minutes}min/wk`} />
                  </div>

                  <div className="bg-slate-50 rounded p-3 mb-4 font-mono text-xs text-slate-700">
                    {Object.entries(rule.pattern).map(([k, v]) => (
                      <div key={k}>
                        <span className="text-blue-600">{k}</span>
                        <span className="text-slate-500">: </span>
                        <span>{String(v)}</span>
                      </div>
                    ))}
                  </div>

                  <div className="flex gap-2">
                    <button
                      onClick={() => applyRule(rule.rule_id)}
                      className="flex-1 bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center justify-center gap-2"
                    >
                      <CheckCircle className="w-4 h-4" /> Apply Rule
                    </button>
                    <button
                      onClick={() => rejectRule(rule.rule_id)}
                      className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-sm font-medium flex items-center gap-2"
                    >
                      <XCircle className="w-4 h-4" /> Reject
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </main>

      <footer className="border-t border-slate-200 mt-20 bg-white">
        <div className="max-w-7xl mx-auto px-6 py-6 text-center text-sm text-slate-500">
          FP Tuning Dashboard v2.0
        </div>
      </footer>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, subtext, color }: any) {
  const colors: Record<string, string> = {
    blue: 'bg-blue-50 text-blue-600',
    red: 'bg-red-50 text-red-600',
    green: 'bg-green-50 text-green-600',
    purple: 'bg-purple-50 text-purple-600',
  };
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center mb-3 ${colors[color]}`}>
        <Icon className="w-5 h-5" />
      </div>
      <p className="text-2xl font-bold text-slate-900">{value}</p>
      <p className="text-sm font-medium text-slate-700 mt-0.5">{label}</p>
      {subtext && <p className="text-xs text-slate-500 mt-1">{subtext}</p>}
    </div>
  );
}

function MiniStat({ icon: Icon, label, value }: any) {
  return (
    <div className="bg-slate-50 rounded-lg p-3">
      <div className="flex items-center gap-1.5 text-xs text-slate-500 mb-1">
        <Icon className="w-3.5 h-3.5" />
        {label}
      </div>
      <p className="text-sm font-semibold text-slate-900">{value}</p>
    </div>
  );
}
