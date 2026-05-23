"""
False Positive Tuning Dashboard - Backend API
Deployed on Railway.app
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from dataclasses import asdict
import os
import json
from datetime import datetime
from uuid import uuid4

from src.fp_engine import FPDetectionEngine, Alert, TuningRule
from src.sample_data import generate_sample_alerts
from src.rule_library import get_all_rules, get_rule_by_name, fetch_sigma_rules_from_github

app = Flask(__name__)

# CORS for Vercel frontend
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "http://localhost:3000",
            "http://localhost:5173",
            r"https://.*\.vercel\.app",
            "https://fp-tuning-dashboard.vercel.app",
        ],
        "methods": ["GET", "POST", "OPTIONS", "PUT"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

engine = FPDetectionEngine()


def load_sample_data():
    """Load sample alerts into engine."""
    try:
        with open("data/sample_alerts.json", "r") as f:
            alerts = json.load(f)
        engine.add_alerts(alerts)
        engine.detect_patterns()
    except FileNotFoundError:
        alerts = generate_sample_alerts()
        engine.add_alerts(alerts)
        engine.detect_patterns()


load_sample_data()


@app.route('/')
def root():
    return jsonify({
        'service': 'False Positive Tuning Dashboard API',
        'version': '1.0.0',
        'status': 'running',
        'endpoints': {
            'GET /api/health': 'Health check',
            'GET /api/metrics': 'Dashboard metrics',
            'GET /api/alerts': 'List alerts (?status=pending|fp|tp)',
            'POST /api/alerts/<id>/decision': 'Update analyst decision',
            'GET /api/rules': 'Suggested tuning rules',
            'POST /api/rules/<id>/apply': 'Apply tuning rule',
            'POST /api/rules/<id>/reject': 'Reject tuning rule',
            'POST /api/analyze': 'Re-run pattern detection',
            'POST /api/seed': 'Reset to sample data'
        }
    })


@app.route('/api/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'alerts_loaded': len(engine.alerts),
        'rules_suggested': len(engine.tuning_rules)
    })


@app.route('/api/metrics')
def metrics():
    return jsonify({
        **engine.get_metrics(),
        'severity_distribution': engine.get_severity_distribution(),
        'decision_distribution': engine.get_decision_distribution(),
    })


@app.route('/api/alerts')
def list_alerts():
    status = request.args.get('status', 'all')
    if status == 'pending':
        filtered = [a for a in engine.alerts if a.analyst_decision in (None, "pending")]
    elif status == 'fp':
        filtered = [a for a in engine.alerts if a.analyst_decision == "false_positive"]
    elif status == 'tp':
        filtered = [a for a in engine.alerts if a.analyst_decision == "true_positive"]
    else:
        filtered = engine.alerts
    return jsonify({
        'count': len(filtered),
        'alerts': [asdict(a) for a in filtered]
    })


@app.route('/api/alerts/<alert_id>/decision', methods=['POST', 'OPTIONS'])
def update_decision(alert_id):
    if request.method == 'OPTIONS':
        return '', 204
    data = request.json or {}
    decision = data.get('decision')
    notes = data.get('notes', '')
    analyst_id = data.get('analyst_id', 'analyst_1')
    
    if decision not in ('true_positive', 'false_positive'):
        return jsonify({'error': 'Invalid decision'}), 400
    
    success = engine.update_decision(alert_id, decision, notes, analyst_id)
    if not success:
        return jsonify({'error': 'Alert not found'}), 404
    
    engine.detect_patterns()
    return jsonify({
        'success': True,
        'alert_id': alert_id,
        'decision': decision,
        'rules_suggested': len([r for r in engine.tuning_rules if r.status == 'pending'])
    })


@app.route('/api/rules')
def list_rules():
    status = request.args.get('status', 'all')
    if status != 'all':
        filtered = [r for r in engine.tuning_rules if r.status == status]
    else:
        filtered = engine.tuning_rules
    return jsonify({
        'count': len(filtered),
        'rules': [asdict(r) for r in filtered]
    })


@app.route('/api/rules/<rule_id>/apply', methods=['POST', 'OPTIONS'])
def apply_rule(rule_id):
    if request.method == 'OPTIONS':
        return '', 204
    success = engine.apply_rule(rule_id)
    if not success:
        return jsonify({'error': 'Rule not found'}), 404
    return jsonify({
        'success': True,
        'rule_id': rule_id,
        'status': 'applied'
    })


@app.route('/api/rules/<rule_id>/reject', methods=['POST', 'OPTIONS'])
def reject_rule(rule_id):
    if request.method == 'OPTIONS':
        return '', 204
    success = engine.reject_rule(rule_id)
    if not success:
        return jsonify({'error': 'Rule not found'}), 404
    return jsonify({'success': True, 'rule_id': rule_id, 'status': 'rejected'})


@app.route('/api/analyze', methods=['POST', 'OPTIONS'])
def analyze():
    if request.method == 'OPTIONS':
        return '', 204
    rules = engine.detect_patterns()
    return jsonify({
        'success': True,
        'rules_generated': len(rules),
        'rules': [asdict(r) for r in rules]
    })


@app.route('/api/seed', methods=['POST', 'OPTIONS'])
def seed():
    if request.method == 'OPTIONS':
        return '', 204
    global engine
    engine = FPDetectionEngine()
    load_sample_data()
    return jsonify({
        'success': True,
        'alerts_loaded': len(engine.alerts),
        'rules_suggested': len(engine.tuning_rules)
    })


INGEST_API_KEY = os.getenv('INGEST_API_KEY', '')
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')


def _adapt_splunk(data: dict) -> dict:
    result = data.get('result', data)
    return {
        'alert_id': f"SPL-{result.get('sid', data.get('sid', uuid4().hex[:8]))}",
        'timestamp': datetime.now().isoformat(),
        'rule_name': data.get('search_name', result.get('rule_name', 'Unknown Rule')),
        'severity': result.get('severity', result.get('urgency', 'medium')).lower(),
        'source_ip': result.get('src_ip', result.get('src', result.get('source_ip', '0.0.0.0'))),
        'destination_ip': result.get('dest_ip', result.get('dest', '0.0.0.0')),
        'user': result.get('user', result.get('src_user', 'unknown')),
        'host': result.get('host', result.get('dest_host', 'unknown')),
        'process': result.get('process', result.get('process_name', 'unknown')),
        'description': result.get('_raw', f"Splunk alert: {data.get('search_name', 'Unknown')}"),
        'analyst_decision': None,
    }


def _adapt_elastic(data: dict) -> dict:
    rule = data.get('rule', {})
    src = data.get('source', {})
    return {
        'alert_id': f"ELK-{data.get('id', uuid4().hex[:8])}",
        'timestamp': data.get('@timestamp', datetime.now().isoformat()),
        'rule_name': rule.get('name', 'Unknown Rule'),
        'severity': rule.get('severity', 'medium').lower(),
        'source_ip': src.get('ip', '0.0.0.0'),
        'destination_ip': data.get('destination', {}).get('ip', '0.0.0.0'),
        'user': data.get('user', {}).get('name', 'unknown'),
        'host': data.get('host', {}).get('hostname', data.get('host', {}).get('name', 'unknown')),
        'process': data.get('process', {}).get('name', data.get('process', {}).get('executable', 'unknown')),
        'description': f"Elastic alert: {rule.get('name', 'Unknown')}",
        'analyst_decision': None,
    }


def _adapt_generic(data: dict) -> dict:
    return {
        'alert_id': data.get('alert_id', f"GEN-{uuid4().hex[:8]}"),
        'timestamp': data.get('timestamp', datetime.now().isoformat()),
        'rule_name': data.get('rule_name', data.get('rule', 'Unknown Rule')),
        'severity': data.get('severity', 'medium').lower(),
        'source_ip': data.get('source_ip', data.get('src_ip', '0.0.0.0')),
        'destination_ip': data.get('destination_ip', data.get('dest_ip', '0.0.0.0')),
        'user': data.get('user', data.get('username', 'unknown')),
        'host': data.get('host', data.get('hostname', 'unknown')),
        'process': data.get('process', data.get('process_name', 'unknown')),
        'description': data.get('description', data.get('message', 'Ingested alert')),
        'analyst_decision': None,
    }


@app.route('/api/library')
def rule_library():
    rules = get_all_rules()

    # Annotate each rule with FP/TP counts from live alert data
    fp_by_rule = {}
    tp_by_rule = {}
    for alert in engine.alerts:
        if alert.analyst_decision == 'false_positive':
            fp_by_rule[alert.rule_name] = fp_by_rule.get(alert.rule_name, 0) + 1
        elif alert.analyst_decision == 'true_positive':
            tp_by_rule[alert.rule_name] = tp_by_rule.get(alert.rule_name, 0) + 1

    annotated = []
    for rule in rules:
        fp = fp_by_rule.get(rule['name'], 0)
        tp = tp_by_rule.get(rule['name'], 0)
        total = fp + tp
        annotated.append({
            **rule,
            'fp_count': fp,
            'tp_count': tp,
            'fp_rate': round(fp / total * 100, 1) if total > 0 else None,
        })

    annotated.sort(key=lambda r: r['fp_count'], reverse=True)
    return jsonify({'count': len(annotated), 'rules': annotated})


@app.route('/api/library/fetch-sigma', methods=['POST'])
def fetch_sigma():
    """Trigger a live fetch of rule names from SigmaHQ GitHub."""
    names = fetch_sigma_rules_from_github(token=GITHUB_TOKEN)
    return jsonify({'fetched': len(names), 'sample': names[:10]})


ADAPTERS = {
    'splunk': _adapt_splunk,
    'elastic': _adapt_elastic,
    'generic': _adapt_generic,
}


@app.route('/api/ingest', methods=['POST', 'OPTIONS'])
def ingest():
    if request.method == 'OPTIONS':
        return '', 204

    if INGEST_API_KEY:
        key = request.headers.get('X-API-Key', '')
        if key != INGEST_API_KEY:
            return jsonify({'error': 'Unauthorized'}), 401

    source = request.args.get('source', 'generic').lower()
    if source not in ADAPTERS:
        return jsonify({'error': f'Unknown source. Use: {", ".join(ADAPTERS)}'}), 400

    data = request.json
    if not data:
        return jsonify({'error': 'Empty body'}), 400

    try:
        alert = ADAPTERS[source](data)
        engine.add_alerts([alert])
        engine.detect_patterns()
        return jsonify({
            'success': True,
            'alert_id': alert['alert_id'],
            'rule_name': alert['rule_name'],
            'total_alerts': len(engine.alerts),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    env = os.getenv('FLASK_ENV', 'development')
    print(f"🚀 FP Tuning API starting on port {port} ({env})")
    print(f"   Loaded {len(engine.alerts)} alerts")
    print(f"   Generated {len(engine.tuning_rules)} tuning suggestions")
    app.run(host='0.0.0.0', port=port, debug=(env == 'development'))
