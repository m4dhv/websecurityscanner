from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# Database configuration - choose one
# PostgreSQL (recommended)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'postgresql://user:password@localhost:5432/security_scanner'
)

# SQLite (for development/simple setup)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security_scanner.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# Database Models
class ScanSession(db.Model):
    __tablename__ = 'scan_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='in_progress')  # in_progress, completed, failed
    total_urls_scanned = db.Column(db.Integer, default=0)
    vulnerabilities_found = db.Column(db.Integer, default=0)
    duration_seconds = db.Column(db.Integer)
    browser = db.Column(db.String(50))  # Chrome, Firefox, etc.
    
    vulnerabilities = db.relationship('Vulnerability', backref='session', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'target_url': self.target_url,
            'scan_date': self.scan_date.isoformat(),
            'status': self.status,
            'total_urls_scanned': self.total_urls_scanned,
            'vulnerabilities_found': self.vulnerabilities_found,
            'duration_seconds': self.duration_seconds,
            'browser': self.browser
        }


class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('scan_sessions.id'), nullable=False)
    vulnerability_type = db.Column(db.String(100), nullable=False)  # SQL Injection, XSS, etc.
    url = db.Column(db.String(500), nullable=False)
    parameter = db.Column(db.String(255))
    payload = db.Column(db.Text)
    info_type = db.Column(db.String(100))  # For sensitive info: email, phone, etc.
    severity = db.Column(db.String(50), default='medium')  # low, medium, high, critical
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'session_id': self.session_id,
            'vulnerability_type': self.vulnerability_type,
            'url': self.url,
            'parameter': self.parameter,
            'payload': self.payload,
            'info_type': self.info_type,
            'severity': self.severity,
            'timestamp': self.timestamp.isoformat()
        }


# API Endpoints

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Initialize a new scan session"""
    data = request.json
    
    session = ScanSession(
        target_url=data.get('target_url'),
        browser=data.get('browser', 'unknown')
    )
    db.session.add(session)
    db.session.commit()
    
    return jsonify({
        'session_id': session.id,
        'message': 'Scan session created'
    }), 201


@app.route('/api/scan/<int:session_id>/report', methods=['POST'])
def report_vulnerability(session_id):
    """Report a vulnerability found during scan"""
    data = request.json
    session = ScanSession.query.get(session_id)
    
    if not session:
        return jsonify({'error': 'Session not found'}), 404
    
    vulnerability = Vulnerability(
        session_id=session_id,
        vulnerability_type=data.get('type'),
        url=data.get('url'),
        parameter=data.get('parameter'),
        payload=data.get('payload'),
        info_type=data.get('info_type'),
        severity=data.get('severity', 'medium')
    )
    db.session.add(vulnerability)
    session.vulnerabilities_found = Vulnerability.query.filter_by(session_id=session_id).count() + 1
    db.session.commit()
    
    return jsonify({'message': 'Vulnerability recorded'}), 201


@app.route('/api/scan/<int:session_id>/complete', methods=['PUT'])
def complete_scan(session_id):
    """Mark scan as completed"""
    data = request.json
    session = ScanSession.query.get(session_id)
    
    if not session:
        return jsonify({'error': 'Session not found'}), 404
    
    session.status = 'completed'
    session.total_urls_scanned = data.get('total_urls_scanned', 0)
    session.duration_seconds = data.get('duration_seconds', 0)
    db.session.commit()
    
    return jsonify(session.to_dict()), 200


@app.route('/api/scans', methods=['GET'])
def get_all_scans():
    """Get all scan sessions with optional filtering"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    scans = ScanSession.query.order_by(ScanSession.scan_date.desc()).paginate(
        page=page, per_page=per_page
    )
    
    return jsonify({
        'total': scans.total,
        'pages': scans.pages,
        'current_page': page,
        'scans': [scan.to_dict() for scan in scans.items]
    }), 200


@app.route('/api/scan/<int:session_id>', methods=['GET'])
def get_scan(session_id):
    """Get detailed scan results"""
    session = ScanSession.query.get(session_id)
    
    if not session:
        return jsonify({'error': 'Session not found'}), 404
    
    return jsonify({
        'session': session.to_dict(),
        'vulnerabilities': [v.to_dict() for v in session.vulnerabilities]
    }), 200


@app.route('/api/scan/<int:session_id>/vulnerabilities', methods=['GET'])
def get_vulnerabilities(session_id):
    """Get vulnerabilities for a specific scan"""
    vuln_type = request.args.get('type')
    severity = request.args.get('severity')
    
    query = Vulnerability.query.filter_by(session_id=session_id)
    
    if vuln_type:
        query = query.filter_by(vulnerability_type=vuln_type)
    if severity:
        query = query.filter_by(severity=severity)
    
    vulnerabilities = query.all()
    
    return jsonify([v.to_dict() for v in vulnerabilities]), 200


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get overall statistics"""
    total_scans = ScanSession.query.count()
    total_vulnerabilities = Vulnerability.query.count()
    
    vuln_by_type = db.session.query(
        Vulnerability.vulnerability_type,
        db.func.count(Vulnerability.id)
    ).group_by(Vulnerability.vulnerability_type).all()
    
    vuln_by_severity = db.session.query(
        Vulnerability.severity,
        db.func.count(Vulnerability.id)
    ).group_by(Vulnerability.severity).all()
    
    return jsonify({
        'total_scans': total_scans,
        'total_vulnerabilities': total_vulnerabilities,
        'vulnerabilities_by_type': dict(vuln_by_type),
        'vulnerabilities_by_severity': dict(vuln_by_severity)
    }), 200


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
