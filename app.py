import os
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from werkzeug.utils import secure_filename
from detector.url_analyzer import URLAnalyzer
from detector.email_analyzer import EmailAnalyzer
from detector.vt_checker import VTChecker
import uuid
import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = "phish_detect_secret"
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize analyzers
url_analyzer = URLAnalyzer()
email_analyzer = EmailAnalyzer()
vt_checker = VTChecker() # Will use env var if present

# Simple in-memory alert history
alerts = []

def add_alert(alert_type, target, analysis):
    alert = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": alert_type,
        "target": target,
        "score": analysis.get("score", 0),
        "severity": analysis.get("severity", "Low") if "severity" in analysis else ("High" if analysis.get("score", 0) > 50 else "Low"),
        "details": analysis
    }
    alerts.insert(0, alert)
    return alert

@app.route('/')
def index():
    return render_template('dashboard.html', alerts=alerts[:10])

@app.route('/analyze-url', methods=['POST'])
def analyze_url():
    url = request.form.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    analysis = url_analyzer.analyze(url)
    # Add VT data if available
    vt_data = vt_checker.check_url(url)
    analysis['vt_data'] = vt_data
    
    alert = add_alert("URL", url, analysis)
    return jsonify(alert)

@app.route('/upload-eml', methods=['POST'])
def upload_eml():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    
    if file and file.filename.endswith('.eml'):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        try:
            analysis = email_analyzer.analyze_eml(file_path)
            
            # Enrich with VirusTotal data for each URL found in email
            for entry in analysis.get('urls', []):
                vt_res = vt_checker.check_url(entry['url'])
                entry['vt_data'] = vt_res
                if vt_res.get('status') == 'success' and vt_res.get('malicious', 0) > 0:
                    analysis['score'] += 20
                    analysis['suspicious_indicators'].append(f"VT flagged link as malicious: {entry['url']}")

            # Enrich with VirusTotal data for each attachment found in email
            for attach in analysis.get('attachments', []):
                vt_res = vt_checker.check_file_hash(attach['sha256'])
                attach['vt_data'] = vt_res
                if vt_res.get('status') == 'success' and vt_res.get('malicious', 0) > 0:
                    analysis['score'] += 40
                    analysis['suspicious_indicators'].append(f"VT flagged attachment as malicious: {attach['filename']}")

            # Recalculate severity after enrichment
            if analysis["score"] >= 70:
                analysis["severity"] = "High"
            elif analysis["score"] >= 30:
                analysis["severity"] = "Medium"
            else:
                analysis["severity"] = "Low"

            alert = add_alert("Email", filename, analysis)
            return jsonify(alert)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            if os.path.exists(file_path):
                os.remove(file_path) # Clean up
    
    return jsonify({"error": "Invalid file type. Please upload a .eml file"}), 400

@app.route('/alerts')
def get_alerts():
    return jsonify(alerts)

@app.route('/alert/<alert_id>')
def get_alert_detail(alert_id):
    alert = next((a for a in alerts if a['id'] == alert_id), None)
    if alert:
        return jsonify(alert)
    return jsonify({"error": "Alert not found"}), 404

if __name__ == '__main__':
    app.run(debug=True, port=5000)
