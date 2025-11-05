from flask import Flask, jsonify, request, send_file, render_template_string
from flask_cors import CORS
from pymongo import MongoClient
import bcrypt
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import os
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
import tempfile
from pyngrok import ngrok

app = Flask(__name__)
CORS(app)

# Configuration
app.config["MONGO_URI"] = 'mongodb://localhost:27017/NIDS'
app.config["JWT_SECRET_KEY"] = 'XlcM-gDnD_qkJwASM5DLRWht36fmwMLCx5nTPDErtbY'
app.config['UPLOAD_FOLDER'] = 'uploads'
jwt = JWTManager(app)

# MongoDB connection
client = MongoClient(app.config["MONGO_URI"])
db = client.NIDS

# HTML template with embedded CSS and JavaScript
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Network Intrusion Detection System</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        @keyframes gradientBG {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        body {
            font-family: 'Poppins', Arial, sans-serif;
            background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
            background-size: 400% 400%;
            animation: gradientBG 8s ease infinite;
            margin: 0;
            padding: 20px;
            color: #ffffff;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            overflow-x: hidden;
        }

        .container {
            max-width: 800px;
            background: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(20px);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.2);
            position: relative;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            width: 100%;
        }

        h2, h3 {
            color: #ffffff;
            font-size: 32px;
            font-weight: 700;
            border-bottom: 3px solid #4ca1af;
            padding-bottom: 12px;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            gap: 12px;
            letter-spacing: 0.5px;
        }

        h3 { font-size: 24px; }

        label {
            display: block;
            margin-bottom: 14px;
            font-size: 18px;
            color: #ddd;
            font-weight: 500;
        }

        input[type="text"],
        input[type="password"],
        input[type="file"] {
            width: 100%;
            padding: 16px;
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.3);
            background-color: rgba(255, 255, 255, 0.1);
            color: #ffffff;
            font-size: 16px;
            transition: border-color 0.3s ease;
            outline: none;
            box-sizing: border-box;
        }

        input[type="text"]:hover,
        input[type="password"]:hover,
        input[type="file"]:hover {
            border-color: #4ca1af;
            background-color: rgba(255, 255, 255, 0.15);
        }

        .btn, .btn-primary, .btn-secondary {
            padding: 16px 40px;
            border-radius: 30px;
            font-size: 18px;
            font-weight: 600;
            text-transform: uppercase;
            cursor: pointer;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 12px;
            justify-content: center;
            border: none;
            outline: none;
        }

        .btn-primary {
            background: linear-gradient(90deg, #4ca1af, #2c7ef8);
            color: #ffffff;
            box-shadow: 0 10px 30px rgba(76, 161, 175, 0.6);
        }

        .btn-secondary {
            background: linear-gradient(to right, #e74c3c, #c0392b);
            color: #ffffff;
            box-shadow: 0 10px 30px rgba(231, 76, 60, 0.6);
        }

        .btn:hover, .btn-primary:hover, .btn-secondary:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 36px rgba(76, 161, 175, 0.8);
        }

        .result-box {
            margin-top: 25px;
            padding: 20px;
            border-radius: 16px;
            display: none;
        }

        .safe {
            background: rgba(13, 110, 67, 0.2);
            border: 1px solid #0d6e43;
        }

        .danger {
            background: rgba(181, 42, 55, 0.2);
            border: 1px solid #b52a37;
        }

        .loading {
            display: none;
            text-align: center;
            margin: 25px 0;
        }

        .spinner {
            width: 40px;
            height: 40px;
            border: 4px solid rgba(76, 161, 175, 0.2);
            border-radius: 50%;
            border-left-color: #4ca1af;
            animation: spin 1s linear infinite;
            margin: 0 auto 15px;
        }

        .alert {
            padding: 15px;
            background: rgba(181, 42, 55, 0.2);
            color: #ffffff;
            border-radius: 12px;
            margin-top: 15px;
            display: none;
            border: 1px solid #b52a37;
        }

        .stats-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .stat-card {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .stat-card h4 {
            color: #4ca1af;
            margin-top: 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
            padding-bottom: 10px;
            margin-bottom: 15px;
        }

        .button-group {
            display: flex;
            gap: 16px;
            margin-top: 20px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .form-group {
            margin-bottom: 20px;
        }

        ul {
            list-style: none;
            padding: 0;
        }

        li {
            margin-bottom: 8px;
            color: #ffffff;
        }
    </style>
</head>
<body>
    <div class="container">
        <div id="login-section">
            <h2><i class="fa-solid fa-lock"></i> Login</h2>
            <form id="login-form">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" required>
                </div>
                <button type="submit" class="btn btn-primary">
                    <i class="fa-solid fa-sign-in-alt"></i> Login
                </button>
            </form>
            <div class="alert" id="login-error"></div>
        </div>

        <div id="upload-section" style="display: none;">
            <h2><i class="fa-solid fa-shield-halved"></i> Network Intrusion Detection</h2>
            <form id="upload-form">
                <div class="form-group">
                    <label for="file">Upload network traffic data (CSV)</label>
                    <input type="file" id="file" accept=".csv" required>
                </div>
                <div class="button-group">
                    <button type="submit" class="btn btn-primary">
                        <i class="fa-solid fa-upload"></i> Analyze Traffic
                    </button>
                    <button type="button" class="btn btn-secondary" id="logout-btn">
                        <i class="fa-solid fa-sign-out-alt"></i> Logout
                    </button>
                </div>
            </form>

            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>Analyzing network traffic patterns...</p>
            </div>

            <div class="result-box" id="result-box">
                <!-- Results will be populated here -->
            </div>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const token = localStorage.getItem('nids_token');

            // Check if already logged in
            if (token) {
                document.getElementById('login-section').style.display = 'none';
                document.getElementById('upload-section').style.display = 'block';
            }

            // Login form handling
            document.getElementById('login-form').addEventListener('submit', function(e) {
                e.preventDefault();

                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;

                fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.access_token) {
                        localStorage.setItem('nids_token', data.access_token);
                        document.getElementById('login-section').style.display = 'none';
                        document.getElementById('upload-section').style.display = 'block';
                    } else {
                        const errorBox = document.getElementById('login-error');
                        errorBox.textContent = data.message || 'Login failed. Please check your credentials.';
                        errorBox.style.display = 'block';
                    }
                })
                .catch(error => {
                    const errorBox = document.getElementById('login-error');
                    errorBox.textContent = 'Connection error. Please try again.';
                    errorBox.style.display = 'block';
                });
            });

            // File upload and analysis
            document.getElementById('upload-form').addEventListener('submit', function(e) {
                e.preventDefault();

                const fileInput = document.getElementById('file');
                const file = fileInput.files[0];

                if (!file) {
                    alert('Please select a file to analyze');
                    return;
                }

                const token = localStorage.getItem('nids_token');
                if (!token) {
                    alert('Session expired. Please login again.');
                    document.getElementById('login-section').style.display = 'block';
                    document.getElementById('upload-section').style.display = 'none';
                    return;
                }

                const formData = new FormData();
                formData.append('file', file);

                document.getElementById('loading').style.display = 'block';
                document.getElementById('result-box').style.display = 'none';

                fetch('/detect', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    },
                    body: formData
                })
                .then(response => {
                    if (response.status === 401) {
                        localStorage.removeItem('nids_token');
                        document.getElementById('login-section').style.display = 'block';
                        document.getElementById('upload-section').style.display = 'none';
                        throw new Error('Authentication expired. Please login again.');
                    }
                    return response.json();
                })
                .then(data => {
                    const resultBox = document.getElementById('result-box');
                    
                    if (data.error) {
                        resultBox.className = 'result-box danger';
                        resultBox.innerHTML = `<h3>Error Processing File</h3>
                                             <p>An error occurred while analyzing the file: ${data.error}</p>`;
                        resultBox.style.display = 'block';
                        return;
                    }
                    
                    const stats = data.stats || {
                        total_connections: 0,
                        protocols: {},
                        services: {},
                        flags: {},
                        avg_src_bytes: 0,
                        avg_dst_bytes: 0,
                        total_failed_logins: 0,
                        root_shell_attempts: 0,
                        su_attempts: 0,
                        error_rate_stats: {
                            avg_serror_rate: 0,
                            avg_rerror_rate: 0
                        }
                    };
                    
                    const attack_indicators = data.attack_indicators || {
                        dos_indicators: 0,
                        probe_indicators: 0,
                        r2l_indicators: 0,
                        u2r_indicators: 0
                    };

                    let html = '';
                    if (data.is_intrusion) {
                        resultBox.className = 'result-box danger';
                        html += `
                            <h3><i class="fa-solid fa-exclamation-triangle"></i> Intrusion Detected!</h3>
                            <p>Warning! The analyzed network traffic contains patterns indicative of an intrusion attempt.</p>
                            <div class="stats-container">
                                <div class="stat-card">
                                    <h4><i class="fa-solid fa-chart-bar"></i> Detection Summary</h4>
                                    <p>Intrusion packets: ${data.intrusion_count || 0}</p>
                                    <p>Normal packets: ${data.normal_count || 0}</p>
                                    <p>Total connections: ${stats.total_connections}</p>
                                </div>

                                <div class="stat-card">
                                    <h4><i class="fa-solid fa-bug"></i> Attack Indicators</h4>
                                    <p>DoS indicators: ${attack_indicators.dos_indicators}</p>
                                    <p>Probe indicators: ${attack_indicators.probe_indicators}</p>
                                    <p>Remote to Local: ${attack_indicators.r2l_indicators}</p>
                                    <p>User to Root: ${attack_indicators.u2r_indicators}</p>
                                </div>

                                <div class="stat-card">
                                    <h4><i class="fa-solid fa-network-wired"></i> Protocol Distribution</h4>
                                    <ul>
                                        ${Object.entries(stats.protocols).map(([key, value]) =>
                                            `<li>${key}: ${value}</li>`).join('') || '<li>No protocol data</li>'}
                                    </ul>
                                </div>
                            </div>

                            <div class="stats-container">
                                <div class="stat-card">
                                    <h4><i class="fa-solid fa-triangle-exclamation"></i> Attack Severity</h4>
                                    <p>Failed login attempts: ${stats.total_failed_logins}</p>
                                    <p>Root shell attempts: ${stats.root_shell_attempts}</p>
                                    <p>SU attempts: ${stats.su_attempts}</p>
                                    <p>Average error rate: ${stats.error_rate_stats?.avg_serror_rate || 0}%</p>
                                </div>

                                <div class="stat-card">
                                    <h4><i class="fa-solid fa-server"></i> Top Services Targeted</h4>
                                    <ul>
                                        ${Object.entries(stats.services).map(([key, value]) =>
                                            `<li>${key}: ${value}</li>`).join('') || '<li>No service data</li>'}
                                    </ul>
                                </div>
                            </div>`;
                    } else {
                        resultBox.className = 'result-box safe';
                        html += `
                            <h3><i class="fa-solid fa-check-circle"></i> No Intrusion Detected</h3>
                            <p>The analyzed network traffic appears to be normal.</p>
                            <div class="stats-container">
                                <div class="stat-card">
                                    <h4><i class="fa-solid fa-chart-line"></i> Traffic Summary</h4>
                                    <p>Total connections: ${stats.total_connections}</p>
                                    <p>Avg source bytes: ${stats.avg_src_bytes}</p>
                                    <p>Avg destination bytes: ${stats.avg_dst_bytes}</p>
                                </div>

                                <div class="stat-card">
                                    <h4><i class="fa-solid fa-network-wired"></i> Protocol Distribution</h4>
                                    <ul>
                                        ${Object.entries(stats.protocols).map(([key, value]) =>
                                            `<li>${key}: ${value}</li>`).join('') || '<li>No protocol data</li>'}
                                    </ul>
                                </div>
                            </div>`;
                    }

                    resultBox.innerHTML = html;
                    resultBox.style.display = 'block';
                })
                .catch(error => {
                    const resultBox = document.getElementById('result-box');
                    resultBox.className = 'result-box danger';
                    resultBox.innerHTML = `<h3><i class="fa-solid fa-times-circle"></i> Error</h3><p>${error.message || 'Error processing your request'}</p>`;
                    resultBox.style.display = 'block';
                })
                .finally(() => {
                    document.getElementById('loading').style.display = 'none';
                });
            });

            // Logout handler
            document.getElementById('logout-btn').addEventListener('click', function() {
                localStorage.removeItem('nids_token');
                document.getElementById('login-section').style.display = 'block';
                document.getElementById('upload-section').style.display = 'none';
                document.getElementById('result-box').style.display = 'none';
                document.getElementById('login-error').style.display = 'none';
                document.getElementById('username').value = '';
                document.getElementById('password').value = '';
                document.getElementById('file').value = '';
            });
        });
    </script>
</body>
</html>

"""

@app.route('/')
def home():
    return render_template_string(html_template)

# Keep your existing API endpoints intact
@app.route('/api')
def api_info():
    return jsonify({
        "status": "online",
        "message": "Network Intrusion Detection System API is running",
        "endpoints": {
            "/login": "POST - Authenticate and get JWT token",
            "/detect": "POST - Upload file for intrusion detection (requires JWT)"
        }
    })

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    # First check users collection
    user = db.users.find_one({'username': data['username']})

    # If not found, check admins collection
    if not user:
        user = db.admins.find_one({'username': data['username']})

    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user['password']):
        access_token = create_access_token(identity=data['username'])
        return jsonify({"access_token": access_token})
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/detect', methods=['POST'])
@jwt_required()
def detect():
    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    try:
        # Save to temp file
        _, temp_path = tempfile.mkstemp()
        file.save(temp_path)

        # Make predictions with detailed stats
        result = make_predictions(
            temp_path,
            'naive_bayes_model.pkl',
            'standard_scaler.pkl',
            'selected_features.pkl'
        )

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def make_predictions(test_data_file, model_file, scaler_file, features_file):
    try:
        # Load the model, scaler, and features
        model = joblib.load(model_file)
        scaler = joblib.load(scaler_file)
        features = joblib.load(features_file)

        # Read the CSV file
        df = pd.read_csv(test_data_file)

        # Initialize stats with default values in case of errors
        stats = {
            'total_connections': int(len(df)),
            'protocols': {},
            'services': {},
            'flags': {},
            'avg_src_bytes': 0,
            'avg_dst_bytes': 0,
            'total_failed_logins': 0,
            'root_shell_attempts': 0,
            'su_attempts': 0,
            'error_rate_stats': {
                'avg_serror_rate': 0,
                'avg_rerror_rate': 0,
            }
        }

        attack_indicators = {
            'dos_indicators': 0,
            'probe_indicators': 0,
            'r2l_indicators': 0,
            'u2r_indicators': 0
        }

        # Extract features that exist in the DataFrame
        if 'protocol_type' in df.columns:
            # Convert to regular Python dict with int values
            protocols_dict = df['protocol_type'].value_counts().to_dict()
            stats['protocols'] = {k: int(v) for k, v in protocols_dict.items()}

        if 'service' in df.columns:
            services_dict = df['service'].value_counts().head(5).to_dict()
            stats['services'] = {k: int(v) for k, v in services_dict.items()}

        if 'flag' in df.columns:
            flags_dict = df['flag'].value_counts().to_dict()
            stats['flags'] = {k: int(v) for k, v in flags_dict.items()}

        if 'src_bytes' in df.columns:
            stats['avg_src_bytes'] = float(round(df['src_bytes'].mean(), 2))

        if 'dst_bytes' in df.columns:
            stats['avg_dst_bytes'] = float(round(df['dst_bytes'].mean(), 2))

        if 'num_failed_logins' in df.columns:
            stats['total_failed_logins'] = int(df['num_failed_logins'].sum())

        if 'root_shell' in df.columns:
            stats['root_shell_attempts'] = int(df['root_shell'].sum())

        if 'su_attempted' in df.columns:
            stats['su_attempts'] = int(df['su_attempted'].sum())

        if all(col in df.columns for col in ['serror_rate', 'rerror_rate']):
            stats['error_rate_stats'] = {
                'avg_serror_rate': float(round(df['serror_rate'].mean() * 100, 2)),
                'avg_rerror_rate': float(round(df['rerror_rate'].mean() * 100, 2)),
            }

        # Calculate attack indicators only if all required columns exist
        if all(col in df.columns for col in ['count', 'serror_rate']):
            attack_indicators['dos_indicators'] = int(len(df[(df['count'] > 100) & (df['serror_rate'] > 0.7)]))

        if all(col in df.columns for col in ['dst_host_count', 'dst_host_same_srv_rate']):
            attack_indicators['probe_indicators'] = int(len(df[(df['dst_host_count'] > 150) & (df['dst_host_same_srv_rate'] < 0.1)]))

        if all(col in df.columns for col in ['num_failed_logins', 'num_compromised']):
            attack_indicators['r2l_indicators'] = int(len(df[(df['num_failed_logins'] > 0) | (df['num_compromised'] > 0)]))

        if all(col in df.columns for col in ['root_shell', 'su_attempted']):
            attack_indicators['u2r_indicators'] = int(len(df[(df['root_shell'] > 0) | (df['su_attempted'] > 0)]))

        # Preprocessing for model
        le = LabelEncoder()
        for col in df.columns:
            if df[col].dtype == 'object':
                df[col] = le.fit_transform(df[col])

        # Make sure we only use features that exist in the model
        available_features = [f for f in features if f in df.columns]
        X = df[available_features]
        X = scaler.transform(X)

        predictions = model.predict(X)
        is_intrusion = int(predictions.mean() > 0.5)

        # Convert numpy types to Python native types
        return {
            'is_intrusion': int(is_intrusion),
            'stats': stats,
            'attack_indicators': attack_indicators,
            'intrusion_count': int(sum(predictions)),
            'normal_count': int(len(predictions) - sum(predictions))
        }

    except Exception as e:
        print(f"Error in make_predictions: {str(e)}")
        # Return a minimal result on error
        return {
            'is_intrusion': 1,  # Default to warning on error
            'stats': {
                'total_connections': 0,
                'protocols': {},
                'services': {},
                'flags': {},
                'avg_src_bytes': 0,
                'avg_dst_bytes': 0,
                'total_failed_logins': 0,
                'root_shell_attempts': 0,
                'su_attempts': 0,
                'error_rate_stats': {
                    'avg_serror_rate': 0,
                    'avg_rerror_rate': 0,
                }
            },
            'attack_indicators': {
                'dos_indicators': 0,
                'probe_indicators': 0,
                'r2l_indicators': 0,
                'u2r_indicators': 0
            },
            'intrusion_count': 0,
            'normal_count': 0,
            'error': str(e)
        }

        
if __name__ == '__main__':
    # Create upload folder if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Start ngrok tunnel
    public_url = ngrok.connect(5000)
    print(f" * ngrok tunnel \"{public_url}\" -> \"http://127.0.0.1:5000\"")

    # Run the app on port 5000
    app.run(host='0.0.0.0', port=5000)