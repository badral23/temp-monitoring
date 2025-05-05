#!/usr/bin/env python3
import socket
import ssl
import json
import threading
import sqlite3
import os
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_cors import CORS  # For enabling cross-origin requests

# Configuration
HOST = '0.0.0.0'
SSL_PORT = 3003  # Port for secure data collection from Raspberry Pi
API_PORT = 5000  # Port for API access from dashboard
DB_PATH = 'temperature_data.db'
CERT_PATH = 'certs/server.crt'
KEY_PATH = 'certs/server.key'

# Ensure certificates directory exists
os.makedirs('certs', exist_ok=True)

# Flask application
app = Flask(__name__, static_folder='static')
CORS(app)  # Enable CORS for all routes

# Database setup
def setup_database():
    """Set up SQLite database and tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create temperature_readings table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS temperature_readings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL,
        temperature REAL NOT NULL,
        humidity REAL NOT NULL,
        timestamp TEXT NOT NULL,
        received_at TEXT NOT NULL
    )
    ''')
    
    # Create index for faster queries
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON temperature_readings(timestamp)')
    
    conn.commit()
    conn.close()
    print(f"Database setup complete at {DB_PATH}")

def insert_reading(temp, humidity, device_id="rpi4_sensor"):
    """Insert temperature reading into database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        now = datetime.now().isoformat()
        
        cursor.execute(
            'INSERT INTO temperature_readings (device_id, temperature, humidity, timestamp, received_at) VALUES (?, ?, ?, ?, ?)',
            (
                device_id,
                temp,
                humidity,
                now,
                now
            )
        )
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error inserting data: {e}")
        return False

def generate_self_signed_cert():
    """Generate a self-signed certificate if one doesn't exist"""
    if not (os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH)):
        print("Generating self-signed certificate...")
        from OpenSSL import crypto
        
        # Create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        
        # Create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "State"
        cert.get_subject().L = "City"
        cert.get_subject().O = "Organization"
        cert.get_subject().OU = "Organizational Unit"
        cert.get_subject().CN = socket.gethostname()
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)  # 10 years
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        
        # Save certificate
        with open(CERT_PATH, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        
        # Save private key
        with open(KEY_PATH, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
            
        print(f"Self-signed certificate generated and saved to {CERT_PATH}")
    else:
        print("Certificate and key already exist")

def parse_dht_data(data_string):
    """Parse DHT11 data from string format"""
    try:
        # More flexible parsing to handle the actual Arduino output format:
        # "DHT11# Humidity: 45.20%  |  Temperature: 23.40°C"
        
        # Extract humidity using regex
        humidity_match = re.search(r'Humidity:\s*(\d+\.?\d*)%', data_string)
        if humidity_match:
            humidity = float(humidity_match.group(1))
        else:
            print(f"Could not parse humidity from: {data_string}")
            return None, None
        
        # Extract temperature using regex
        temp_match = re.search(r'Temperature:\s*(\d+\.?\d*)°C', data_string)
        if temp_match:
            temperature = float(temp_match.group(1))
        else:
            print(f"Could not parse temperature from: {data_string}")
            return None, None
            
        return temperature, humidity
    except Exception as e:
        print(f"Error parsing data: {e}")
        print(f"Raw data was: {data_string}")
        return None, None

def run_ssl_server():
    """Run the SSL server to receive encrypted data from Raspberry Pi"""
    # Generate certificate
    generate_self_signed_cert()
    
    # Create socket and bind to port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, SSL_PORT))
    server_socket.listen(1)
    
    # Wrap with SSL/TLS
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH)
    
    secure_socket = context.wrap_socket(server_socket, server_side=True)
    
    print(f"Secure server is listening on {HOST}:{SSL_PORT}")
    
    try:
        while True:
            print("Waiting for client...")
            client, addr = secure_socket.accept()
            print(f"Secure client connected from {addr}")
            
            client_thread = threading.Thread(target=handle_client, args=(client, addr))
            client_thread.daemon = True
            client_thread.start()
    
    except KeyboardInterrupt:
        print("Stopping server...")
    finally:
        secure_socket.close()
        print("Server stopped")

def handle_client(client, addr):
    """Handle client connection and data"""
    try:
        while True:
            data = client.recv(1024)
            if not data:
                print(f"Client {addr} disconnected")
                break
            
            data_string = data.decode().strip()
            print(f"Received (decrypted) from {addr}: {data_string}")
            
            # Parse and store in database
            temp, humidity = parse_dht_data(data_string)
            if temp is not None and humidity is not None:
                insert_success = insert_reading(temp, humidity)
                if insert_success:
                    print(f"Stored: Temp={temp}°C, Humidity={humidity}%")
                else:
                    print("Failed to store reading in database")
    
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        client.close()

# Serve static files for the dashboard
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

# API Endpoints
@app.route('/api/data/latest')
def get_latest_data():
    """Get latest temperature reading"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT device_id, temperature, humidity, timestamp
        FROM temperature_readings
        ORDER BY timestamp DESC
        LIMIT 1
        ''')
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return jsonify({
                'temperature': result['temperature'],
                'humidity': result['humidity'],
                'timestamp': result['timestamp'],
                'device_id': result['device_id']
            })
        else:
            return jsonify({'error': 'No data available'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/data/history')
def get_historical_data():
    """Get historical temperature data"""
    try:
        # Get query parameters
        hours = request.args.get('hours', default=24, type=int)
        minutes = request.args.get('minutes', default=0, type=int)
        device_id = request.args.get('device_id', default=None, type=str)
        limit = request.args.get('limit', default=1000, type=int)
        
        # Calculate time range
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours, minutes=minutes)
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = '''
        SELECT device_id, temperature, humidity, timestamp
        FROM temperature_readings
        WHERE timestamp >= ?
        '''
        params = [start_time.isoformat()]
        
        if device_id:
            query += ' AND device_id = ?'
            params.append(device_id)
            
        query += ' ORDER BY timestamp ASC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        
        results = cursor.fetchall()
        conn.close()
        
        data = [{
            'device_id': row['device_id'],
            'temperature': row['temperature'],
            'humidity': row['humidity'],
            'timestamp': row['timestamp']
        } for row in results]
        
        return jsonify(data)
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/data/stats')
def get_stats():
    """Get statistics about temperature and humidity"""
    try:
        # Get query parameters
        hours = request.args.get('hours', default=24, type=int)
        device_id = request.args.get('device_id', default=None, type=str)
        
        # Calculate time range
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = '''
        SELECT 
            MIN(temperature) as min_temp,
            MAX(temperature) as max_temp,
            AVG(temperature) as avg_temp,
            MIN(humidity) as min_humidity,
            MAX(humidity) as max_humidity,
            AVG(humidity) as avg_humidity,
            COUNT(*) as reading_count
        FROM temperature_readings
        WHERE timestamp >= ?
        '''
        params = [start_time.isoformat()]
        
        if device_id:
            query += ' AND device_id = ?'
            params.append(device_id)
        
        cursor.execute(query, params)
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return jsonify({
                'temperature': {
                    'min': result['min_temp'],
                    'max': result['max_temp'],
                    'avg': result['avg_temp']
                },
                'humidity': {
                    'min': result['min_humidity'],
                    'max': result['max_humidity'],
                    'avg': result['avg_humidity']
                },
                'reading_count': result['reading_count'],
                'period_hours': hours
            })
        else:
            return jsonify({'error': 'No data available'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices')
def get_devices():
    """Get list of all device IDs"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT DISTINCT device_id
        FROM temperature_readings
        ''')
        
        results = cursor.fetchall()
        conn.close()
        
        devices = [row['device_id'] for row in results]
        return jsonify(devices)
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Added endpoint for real-time updates via polling
@app.route('/api/data/realtime')
def get_realtime_data():
    """Get newest readings since a given timestamp"""
    try:
        # Get the last timestamp the client has
        last_timestamp = request.args.get('since', default=None, type=str)
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if last_timestamp:
            query = '''
            SELECT device_id, temperature, humidity, timestamp
            FROM temperature_readings
            WHERE timestamp > ?
            ORDER BY timestamp ASC
            '''
            cursor.execute(query, [last_timestamp])
        else:
            # If no timestamp is provided, just get the latest reading
            query = '''
            SELECT device_id, temperature, humidity, timestamp
            FROM temperature_readings
            ORDER BY timestamp DESC
            LIMIT 1
            '''
            cursor.execute(query)
        
        results = cursor.fetchall()
        conn.close()
        
        data = [{
            'device_id': row['device_id'],
            'temperature': row['temperature'],
            'humidity': row['humidity'],
            'timestamp': row['timestamp']
        } for row in results]
        
        return jsonify(data)
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def main():
    # Set up database
    setup_database()
    
    # Start SSL server in a separate thread
    ssl_thread = threading.Thread(target=run_ssl_server)
    ssl_thread.daemon = True
    ssl_thread.start()
    
    # Start API server
    print(f"Starting API server on port {API_PORT}")
    app.run(host=HOST, port=API_PORT, debug=False, threaded=True)

if __name__ == "__main__":
    main()