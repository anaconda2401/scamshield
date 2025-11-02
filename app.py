# app.py

from flask import Flask, render_template, request, jsonify
from analyzer import scamshield_analyze  # <-- IMPORTS YOUR "BRAIN"
import os

app = Flask(__name__)

# ROUTE 1: THE UI (for testing)
@app.route('/')
def home():
    """Serves the simple HTML test page."""
    return render_template('index.html')

# ROUTE 2: THE CLOUD API ENDPOINT
@app.route('/api/analyze', methods=['POST'])
def analyze_api():
    """
    This is the API endpoint your 'demo.py' script will call.
    """
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({'error': 'No "message" field in JSON payload'}), 400
        
        message_text = data.get('message')

        # --- THIS IS WHERE THE MAGIC HAPPENS ---
        classification, reasoning = scamshield_analyze(message_text)
        # ---------------------------------------

        # Send the answer back as JSON
        return jsonify({
            'classification': classification,
            'reason_label': reasoning  # This is the "label" you wanted
        })
        
    except Exception as e:
        print(f"Error in /api/analyze: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# This part is only for running locally, not for PythonAnywhere
if __name__ == '__main__':
    app.run(debug=True)