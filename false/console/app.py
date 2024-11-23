from flask import Flask, render_template, request, jsonify
import requests

app = Flask(__name__)

CENTRAL_SERVER_URL = "http://localhost:8080"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/rules')
def get_rules():
    response = requests.get(f"{CENTRAL_SERVER_URL}/rules")
    return jsonify(response.json())

@app.route('/rule', methods=['POST'])
def set_rule():
    rule = request.json
    response = requests.post(f"{CENTRAL_SERVER_URL}/rule", json=rule)
    return jsonify(response.json()), response.status_code

@app.route('/logs')
def get_logs():
    response = requests.get(f"{CENTRAL_SERVER_URL}/logs")
    return jsonify(response.json())

if __name__ == '__main__':
    app.run(debug=True)