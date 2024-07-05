from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# Endpoint para consultar VirusTotal
@app.route('/consultar', methods=['POST'])
def consultar_virus_total():
    data = request.json
    ioc = data.get('ioc')
    api_key = data.get('apiKey')

    if not ioc or not api_key:
        return jsonify({'error': 'Missing IOC or API key'}), 400

    url = f'https://www.virustotal.com/api/v3/search?query={ioc}'
    headers = {
        'x-apikey': api_key
    }

    response = requests.get(url, headers=headers)

    if response.ok:
        return jsonify(response.json())
    else:
        return jsonify({'error': 'Failed to fetch data from VirusTotal'}), response.status_code

if __name__ == '__main__':
    app.run()

