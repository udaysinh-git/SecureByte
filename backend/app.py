from flask import Flask, request, jsonify
from encryption import encrypt, decrypt
import base64

app = Flask(__name__)

@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    data = request.json.get('data')
    password = request.json.get('password')
    if not data or not password:
        return jsonify({'error': 'Data and password are required'}), 400
    encrypted_data = encrypt(data.encode(), password)
    return jsonify({'encrypted_data': encrypted_data.hex()})

@app.route('/decrypt', methods=['POST'])
def decrypt_data():
    encrypted_data = bytes.fromhex(request.json.get('encrypted_data'))
    password = request.json.get('password')
    if not encrypted_data or not password:
        return jsonify({'error': 'Encrypted data and password are required'}), 400
    try:
        decrypted_data = decrypt(encrypted_data, password)
        return jsonify({'decrypted_data': decrypted_data.decode()})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/encrypt_file', methods=['POST'])
def encrypt_file():
    file = request.files['file']
    password = request.form['password']
    if not file or not password:
        return jsonify({'error': 'File and password are required'}), 400
    file_data = file.read()
    encrypted_data = encrypt(file_data, password)
    return jsonify({'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8')})

@app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    encrypted_data = base64.b64decode(request.json.get('encrypted_data'))
    password = request.json.get('password')
    if not encrypted_data or not password:
        return jsonify({'error': 'Encrypted data and password are required'}), 400
    try:
        decrypted_data = decrypt(encrypted_data, password)
        return jsonify({'decrypted_data': base64.b64encode(decrypted_data).decode('utf-8')})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)