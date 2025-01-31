import json
from flask import Flask, jsonify, send_from_directory

def create_app():
    app = Flask(__name__)
    
    @app.route('/api/control-mappings')
    def get_control_mappings():
        try:
            with open('AttackTechniquesToControls/nist800-53-r5-mappings2.json', 'r') as f:
                mappings = json.load(f)
            return jsonify(mappings)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return app
