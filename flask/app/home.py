from flask import Blueprint
from flask import jsonify

home_blueprint = Blueprint('home', __name__)

@home_blueprint.route('data')
def home():
    try:
        return jsonify({'message': 'Hello, World!'})
    except Exception as e:
        # Log the error
        print(f"Error: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500