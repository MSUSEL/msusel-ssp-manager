from flask import Blueprint
from flask import jsonify

ssp_generation_blueprint = Blueprint('generate', __name__)

@ssp_generation_blueprint.route('ssp')
def ssp_generation():
     # Your logic to generate SSP
    try:
        return jsonify({'message': 'SSP generated successfully'})
    except Exception as e:
        # Log the error
        print(f"Error: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500