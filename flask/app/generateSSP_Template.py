from flask import Blueprint
from flask import jsonify

ssp_generation_blueprint = Blueprint('generate', __name__)

@ssp_generation_blueprint.route('ssp')
def ssp_generation():
     # Your logic to generate SSP
    data = {"message": "SSP generated successfully"}
    return jsonify(data)