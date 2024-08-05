from flask import Blueprint
from flask import jsonify

home_blueprint = Blueprint('home', __name__)

@home_blueprint.route('data')
def home():
    return jsonify({"message": "Hello from flask"})