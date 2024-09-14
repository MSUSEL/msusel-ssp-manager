from flask import Flask
import os
import logging

logging.basicConfig(level=logging.INFO)

def create_app():
    app = Flask(__name__)

    app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')
    app.config['CATALOG_FOLDER'] = os.getenv('CATALOG_FOLDER')
    app.config['PROFILE_FOLDER'] = os.getenv('PROFILE_FOLDER')
    app.config['SSP_FOLDER'] = os.getenv('SSP_FOLDER')
    app.config['GENERATION_FOLDER'] = os.getenv('GENERATION_FOLDER')
    app.config['COMPONENT_FOLDER'] = os.getenv('COMPONENT_FOLDER')
    app.config['AP_FOLDER'] = os.getenv('AP_FOLDER')
    app.config['HOST_VOLUME_PATH'] = os.getenv('HOST_VOLUME_PATH')
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.config['HOST_UID'] = os.getenv('HOST_UID')
    app.config['HOST_GID'] = os.getenv('HOST_GID')

    if not os.getenv('SECRET_KEY'):
        raise ValueError("No SECRET_KEY set for Flask application")
    app.secret_key = os.getenv('SECRET_KEY')

    from .home import home_blueprint
    app.register_blueprint(home_blueprint, url_prefix='/api/home/')

    from .generateSSP import generate_blueprint
    app.register_blueprint(generate_blueprint, url_prefix='/api/generate')

    from .upload import upload_blueprint
    app.register_blueprint(upload_blueprint, url_prefix='/api/upload')

    from .validate import validate_blueprint
    app.register_blueprint(validate_blueprint, url_prefix='/api/validate')

    from .test_dependencies import dependencies_blueprint
    app.register_blueprint(dependencies_blueprint, url_prefix='/api/test')

    from .getGraph import getGraph_blueprint
    app.register_blueprint(getGraph_blueprint, url_prefix='/api/getGraph')

    return app