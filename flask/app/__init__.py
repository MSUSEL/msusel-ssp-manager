from flask import Flask
import os

def create_app():
    app = Flask(__name__)

    app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')
    app.config['OSCAL_FOLDER'] = os.getenv('OSCAL_FOLDER')
    app.config['HOST_VOLUME_PATH'] = os.getenv('HOST_VOLUME_PATH')
    app.config['TEMPLATES_AUTO_RELOAD'] = True

    if not os.getenv('SECRET_KEY'):
        raise ValueError("No SECRET_KEY set for Flask application")
    app.secret_key = os.getenv('SECRET_KEY')

    from .home import home_blueprint
    app.register_blueprint(home_blueprint, url_prefix='/api/home/')

    from .generateSSP_Template import ssp_generation_blueprint
    app.register_blueprint(ssp_generation_blueprint, url_prefix='/api/generate')


    return app