from flask import Flask
import os
import logging

logging.basicConfig(level=logging.INFO)

def create_app():
    app = Flask(__name__)

    app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')
    app.config['GENERATION_FOLDER'] = os.getenv('GENERATION_FOLDER')
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

    from .priority_controls import priority_blueprint
    app.register_blueprint(priority_blueprint, url_prefix='/api/priority')

    from .tacticsAndTecniquesGraph import tactics_blueprint
    app.register_blueprint(tactics_blueprint, url_prefix='/api/tactics')

    from .vulnerableFunctions import vulnerable_blueprint
    app.register_blueprint(vulnerable_blueprint, url_prefix='/api/vulnerable')

    from .attack_paths import attack_blueprint
    app.register_blueprint(attack_blueprint, url_prefix='/api/attack')

    # Register test runner blueprint
    from .test_runner import test_runner_bp
    app.register_blueprint(test_runner_bp)

    # Register InSpec runner blueprint
    from .inspec_runner import inspec_runner_bp
    app.register_blueprint(inspec_runner_bp)

    return app