FROM ubuntu:22.04
FROM python:3.10

ARG HOST_VOLUME_PATH

# Anadido
#WORKDIR /app

COPY . .

RUN pip install -r requirements.txt

EXPOSE 5000

# Set environment variables
ENV FLASK_APP=run:create_app
ENV FLASK_ENV=development
ENV SECRET_KEY=your-secret-key
ENV UPLOAD_FOLDER=./shared
ENV CATALOG_FOLDER=./shared/catalog
ENV PROFILE_FOLDER=./shared/profile
ENV SSP_FOLDER=./shared/ssp
ENV GENERATION_FOLDER=./generatedFiles
ENV COMPONENT_FOLDER=./shared/component
ENV AP_FOLDER=./shared/ap
ENV HOST_VOLUME_PATH=$HOST_VOLUME_PATH

#CMD python app.py
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]