#FROM ubuntu:22.04
FROM python:3.10

ARG HOST_VOLUME_PATH
ARG HOST_UID
ARG HOST_GID
#ARG ARANGO_DB_URL
#ARG ARANGO_DB_NAME
#ARG ARANGO_DB_USERNAME
#ARG ARANGO_DB_PASSWORD

# Used to later give ownership of everything to the appuser
WORKDIR /workdir

# Create a non-root user
RUN useradd -ms /bin/bash appuser

# Add appuser to the group with GID 1001 (host docker group)
RUN groupadd -g 1001 dockergroup && usermod -aG dockergroup appuser

COPY . .

RUN pip install -r requirements.txt

# Change ownership of the application files to the non-root user
RUN chown -R appuser:appuser /workdir

# Switch to the non-root user
USER appuser

EXPOSE 5000

# Set environment variables
ENV FLASK_APP=run:create_app
ENV FLASK_ENV=development
ENV SECRET_KEY=your-secret-key
ENV ARANGO_DB_URL=ARANGO_DB_URL
ENV ARANGO_DB_NAME=ARANGO_DB_NAME
ENV ARANGO_DB_USERNAME=ARANGO_DB_USERNAME
ENV ARANGO_DB_PASSWORD=-ARANGO_DB_PASSWORD
# Removed the dot. Ex: ./shared
ENV UPLOAD_FOLDER=/shared
ENV GENERATION_FOLDER=/generatedFiles
ENV HOST_VOLUME_PATH=$HOST_VOLUME_PATH


# Add this near the end of your Dockerfile
RUN chmod -R 777 /workdir

ENTRYPOINT ["sh", "-c", "exec python run.py"]

#CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]