#FROM ubuntu:22.04
FROM python:3.10

ARG HOST_VOLUME_PATH
ARG HOST_UID
ARG HOST_GID

# Used to later give ownership of everything to the appuser
WORKDIR /workdir

# Create a non-root user
RUN useradd -ms /bin/bash appuser
# Create a non-root user with the same UID and GID as the host user
#RUN groupadd -g $HOST_GID appgroup && \
    #useradd -u $HOST_UID -g $HOST_GID -ms /bin/bash appuser

# Check if group already exists; if not, create it
#RUN if ! getent group ${HOST_GID} ; then groupadd -g ${HOST_GID} appgroup ; fi && \
    #if ! getent passwd ${HOST_UID} ; then useradd -u ${HOST_UID} -g ${HOST_GID} -ms /bin/bash appuser ; fi



# Add appuser to the docker group
#RUN usermod -aG docker appuser

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
# Removed the dot. Ex: ./shared
ENV UPLOAD_FOLDER=/shared
ENV CATALOG_FOLDER=/processing/catalog
ENV PROFILE_FOLDER=/processing/profile
ENV SSP_FOLDER=/temp_ssp
ENV GENERATION_FOLDER=/generatedFiles
ENV COMPONENT_FOLDER=/processing/component
ENV AP_FOLDER=/processing/ap
ENV HOST_VOLUME_PATH=$HOST_VOLUME_PATH


# Add this near the end of your Dockerfile
RUN chmod -R 777 /workdir

# Run this as the entrypoint or at the start of your script to ensure permissions are correct
#ENTRYPOINT ["sh", "-c", "chown -R appuser:appuser /workdir && exec python run.py"]
ENTRYPOINT ["sh", "-c", "exec python run.py"]


#CMD python app.py
#CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]