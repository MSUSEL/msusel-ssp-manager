FROM ubuntu:22.04
FROM python:3.10

ARG HOST_VOLUME_PATH

COPY . .

RUN pip install -r requirements.txt

EXPOSE 5000

ENV FLASK_APP=app.py
ENV SECRET_KEY=your-secret-key
ENV UPLOAD_FOLDER=./shared
ENV OSCAL_FOLDER=/shared
ENV HOST_VOLUME_PATH=$HOST_VOLUME_PATH

CMD python app.py