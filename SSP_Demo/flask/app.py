import os
from flask import Flask, flash, request, redirect, url_for, render_template 
from werkzeug.utils import secure_filename
from flask import send_from_directory
import cwe_cve_to_techniques
import threading
import shutil
import logging
import docker
import re

UPLOAD_FOLDER = "./uploads"
ALLOWED_EXTENSIONS = {'json', 'txt', 'py'} # No lo usamos en validation. Do.
OSCAL_FOLDER = "/tmp"

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OSCAL_FOLDER'] = OSCAL_FOLDER

#temp
app.secret_key = 'my-secret-key'


def cli():
    client = docker.from_env() # create a client that can talk to the host's docker daemon
    oscal_file = fileName # name of oscal file to validate (taken from request)
    oscal_model = oscal_file[:-5] # take out extension to insert model as argument
    logging.error("%s oscal_model: ", oscal_model)
    oscal_client_arguments = f"{oscal_model} validate /tmp/{oscal_file}"
    logging.error("%s ", oscal_client_arguments)
    
    # The oscal-cli container (created with image validation on the host) returns a non-zero exit code
    # when the oscal document is not valid. This block catches that exception so that the program
    # may proceed
    try:
        client.containers.run("validation", oscal_client_arguments, volumes = ["/tmp:/tmp"])
    except:
        print("The oscal-cli container exited with non-zero exit code.")

    # Get the last container created by the host's daemon
    containerList = client.containers.list(limit = 1)
    strList = str(containerList)
    x = strList.split(":")
    containerId = x[1][1:11]
    #print(containerId)
    myContainer = client.containers.get(containerId)
    bytesLogOutput = myContainer.logs()
    strLogOutput = bytesLogOutput.decode()
    
    with open("/tmp/validation.txt", "w") as f:
            f.write(strLogOutput)
    f.close()
    global validation_output_list
    validation_output_list = []
    f = open('/tmp/validation.txt', 'r')
    '''
    This version got rid of the escape characters that were messing up the validation 
    output.
    These were ansi escape characters, use for example to add color to the output.
    uses regular expressions module.
    '''
    for line in f:
        reaesc = re.compile(r'\x1b[^m]*m')
        new_text = reaesc.sub('', line)
        validation_output_list.append(new_text)
    myContainer.remove()





def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        werkzeugFilestorageObject = request.files.get("oscal_document")
        logging.error("%s reques oscal doc", werkzeugFilestorageObject.filename)
        if werkzeugFilestorageObject.filename != '':
            oscal_doc = request.files["oscal_document"]
            global fileName
            fileName = oscal_doc.filename
            oscal_doc.save(os.path.join(app.config['OSCAL_FOLDER'], oscal_doc.filename))
            return redirect(url_for('validationResults'))



        ctrl_file = request.files["control_file"]
        vul_file = request.files["vul_file"]

        if ctrl_file.filename == '':
            flash('Error: Please Upload a Control File.')
            return redirect(request.referrer)
            
        elif vul_file.filename == '':
            flash('Error: Please Upload a Vulnerability File.')
            return redirect(request.referrer)
        
        ctrl_filename = 'in_' + ctrl_file.filename
        vul_filename = 'in_' + vul_file.filename
        
        ctrl_file.save(os.path.join(app.config['UPLOAD_FOLDER'], ctrl_filename))
        shutil.copyfile('./uploads/' + ctrl_filename, './uploads/controls.json')

        vul_file.save(os.path.join(app.config['UPLOAD_FOLDER'], vul_filename))
        shutil.copyfile('./uploads/' + vul_filename, './uploads/vulnerabilities.json')
            
        file = open('./uploads/input.txt', 'w')
        file.write('TA00' + request.form.get("tactic_id"))
        file.close()
        return redirect(url_for('result'))
    return render_template('index.html')



@app.route('/templates/table')
def table():
    return render_template('table.html')

@app.route('/templates/network_flow')
def network_flow():
    return render_template('network_flow.html')

@app.route('/templates/result', methods=['GET', 'POST'])
def result():
    x = threading.Thread(target=cwe_cve_to_techniques.main)
    x.start()
    x.join()
    f = open("demofile2.txt", "a")
    f.write("Now the file has more content!")
    f.close()
    return render_template('result.html')



@app.route('/validationResults', methods=['GET', 'POST'])
def validationResults():
    x = threading.Thread(target=cli())
    x.start()
    x.join()
    context = {
        "validation_output_list": validation_output_list,
        "fileName": fileName,
    }
    return render_template('validationResults.html', **context)


@app.route('/templates/graph')
def graph():
    return render_template('graph.html')


@app.route('/uploads/<name>')
def download_file(name):
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
