
import sys
import os
import pandas as pd
import numpy as np
import pickle
import joblib
from libs.NetIDS import NetIDS
from libs.NetIDSFeatureNBased import NetIDSFeatureNBased


path = sys.path
parent = os.path.dirname(__file__)
loc = parent + '/libs'
try:
    path.index(loc)
except(ValueError):
    sys.path.append(loc)

from flask import Flask, render_template, request, jsonify, session, redirect, Response, send_from_directory,url_for
import os, time, threading


app = Flask(__name__)
app.secret_key = b'k843h/jd6uJU73R6778r6ibYGU'

import logging
logging.basicConfig(filename='app_error.log', level=logging.DEBUG)

@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"Unhandled Exception: {e}", exc_info=True)
    return f"Error: {e}", 500


# Load trained model
MODEL_PATH = "models/netids_model.pkl"
DATASET_PATH = ""
UPLOADED_DATASET = 'upload'
MODEL_IS_TRAINED = False
netids_model = NetIDSFeatureNBased(preprocessed_dataset_location=DATASET_PATH) 
    

@app.route('/')
def index():
    print("Debug: Index route accessed", flush=True)
    try:
        # return "Hello World - Minimal Debug"
        return render_template("index.html")
    except Exception as e:
        import traceback
        trace = traceback.format_exc()
        print(f"Index Error: {e}\n{trace}", flush=True)
        return f"<pre>Index Error: {e}\n\nTraceback:\n{trace}</pre>", 200

@app.route("/dashboard")
def dashboard():
    global netids_model
    if 'details' not in session:
        return redirect(url_for('login'))
    user_details = session.get('details')
    df = netids_model.load_datasets()
    
    print('df:', df)
    
    # Defaults in case of missing data
    total_logs = len(df) if df is not None and not df.empty else 0
    attack_count = 0
    normal_count = 0
    decoded_attack_types = {}
    top_src_ips = {}
    top_dst_ports = {}
    traffic_by_protocol = {}

    if df is not None and not df.empty:
        if 'Attack_type' in df.columns:
            attack_count = df[df['Attack_type'] != 1].shape[0]
            normal_count = df[df['Attack_type'] == 1].shape[0]

            attack_types = df['Attack_type'].value_counts().to_dict()  
            encoded_labels = list(attack_types.keys())
            try:
                attack_type_encoder = joblib.load("models/attack_type_encoder.pkl")
                decoded_labels = attack_type_encoder.inverse_transform(encoded_labels)
                decoded_attack_types = dict(zip(decoded_labels, attack_types.values()))
                traffic_by_protocol = dict(zip(decoded_labels, attack_types.values()))
            except Exception as e:
                print(f"Error loading encoder: {e}")
                decoded_attack_types = attack_types
                traffic_by_protocol = attack_types

        if 'ip.src_host' in df.columns:
            top_src_ips = df['ip.src_host'].value_counts().head(5).to_dict()
        
        if 'dst_port' in df.columns:
            top_dst_ports = df['dst_port'].value_counts().head(5).to_dict()
        elif 'dstport' in df.columns:
            top_dst_ports = df['dstport'].value_counts().head(5).to_dict()

    return render_template(
        "dashboard.html",
        total_logs = total_logs,
        attack_count = attack_count,
        normal_count = normal_count,
        attack_types = decoded_attack_types,
        top_src_ips = top_src_ips,
        top_dst_ports = top_dst_ports,
        traffic_by_protocol = traffic_by_protocol, 
        user = user_details
    )

@app.route('/reset')
def reset():
    global UPLOADED_DATASET
    if 'details' not in session:
        return redirect(url_for('login'))
    UPLOADED_DATASET = False
    return redirect(url_for('input'))


@app.route('/profile')
def profile():
    if 'details' not in session:
        return redirect(url_for('login'))
    
    user_details = session.get('details')
    print('user_details:', user_details)
    return render_template("profile.html", name=user_details['name'], user=user_details)

@app.route("/monitor")
def monitor():
    if 'details' not in session:
        return redirect(url_for('login'))
    
    return render_template("monitor.html", csv_uploaded=UPLOADED_DATASET)

@app.route("/monitor/data")
def monitor_data():
    global netids_model, MODEL_IS_TRAINED
        
    if not MODEL_IS_TRAINED:        
        df = netids_model.load_datasets()
        
        feature_cols = [col for col in df.columns if col not in ["Attack_label", "Attack_type"]]
        label_col = "Attack_label"
        type_col = "Attack_type"

        # Train
        log_step("[INFO] Starting training...")
        MODEL_IS_TRAINED = netids_model.train(df, feature_cols, label_col, type_col)
    
    # Load processed dataset
    df = pd.read_csv("datasets/processed.csv")
    random_row = df.sample(1).drop(columns=["Attack_type", "Attack_label"])  # Drop label and type for prediction
    feature_columns = random_row.columns
    print('selected trafic data:', random_row)
    print('feature_columns:', feature_columns)
    
    decoded_label, decoded_type = netids_model.predict0(random_row, feature_columns)
    
    print('decoded_label:', decoded_label)
    print('decoded_type:', decoded_type)
    
    values = random_row.values.flatten().astype(float)
    mean_val = np.mean(values)
    # avoid division by zero
    scaled_values = values / mean_val if mean_val != 0 else values  
    data = scaled_values.tolist()
    
    ln = len(data)
    labels = list(random_row.columns)
    result = {
        "data" : data,
        "length" : ln,
        "labels" : labels, 
        "attack_label" : decoded_label,
        "attack_type" : decoded_type
    } 
    print('result:',result)
    return jsonify(result)
    
training_logs = []

def log_step(message):
    """Append log messages to the training log list."""
    training_logs.append(message)
    print(message)


# INPUT
@app.route('/input', methods=['GET', 'POST'])
def input():
    global UPLOADED_DATASET, netids_model
    UPLOADED_DATASET = False
    if 'details' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['csv_file']
        if file and file.filename.endswith('.csv'):
            filepath = os.path.join(DATASET_PATH, file.filename)
            file.save(filepath)
            session['DATASET_PATH'] = filepath
            UPLOADED_DATASET = True
            netids_model = NetIDSFeatureNBased(preprocessed_dataset_location=filepath) 
            return redirect(url_for('process'))  # fixed redirect
        else:
            return "Invalid file type. Only .csv allowed."
            
    return render_template('input.html')


# PROCESS
@app.route("/process", methods=["GET", "POST"])
def process():
    global UPLOADED_DATASET
    if 'details' not in session:
        return redirect(url_for('login'))
    
    if os.path.exists("models/netids_transfer.pkl"):
        log_step("[INFO] A trained model already exists.")

    if not training_logs or training_logs[-1] not in ("[SUCCESS] Model training completed successfully.", "[ERROR]"):
        # Start training in a background thread
        training_logs.clear()
        threading.Thread(target=train_netids_model).start()

    return render_template("pretrain_model.html", csv_uploaded=UPLOADED_DATASET)


def train_netids_model():
    global netids_model, MODEL_IS_TRAINED
    try:
        log_step("[INFO] Loading datasets...")
        
        df = netids_model.load_datasets()
        
        print('loaded df:', df.head())
        
        feature_cols = [col for col in df.columns if col not in ["Attack_label", "Attack_type"]]
        label_col = "Attack_label"
        type_col = "Attack_type"

        # Train
        log_step("[INFO] Starting training...")
        MODEL_IS_TRAINED = netids_model.train(df, feature_cols, label_col, type_col)

        # Evaluate
        log_step("[INFO] Evaluating model...") 
        class_report, accuracy_percent  = netids_model.evaluate(df, feature_cols, label_col, type_col)
        print('[DEBUG] Evaluation result: ', class_report, accuracy_percent) 
        
        log_step('[INFO] Classification report:')
        log_step(class_report)
        
        log_step('[INFO] Accuracy: ' + str(accuracy_percent))

        log_step("[INFO] Saving model to models/netids_transfer.pkl")
        netids_model.save_model("models/netids_transfer.pkl", feature_cols)

        log_step("[SUCCESS] Model training completed successfully.")
        
        return True

    except Exception as e:
        log_step(f"[ERROR] train_netids_model: {str(e)}")
        return False



@app.route("/pretrain_progress")
def pretrain_progress():
    def event_stream():
        last_index = 0
        while True:
            if last_index < len(training_logs):
                yield f"data: {training_logs[last_index]}\n\n"
                last_index += 1
            time.sleep(0.5)
    return Response(event_stream(), content_type="text/event-stream")


@app.route('/plots/<image_name>')
def plots(image_name):
    if os.path.exists(os.path.join('plots', image_name)):
        return send_from_directory('plots',  str(image_name))
    else:
        return send_from_directory('plots', 'no_image.jpg')


'''
USER ACCESS
'''

@app.route('/login')
def login():
    return render_template("login.html")

@app.route('/register')
def register():
    return render_template("register.html")

@app.route('/forgot_login')
def forgot_login():
    return render_template("forgot_login.html")

@app.route('/do_reset_password', methods=['POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form.get('username')
        new_password = request.form.get('new_password')
        re_new_password = request.form.get('re_new_password')

        if not username:
            return render_template("forgot_login.html", message='Invalid user')
        if not new_password:
            return render_template("forgot_login.html", message='Please enter new password')
        if not re_new_password:
            return render_template("forgot_login.html", message='Enter same new password again')
        if new_password != re_new_password:
            return render_template("forgot_login.html", message='Both passwords do not match')

        from libs.User import User as db
        details = db().reset_password(username, new_password)

        if details == 'done':
            return render_template("login.html", message="Password reset successful")
        elif details == 'failed':
            return render_template("forgot_login.html", message="Unknown user")
        else:
            return render_template("forgot_login.html", message="Unknown error")

@app.route('/doregister', methods=['POST', 'GET'])
def doregister():
    if request.method == 'POST':
        name = request.form.get('name')
        phone = request.form.get('phone')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        from libs.User import User as db
        details = db().register(name, email, phone, username, password)

        if details == 'done':
            return render_template("login.html")
        elif details == 'user_exists':
            return render_template("register.html", message='User with the same email exists.')
        else:
            return render_template("register.html")
    return render_template("register.html")

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if request.method == 'POST':
        name = request.form.get('name')
        phone = request.form.get('phone')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        from libs.User import User as db
        details = db().update(name, phone, email, username, password)

        if details:
            session['details'] = details
            return render_template("profile.html", message="Profile updated successfully", name=details['name'], user=details)
        else:
            return render_template("profile.html", message='Unknown error', user=session.get('details'))
    return render_template("profile.html")

@app.route('/dologin', methods=['POST'])
def dologin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        from libs.User import User as db
        details = db().login(username, password)

        if details:
            session['details'] = details
            return redirect("/dashboard")
        else:
            return render_template("login.html", message='User does not exist or check your details')
    return render_template("login.html")

@app.route('/logout')
def logout():
    session['details'] = None
    return render_template("login.html")

if __name__ == '__main__':
    print("Starting Flask server on http://0.0.0.0:5000...")
    app.run(host='0.0.0.0', port=5000, debug=False)
