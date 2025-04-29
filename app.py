from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import socket, ssl, os, threading, time

app = Flask(__name__)
app.secret_key = 'super_secret_chat_key_12345'

SERVER_HOST = 'localhost'
SERVER_PORT = 12345
BUFFER_SIZE = 1024
FILE_UPLOAD_DIR = "client_uploads"
os.makedirs(FILE_UPLOAD_DIR, exist_ok=True)

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

client_socket = None
messages = []
connection_alive = False
socket_lock = threading.Lock()  # Add lock for thread safety

def connect_to_server():
    global client_socket, connection_alive
    try:
        with socket_lock:
            client_socket = socket.create_connection((SERVER_HOST, SERVER_PORT))
            client_socket = context.wrap_socket(client_socket, server_hostname=SERVER_HOST)
            auth_request = client_socket.recv(BUFFER_SIZE).decode('utf-8')
            if auth_request != "AUTH_REQUIRED":
                client_socket.close()
                connection_alive = False
                return False
            connection_alive = True
            return True
    except Exception as e:
        print(f"Connection error: {e}")
        connection_alive = False
        return False

def send_to_server(data):
    global client_socket, connection_alive
    try:
        with socket_lock:
            if not connection_alive:
                if not connect_to_server():
                    return None
            client_socket.sendall(data.encode('utf-8'))
            return client_socket.recv(BUFFER_SIZE).decode('utf-8')
    except Exception as e:
        print(f"Send error: {e}")
        connection_alive = False
        return None

def receive_chat_messages():
    global client_socket, messages, connection_alive
    while True:
        if not connection_alive:
            time.sleep(5)
            continue

        try:
            with socket_lock:
                if not connection_alive:
                    continue

                # Send a keep-alive ping only every 30 seconds instead of each loop
                if int(time.time()) % 30 == 0:
                    try:
                        client_socket.sendall(b'PING')
                        # Don't wait for response here, we'll handle it below
                    except:
                        connection_alive = False
                        continue

                # Set a shorter timeout for receiving data
                client_socket.settimeout(1.0)
                data = client_socket.recv(BUFFER_SIZE).decode('utf-8')

                if not data:
                    print("No data received; connection likely closed.")
                    connection_alive = False
                    continue

                if data.startswith("CHAT:"):
                    _, sender, message = data.split(":", 2)
                    messages.append({
                        "sender": sender,
                        "message": message,
                        "timestamp": time.time(),
                        "type": "chat"
                    })

                elif data.startswith("FILE_REQUEST:"):
                    _, sender, filename, _ = data.split(":")
                    messages.append({
                        "sender": sender,
                        "message": f"sent a file: {filename}",
                        "timestamp": time.time(),
                        "type": "file"
                    })

                elif data.startswith("ERROR:"):
                    messages.append({
                        "sender": "System",
                        "message": data[6:],
                        "timestamp": time.time(),
                        "type": "system"
                    })

                elif data == "PONG":
                    # Keep-alive acknowledged - do nothing
                    pass

                # Reset timeout to normal after successful receive
                client_socket.settimeout(5.0)

        except socket.timeout:
            # Timeout is normal, just continue
            continue
        except Exception as e:
            print(f"Receiver thread error: {e}")
            connection_alive = False
            time.sleep(5)

def ensure_receiver_thread():
    if not any(t.name == "ChatReceiverThread" for t in threading.enumerate()):
        receiver_thread = threading.Thread(target=receive_chat_messages, daemon=True, name="ChatReceiverThread")
        receiver_thread.start()
        return True
    return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    global client_socket, connection_alive
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if connect_to_server():
            response = send_to_server(f"LOGIN:{username}:{password}")
            if response and "Success" in response:
                session['username'] = username
                auth_status = client_socket.recv(BUFFER_SIZE).decode('utf-8')
                if auth_status == "AUTH_SUCCESS":
                    with socket_lock:
                        client_socket.settimeout(5.0)
                    ensure_receiver_thread()
                    return redirect(url_for('chat'))
                else:
                    flash("Authentication failed.", "danger")
            else:
                flash("Login failed.", "danger")
        else:
            flash("Could not connect to server.", "danger")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if connect_to_server():
            response = send_to_server(f"REGISTER:{username}:{password}")
            if response and "Success" in response:
                flash("Registration successful!", "success")
                return redirect(url_for('login'))
            else:
                flash(response or "Registration failed.", "danger")
        else:
            flash("Could not connect to server.", "danger")
    return render_template('register.html')

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    ensure_receiver_thread()  # Make sure receiver thread is running
    return render_template('chat.html', username=session['username'])

@app.route('/send_chat', methods=['POST'])
def send_chat():
    global messages, connection_alive
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'})

    recipient = request.form['recipient']
    message = request.form['message']

    # Validate recipient
    if not recipient or not message:
        return jsonify({'status': 'error', 'message': 'Recipient and message required'})

    # Check if sending to self - block on client side
    if recipient == session['username']:
        return jsonify({'status': 'error', 'message': 'Cannot message yourself'})

    # Check connection and try to reconnect if needed
    if not connection_alive:
        if connect_to_server():
            # Re-authenticate after reconnection
            response = send_to_server(f"LOGIN:{session['username']}:{session.get('password', '')}")
            if not response or "Success" not in response:
                return jsonify({'status': 'error', 'message': 'Reconnection failed - please log in again'})
            auth_status = client_socket.recv(BUFFER_SIZE).decode('utf-8')
            if auth_status != "AUTH_SUCCESS":
                return jsonify({'status': 'error', 'message': 'Authentication failed after reconnection'})
            ensure_receiver_thread()
        else:
            return jsonify({'status': 'error', 'message': 'Server not connected'})

    # Send the message
    response = send_to_server(f"CHAT:{recipient}:{message}")
    if response and response == "CHAT_SENT":
        # Add message to local display
        messages.append({
            "sender": session['username'],
            "recipient": recipient,
            "message": message,
            "timestamp": time.time(),
            "type": "chat"
        })
        return jsonify({'status': 'sent'})
    else:
        err_msg = response if response else 'Failed to send message'
        return jsonify({'status': 'error', 'message': err_msg})

@app.route('/connection_status')
def connection_status():
    return jsonify({
        'status': 'connected' if connection_alive else 'disconnected',
        'username': session.get('username', '')
    })

@app.route('/receive_messages')
def receive_messages():
    global messages
    if 'username' not in session:
        return jsonify([])
    current_messages = messages.copy()
    messages = []
    return jsonify(current_messages)

@app.route('/logout')
def logout():
    global client_socket, connection_alive
    with socket_lock:
        if client_socket:
            try: client_socket.close()
            except: pass
        connection_alive = False
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/reconnect')
def reconnect():
    global connection_alive
    if not connection_alive and 'username' in session:
        if connect_to_server():
            # Re-authenticate after reconnection
            response = send_to_server(f"LOGIN:{session['username']}:{session.get('password', '')}")
            if response and "Success" in response:
                auth_status = client_socket.recv(BUFFER_SIZE).decode('utf-8')
                if auth_status == "AUTH_SUCCESS":
                    ensure_receiver_thread()
                    return jsonify({'status': 'success', 'message': 'Reconnected'})
    return jsonify({'status': 'attempted'})

if __name__ == '__main__':
    app.run(debug=True, port=5001)