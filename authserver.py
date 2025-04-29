import socket, ssl, sqlite3, hashlib, threading, os

def register_user(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        # Create table if not exists
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
        ''')

        cursor.execute('SELECT username FROM users WHERE username=?', (username,))
        if cursor.fetchone():
            return "Error: Username already exists."
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        return "Success: User registered!"
    except sqlite3.OperationalError as e:
        return f"Error: {str(e)}"
    finally:
        conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT password FROM users WHERE username=?', (username,))
        result = cursor.fetchone()
        if result and hashlib.sha256(password.encode()).hexdigest() == result[0]:
            return "Success: User authenticated!"
        return "Error: Invalid credentials."
    except Exception as e:
        return f"Error: Database error: {str(e)}"
    finally:
        conn.close()

HOST = 'localhost'
PORT = 12345
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"
BUFFER_SIZE = 1024
FILE_STORAGE_DIR = "server_files"
os.makedirs(FILE_STORAGE_DIR, exist_ok=True)

# Thread-safe client dictionary
clients_lock = threading.Lock()
clients = {}

def handle_client(conn, addr):
    print(f"Client from {addr}")
    username = None
    try:
        conn.sendall("AUTH_REQUIRED".encode('utf-8'))
        auth_data = conn.recv(BUFFER_SIZE).decode('utf-8')

        if auth_data.startswith("LOGIN:"):
            try:
                _, username, password = auth_data.split(":", 2)
                response = authenticate_user(username, password)
            except ValueError:
                response = "Error: Invalid login format"
        elif auth_data.startswith("REGISTER:"):
            try:
                _, username, password = auth_data.split(":", 2)
                response = register_user(username, password)
            except ValueError:
                response = "Error: Invalid registration format"
        else:
            response = "Error: Invalid auth request"

        conn.sendall(response.encode('utf-8'))

        if "Success" in response:
            with clients_lock:
                # If same user was already logged in elsewhere, remove old connection
                if username in clients:
                    try:
                        old_conn = clients[username]
                        old_conn.sendall("ERROR:Logged in elsewhere".encode('utf-8'))
                        # Let the old connection thread clean itself up
                    except:
                        pass

                # Register the new connection
                clients[username] = conn

            conn.sendall("AUTH_SUCCESS".encode('utf-8'))
        else:
            conn.sendall("AUTH_FAILED".encode('utf-8'))
            return

        # Set a timeout for the socket operations
        conn.settimeout(60)  # 60 seconds timeout

        while True:
            try:
                data = conn.recv(BUFFER_SIZE).decode('utf-8')
                if not data:
                    print(f"Client {username} disconnected.")
                    break

                data = data.strip()
                if data == "PING":
                    conn.sendall("PONG".encode('utf-8'))
                    continue

                if data.startswith("CHAT:"):
                    try:
                        _, recipient, message = data.split(":", 2)
                        send_message(username, recipient, message, conn)
                    except ValueError:
                        conn.sendall("ERROR:Invalid chat format".encode('utf-8'))

                elif data.startswith("FILE_REQUEST:"):
                    try:
                        _, recipient, filename, filesize = data.split(":", 3)
                        handle_file_request(username, recipient, filename, int(filesize))
                    except (ValueError, TypeError):
                        conn.sendall("ERROR:Invalid file request format".encode('utf-8'))

                else:
                    conn.sendall("ERROR:Unknown command".encode("utf-8"))

            except socket.timeout:
                # Just to keep the connection alive, do nothing on timeout
                continue
            except ConnectionResetError:
                print(f"Connection reset by {username}")
                break
            except Exception as e:
                print(f"Error in communication with {username}: {e}")
                break

    except Exception as e:
        print(f"Client setup error: {e}")

    finally:
        if username:
            remove_client(username)
        try:
            conn.close()
        except:
            pass

def send_message(sender, recipient, message, sender_socket):
    """Send a message from sender to recipient"""
    if sender == recipient:
        # Don't allow messaging yourself
        sender_socket.sendall("ERROR:Cannot send message to yourself".encode('utf-8'))
        return

    with clients_lock:
        if recipient in clients:
            try:
                # Send to recipient
                recipient_socket = clients[recipient]
                recipient_socket.sendall(f"CHAT:{sender}:{message}".encode('utf-8'))

                # Confirm to sender
                sender_socket.sendall("CHAT_SENT".encode('utf-8'))
            except Exception as e:
                print(f"Failed to send message: {e}")
                sender_socket.sendall("ERROR:Failed to send message".encode('utf-8'))
                # Remove recipient if their connection is broken
                if recipient in clients:
                    remove_client(recipient)
        else:
            sender_socket.sendall("ERROR:Recipient not online".encode('utf-8'))

def handle_file_request(sender, recipient, filename, filesize):
    with clients_lock:
        if recipient in clients:
            try:
                clients[recipient].sendall(f"FILE_REQUEST:{sender}:{filename}:{filesize}".encode('utf-8'))
            except Exception as e:
                print(f"File send error: {e}")
                # Remove recipient if their connection is broken
                if recipient in clients:
                    remove_client(recipient)

def remove_client(username):
    with clients_lock:
        if username in clients:
            del clients[username]
            print(f"{username} disconnected.")

def main():
    # Initialize the database if it doesn't exist
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
    ''')
    conn.commit()
    conn.close()

    # Set up SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    # Check if certificate files exist
    if not os.path.isfile(CERT_FILE) or not os.path.isfile(KEY_FILE):
        print("Certificate files missing. Generating self-signed certificate...")
        os.system(f"openssl req -x509 -newkey rsa:4096 -keyout {KEY_FILE} -out {CERT_FILE} -days 365 -nodes -subj '/CN=localhost'")

    try:
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    except Exception as e:
        print(f"Error loading certificates: {e}")
        print("Please make sure valid certificate files exist.")
        return

    # Start server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Allow address reuse to avoid "Address already in use" errors on restart
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            s.bind((HOST, PORT))
            s.listen(5)
            with context.wrap_socket(s, server_side=True) as ssock:
                print(f"Server running at {HOST}:{PORT}")
                while True:
                    try:
                        conn, addr = ssock.accept()
                        threading.Thread(target=handle_client, args=(conn, addr)).start()
                    except Exception as e:
                        print(f"Error accepting connection: {e}")
        except Exception as e:
            print(f"Server startup error: {e}")

if __name__ == "__main__":
    main()