from flask import Flask, request, render_template
import socket
import ssl
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# List of insecure cipher suites
INSECURE_CIPHER_SUITES = [
    'TLS_RSA_WITH_RC4_128_MD5',
    'TLS_RSA_WITH_RC4_128_SHA',
    'TLS_RSA_WITH_DES_CBC_SHA',
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    'TLS_RSA_WITH_NULL_MD5',
    'TLS_RSA_WITH_NULL_SHA',
    'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
    'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
    'TLS_DHE_RSA_WITH_DES_CBC_SHA'
]

def get_certificate(hostname, port):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.settimeout(3.0)
    conn.connect((hostname, port))
    cert = conn.getpeercert(True)
    conn.close()
    return ssl.DER_cert_to_PEM_cert(cert)

def check_expiry(cert_pem):
    cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
    expiry_date = cert.not_valid_after
    if expiry_date < datetime.utcnow():
        return f"[ERROR] Certificate expired on {expiry_date}"
    else:
        return f"[OK] Certificate is valid until {expiry_date}"

def check_certificate_chain(cert_pem):
    cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
    try:
        cert_chain = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        return f"[OK] Certificate chain is present: {cert_chain}"
    except x509.ExtensionNotFound:
        return "[ERROR] Certificate chain is missing"

def check_protocol_support(hostname, port):
    results = []
    protocols = [ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1, ssl.PROTOCOL_TLSv1_2]

    # Conditionally add TLS 1.3 if available
    if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
        protocols.append(ssl.PROTOCOL_TLSv1_3)

    for protocol in protocols:
        try:
            context = ssl.SSLContext(protocol)
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
            conn.settimeout(3.0)
            conn.connect((hostname, port))
            results.append(f"[OK] Supported protocol: {ssl._PROTOCOL_NAMES[protocol]}")
            conn.close()
        except ssl.SSLError:
            results.append(f"[WARNING] Unsupported protocol: {ssl._PROTOCOL_NAMES[protocol]}")
        except Exception as e:
            results.append(f"[ERROR] {e}")
    return results

def check_cipher_suites(hostname, port):
    results = []
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.settimeout(3.0)
    conn.connect((hostname, port))

    # Get the list of cipher suites used by the server
    ciphers = conn.cipher()
    if ciphers:
        cipher_name = ciphers[0]
        if cipher_name in INSECURE_CIPHER_SUITES:
            results.append(f"[ERROR] Insecure cipher suite in use: {cipher_name}")
        else:
            results.append(f"[OK] Secure cipher suite in use: {cipher_name}")
    else:
        results.append("[ERROR] No cipher suite found")

    conn.close()
    return results

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        hostname = request.form['hostname']
        port = int(request.form['port'])
        results = []

        cert_pem = get_certificate(hostname, port)
        results.append(check_expiry(cert_pem))
        results.append(check_certificate_chain(cert_pem))
        results.extend(check_protocol_support(hostname, port))
        results.extend(check_cipher_suites(hostname, port))

        return render_template('results.html', results=results)

    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True)