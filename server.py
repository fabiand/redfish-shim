#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import ssl
import tempfile
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

class RedfishHandler(BaseHTTPRequestHandler):
    # Server state
    power_state = 'On'  # Default power state
    
    def do_GET(self):
        routes = {
            '/redfish/v1/': {
                '@odata.type': '#ServiceRoot.v1_0_0.ServiceRoot',
                'Id': 'RootService',
                'Name': 'Root Service',
                'RedfishVersion': '1.0.0',
                'Systems': {'@odata.id': '/redfish/v1/Systems'}
            },
            '/redfish/v1/Systems': {
                '@odata.type': '#ComputerSystemCollection.ComputerSystemCollection',
                'Name': 'Computer System Collection',
                'Members': [{'@odata.id': '/redfish/v1/Systems/1'}],
                'Members@odata.count': 1
            },
            '/redfish/v1/Systems/1': {
                '@odata.type': '#ComputerSystem.v1_0_0.ComputerSystem',
                'Id': '1',
                'Name': 'System',
                'SystemType': 'Physical',
                'PowerState': RedfishHandler.power_state,
                'Status': {'State': 'Enabled' if RedfishHandler.power_state == 'On' else 'Disabled', 
                          'Health': 'OK'},
                'Actions': {
                    '#ComputerSystem.Reset': {
                        'target': '/redfish/v1/Systems/1/Actions/ComputerSystem.Reset',
                        'ResetType@Redfish.AllowableValues': ['On', 'ForceOff', 'GracefulShutdown', 'ForceRestart', 'GracefulRestart', 'PowerCycle']
                    }
                }
            }
        }
        routes['/redfish/v1'] = routes['/redfish/v1/']
        
        response = routes.get(self.path, {'error': 'Not found'})
        
        self.send_response(200 if self.path in routes else 404)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response, indent=2).encode())

    def do_POST(self):
        if self.path == '/redfish/v1/Systems/1/Actions/ComputerSystem.Reset':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                reset_type = data.get('ResetType', 'ForceRestart')
                
                # Update power state based on reset type
                if reset_type in ['On']:
                    RedfishHandler.power_state = 'On'
                elif reset_type in ['ForceOff', 'GracefulShutdown']:
                    RedfishHandler.power_state = 'Off'
                elif reset_type in ['ForceRestart', 'GracefulRestart', 'PowerCycle']:
                    # For restart operations, system goes through Off->On cycle
                    RedfishHandler.power_state = 'On'
                
                # Mock response
                response = {
                    '@odata.type': '#Message.v1_0_0.Message',
                    'MessageId': 'Base.1.0.Success',
                    'Message': f'System reset ({reset_type}) initiated successfully. Power state: {RedfishHandler.power_state}',
                    'Severity': 'OK'
                }
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response, indent=2).encode())
                
                print(f"Power operation: {reset_type} -> Power state: {RedfishHandler.power_state}")
                
            except json.JSONDecodeError:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                error = {'error': 'Invalid JSON'}
                self.wfile.write(json.dumps(error).encode())
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            error = {'error': 'Endpoint not found'}
            self.wfile.write(json.dumps(error).encode())

def get_certificate():
    cert_file = 'server.crt'
    key_file = 'server.key'
    
    # Check if certificate files exist
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print(f"Using existing certificate: {cert_file}")
        return cert_file, key_file, False  # False = don't delete
    else:
        print("Certificate files not found, generating self-signed certificate...")
        return generate_self_signed_cert()

def generate_self_signed_cert():
    # Generate private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # Create certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=30)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())
    
    # Write to temporary files
    cert_file = tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem')
    key_file = tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key')
    
    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
    
    cert_file.close()
    key_file.close()
    
    return cert_file.name, key_file.name, True  # True = delete when done

if __name__ == '__main__':
    # Get certificate (either existing files or generate new ones)
    cert_file, key_file, should_delete = get_certificate()
    
    try:
        server = HTTPServer(('localhost', 8443), RedfishHandler)
        
        # Configure SSL
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        
        print("Mock Redfish server running on https://localhost:8443")
        print("Use curl -k https://localhost:8443/redfish/v1/ to test")
        server.serve_forever()
    finally:
        # Clean up temp files only if they were generated
        if should_delete:
            os.unlink(cert_file)
            os.unlink(key_file)
