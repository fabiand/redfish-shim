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
from abc import ABC, abstractmethod


class PowerController(ABC):
    """Abstract base class for power control implementations"""
    
    @abstractmethod
    def power_on(self) -> dict:
        """Power on the system. Returns status dict."""
        pass
    
    @abstractmethod
    def power_off(self, graceful: bool = False) -> dict:
        """Power off the system. Returns status dict."""
        pass
    
    @abstractmethod
    def reboot(self, graceful: bool = False) -> dict:
        """Reboot the system. Returns status dict."""
        pass
    
    @abstractmethod
    def get_power_state(self) -> str:
        """Get current power state ('On', 'Off', etc.)"""
        pass
    
    @abstractmethod
    def get_system_status(self) -> dict:
        """Get system status dict with State and Health"""
        pass


class MockPowerController(PowerController):
    """Mock implementation for testing"""
    
    def __init__(self):
        self._power_state = 'On'
    
    def power_on(self) -> dict:
        print("Mock: Powering on system")
        self._power_state = 'On'
        return {"success": True, "message": "System powered on"}
    
    def power_off(self, graceful: bool = False) -> dict:
        method = "gracefully" if graceful else "forcefully"
        print(f"Mock: Powering off system {method}")
        self._power_state = 'Off'
        return {"success": True, "message": f"System powered off {method}"}
    
    def reboot(self, graceful: bool = False) -> dict:
        method = "gracefully" if graceful else "forcefully"
        print(f"Mock: Rebooting system {method}")
        self._power_state = 'On'  # After reboot, system is on
        return {"success": True, "message": f"System rebooted {method}"}
    
    def get_power_state(self) -> str:
        return self._power_state
    
    def get_system_status(self) -> dict:
        return {
            'State': 'Enabled' if self._power_state == 'On' else 'Disabled',
            'Health': 'OK'
        }


class RedfishServer:
    """Main Redfish server implementation"""
    
    def __init__(self, power_controller: PowerController):
        self.power_controller = power_controller
    
    def get_service_root(self) -> dict:
        return {
            '@odata.type': '#ServiceRoot.v1_0_0.ServiceRoot',
            'Id': 'RootService',
            'Name': 'Root Service',
            'RedfishVersion': '1.0.0',
            'Systems': {'@odata.id': '/redfish/v1/Systems'}
        }
    
    def get_systems_collection(self) -> dict:
        return {
            '@odata.type': '#ComputerSystemCollection.ComputerSystemCollection',
            'Name': 'Computer System Collection',
            'Members': [{'@odata.id': '/redfish/v1/Systems/1'}],
            'Members@odata.count': 1
        }
    
    def get_system(self) -> dict:
        return {
            '@odata.type': '#ComputerSystem.v1_0_0.ComputerSystem',
            'Id': '1',
            'Name': 'System',
            'SystemType': 'Physical',
            'PowerState': self.power_controller.get_power_state(),
            'Status': self.power_controller.get_system_status(),
            'Actions': {
                '#ComputerSystem.Reset': {
                    'target': '/redfish/v1/Systems/1/Actions/ComputerSystem.Reset',
                    'ResetType@Redfish.AllowableValues': [
                        'On', 'ForceOff', 'GracefulShutdown', 
                        'ForceRestart', 'GracefulRestart', 'PowerCycle'
                    ]
                }
            }
        }
    
    def handle_reset_action(self, reset_type: str) -> dict:
        """Handle system reset/power actions"""
        try:
            if reset_type == 'On':
                result = self.power_controller.power_on()
            elif reset_type == 'ForceOff':
                result = self.power_controller.power_off(graceful=False)
            elif reset_type == 'GracefulShutdown':
                result = self.power_controller.power_off(graceful=True)
            elif reset_type in ['ForceRestart', 'PowerCycle']:
                result = self.power_controller.reboot(graceful=False)
            elif reset_type == 'GracefulRestart':
                result = self.power_controller.reboot(graceful=True)
            else:
                return {
                    '@odata.type': '#Message.v1_0_0.Message',
                    'MessageId': 'Base.1.0.ActionParameterNotSupported',
                    'Message': f'Reset type {reset_type} is not supported',
                    'Severity': 'Warning'
                }
            
            if result.get('success', False):
                return {
                    '@odata.type': '#Message.v1_0_0.Message',
                    'MessageId': 'Base.1.0.Success',
                    'Message': f'{result["message"]}. Current state: {self.power_controller.get_power_state()}',
                    'Severity': 'OK'
                }
            else:
                return {
                    '@odata.type': '#Message.v1_0_0.Message',
                    'MessageId': 'Base.1.0.GeneralError',
                    'Message': result.get('message', 'Operation failed'),
                    'Severity': 'Critical'
                }
                
        except Exception as e:
            return {
                '@odata.type': '#Message.v1_0_0.Message',
                'MessageId': 'Base.1.0.InternalError',
                'Message': f'Internal error: {str(e)}',
                'Severity': 'Critical'
            }


class RedfishHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Redfish API"""
    
    def __init__(self, redfish_server: RedfishServer, *args, **kwargs):
        self.redfish_server = redfish_server
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        routes = {
            '/redfish/v1': self.redfish_server.get_service_root(),
            '/redfish/v1/Systems': self.redfish_server.get_systems_collection(),
            '/redfish/v1/Systems/1': self.redfish_server.get_system()
        }
        
        response = routes.get(self.path, {'error': 'Not found'})
        status_code = 200 if self.path in routes else 404
        
        self.send_response(status_code)
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
                
                response = self.redfish_server.handle_reset_action(reset_type)
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response, indent=2).encode())
                
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


class CertificateManager:
    """Handles SSL certificate management"""
    
    @staticmethod
    def get_certificate():
        cert_file = 'server.crt'
        key_file = 'server.key'
        
        if os.path.exists(cert_file) and os.path.exists(key_file):
            print(f"Using existing certificate: {cert_file}")
            return cert_file, key_file, False
        else:
            print("Certificate files not found, generating self-signed certificate...")
            return CertificateManager._generate_self_signed_cert()
    
    @staticmethod
    def _generate_self_signed_cert():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
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
        
        return cert_file.name, key_file.name, True


def create_handler_with_server(redfish_server):
    """Factory function to create handler with redfish server dependency"""
    def handler(*args, **kwargs):
        return RedfishHandler(redfish_server, *args, **kwargs)
    return handler


def main():
    # Create power controller (easily replaceable)
    power_controller = MockPowerController()
    
    # Create Redfish server
    redfish_server = RedfishServer(power_controller)
    
    # Get certificate
    cert_file, key_file, should_delete = CertificateManager.get_certificate()
    
    try:
        # Create HTTP server with custom handler
        handler_class = create_handler_with_server(redfish_server)
        server = HTTPServer(('localhost', 8443), handler_class)
        
        # Configure SSL
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        
        print("Mock Redfish server running on https://localhost:8443")
        print("Use curl -k https://localhost:8443/redfish/v1/ to test")
        print("\nTo implement custom power control, extend PowerController class")
        server.serve_forever()
        
    finally:
        if should_delete:
            os.unlink(cert_file)
            os.unlink(key_file)


if __name__ == '__main__':
    main()
