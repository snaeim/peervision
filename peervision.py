from http.server import HTTPServer, BaseHTTPRequestHandler
import mimetypes
import json
import subprocess
import urllib.parse
import ipaddress
import os
import sys
from typing import Dict, Any, Optional, List

class WireGuardAPIHandler(BaseHTTPRequestHandler):
    def serve_static_file(self, path: str) -> None:
        """Serve a static file."""
        try:
            # Map file extensions to MIME types
            if not mimetypes.inited:
                mimetypes.init()
                
            # Determine the file's MIME type
            content_type, _ = mimetypes.guess_type(path)
            if not content_type:
                content_type = 'application/octet-stream'
                
            with open(path, 'rb') as file:
                content = file.read()
                
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error_response(404, f"File not found: {path}")
        except IOError as e:
            self.send_error_response(500, f"Error reading file: {str(e)}")

    def send_json_response(self, status_code: int, data: Dict[str, Any]) -> None:
        """Send a JSON response with the given data and status code."""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Server', 'wgctl-server')  # Generic server name for security
        self.send_header('X-Content-Type-Options', 'nosniff')  # Security header
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def send_error_response(self, status_code: int, message: str) -> None:
        """Send an error response with the given message and status code."""
        self.send_json_response(status_code, {"error": message})

    def get_client_ip(self) -> str:
        """Extract the client's IP address from headers or connection."""
        # Try to get from X-Forwarded-For if behind a proxy
        if 'X-Forwarded-For' in self.headers:
            return self.headers.get('X-Forwarded-For').split(',')[0].strip()
        return self.client_address[0]

    def get_interface_for_client_ip(self) -> Optional[str]:
        """Determine which WireGuard interface the client's IP belongs to."""
        client_ip = self.get_client_ip()

        try:
            # Get all interfaces and their networks
            interfaces_data = self.execute_command(["wgctl", "show", "interfaces", "format", "json"])
            interfaces = json.loads(interfaces_data)

            if "interfaces" not in interfaces:
                return None

            # Check which network the client IP belongs to
            client_ip_obj = ipaddress.ip_address(client_ip)
            for interface_name, interface_info in interfaces["interfaces"].items():
                if "network" in interface_info:
                    try:
                        network = ipaddress.ip_network(interface_info["network"])
                        if client_ip_obj in network:
                            return interface_name
                    except ValueError:
                        # Invalid network format, continue to next interface
                        continue
        except (json.JSONDecodeError, ValueError, subprocess.SubprocessError) as e:
            sys.stderr.write(f"Error determining interface: {str(e)}\n")
            return None

        return None

    def execute_command(self, cmd: List[str]) -> str:
        """Execute a shell command and return its output."""
        try:
            # Use a timeout to prevent hanging processes
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                check=True, 
                timeout=30,  # 30 second timeout
                env=os.environ.copy()  # Use a clean environment
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            sys.stderr.write(f"Command failed: {e.stderr}\n")
            raise RuntimeError(f"Command execution failed: {e.stderr}")
        except subprocess.TimeoutExpired:
            sys.stderr.write(f"Command timed out: {' '.join(cmd)}\n")
            raise RuntimeError("Command execution timed out")
    
    def merge_wgctl_and_wgstat_data(self, interface: str) -> Dict[str, Any]:
        """Merge data from wgctl show and wgstat show commands."""
        try:
            # Get configuration data
            config_data = self.execute_command(["wgctl", "show", interface, "format", "json"])
            config = json.loads(config_data)

            # Get stats data
            stats_data = self.execute_command(["wgstat", "show", interface, "json"])
            stats = json.loads(stats_data)

            # Copy stats interface data to config interface
            if "interface" in stats and "interface" in config:
                for key, value in stats["interface"].items():
                    if key != "name" and key != "public_key":
                        config["interface"][key] = value

            # Match stats peer data with config peer data by public key
            if "peers" in stats and "peers" in config:
                for peer_name, peer_info in config["peers"].items():
                    public_key = peer_info.get("publicKey")
                    if public_key and public_key in stats["peers"]:
                        # Copy stats peer data to config peer
                        for key, value in stats["peers"][public_key].items():
                            if key not in ["public_key"]:  # Avoid duplicating keys
                                config["peers"][peer_name][key] = value

            return config

        except (json.JSONDecodeError, subprocess.SubprocessError) as e:
            sys.stderr.write(f"Failed to merge data: {str(e)}\n")
            raise RuntimeError(f"Failed to merge data: {str(e)}")

    def parse_post_data(self) -> Dict[str, Any]:
        """Parse POST data from the request."""
        content_length = int(self.headers.get('Content-Length', 0))
        
        # Limit the size of POST data to prevent DoS attacks
        if content_length > 10240:  # 10KB limit
            raise ValueError("POST data too large")
            
        post_data = self.rfile.read(content_length).decode('utf-8')

        if self.headers.get('Content-Type') == 'application/json':
            return json.loads(post_data)
        else:
            return dict(urllib.parse.parse_qsl(post_data))

    def validate_peer_name(self, peer_name: str) -> bool:
        """Validate peer name to prevent command injection."""
        # Allow only alphanumeric characters, dash, and underscore
        return bool(peer_name and peer_name.isalnum() or 
                    all(c.isalnum() or c in '-_' for c in peer_name))
    
    def handle_show_endpoint(self) -> None:
        """Handle /interface/show endpoint."""
        interface = self.get_interface_for_client_ip()
        if not interface:
            self.send_error_response(403, "Forbidden: Unable to determine interface for your IP")
            return

        try:
            merged_data = self.merge_wgctl_and_wgstat_data(interface)
            self.send_json_response(200, merged_data)
        except Exception as e:
            self.send_error_response(500, f"Error: {str(e)}")

    def handle_apply_endpoint(self) -> None:
        """Handle /interface/apply endpoint."""
        interface = self.get_interface_for_client_ip()
        if not interface:
            self.send_error_response(403, "Forbidden: Unable to determine interface for your IP")
            return

        try:
            output = self.execute_command(["wgctl", "apply", interface])
            self.send_json_response(200, {"status": "success", "message": "Configuration applied", "output": output})
        except Exception as e:
            self.send_error_response(500, f"Error applying configuration: {str(e)}")

    def handle_peer_add(self, peer_name: str) -> None:
        """Handle /peer/add/<peer-name> endpoint."""
        if not self.validate_peer_name(peer_name):
            self.send_error_response(400, "Invalid peer name format")
            return
            
        interface = self.get_interface_for_client_ip()
        if not interface:
            self.send_error_response(403, "Forbidden: Unable to determine interface for your IP")
            return

        try:
            # Parse POST data for additional parameters
            params = self.parse_post_data()

            # Build command
            cmd = ["wgctl", "add", peer_name, "for", interface]

            # Validate and add optional parameters if present
            if "private_key" in params:
                # Simple validation for WireGuard private key format (base64, 44 chars)
                key = params["private_key"].strip()
                if len(key) == 44 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" for c in key.rstrip('=')):
                    cmd.extend(["private-key", key])
                else:
                    self.send_error_response(400, "Invalid private key format")
                    return
                    
            if "allowed_ips" in params:
                # Validate IP networks
                try:
                    for ip_net in params["allowed_ips"].split(','):
                        ip_net = ip_net.strip()
                        if ip_net:
                            ipaddress.ip_network(ip_net)
                    cmd.extend(["allowed-ips", params["allowed_ips"]])
                except ValueError:
                    self.send_error_response(400, "Invalid allowed IPs format")
                    return

            output = self.execute_command(cmd)
            self.send_json_response(200, {
                "status": "success",
                "message": f"Peer {peer_name} added",
                "output": output
            })
        except Exception as e:
            self.send_error_response(500, f"Error adding peer: {str(e)}")

    def handle_peer_delete(self, peer_name: str) -> None:
        """Handle /peer/del/<peer-name> endpoint."""
        if not self.validate_peer_name(peer_name):
            self.send_error_response(400, "Invalid peer name format")
            return
            
        interface = self.get_interface_for_client_ip()
        if not interface:
            self.send_error_response(403, "Forbidden: Unable to determine interface for your IP")
            return

        try:
            output = self.execute_command(["wgctl", "remove", peer_name, "for", interface])
            self.send_json_response(200, {
                "status": "success",
                "message": f"Peer {peer_name} removed",
                "output": output
            })
        except Exception as e:
            self.send_error_response(500, f"Error removing peer: {str(e)}")

    def handle_peer_disable(self, peer_name: str) -> None:
        """Handle /peer/disable/<peer-name> endpoint."""
        if not self.validate_peer_name(peer_name):
            self.send_error_response(400, "Invalid peer name format")
            return
            
        interface = self.get_interface_for_client_ip()
        if not interface:
            self.send_error_response(403, "Forbidden: Unable to determine interface for your IP")
            return

        try:
            output = self.execute_command(["wgctl", "disable", peer_name, "for", interface])
            self.send_json_response(200, {
                "status": "success",
                "message": f"Peer {peer_name} disabled",
                "output": output
            })
        except Exception as e:
            self.send_error_response(500, f"Error disabling peer: {str(e)}")

    def handle_peer_enable(self, peer_name: str) -> None:
        """Handle /peer/enable/<peer-name> endpoint."""
        if not self.validate_peer_name(peer_name):
            self.send_error_response(400, "Invalid peer name format")
            return
            
        interface = self.get_interface_for_client_ip()
        if not interface:
            self.send_error_response(403, "Forbidden: Unable to determine interface for your IP")
            return

        try:
            output = self.execute_command(["wgctl", "enable", peer_name, "for", interface])
            self.send_json_response(200, {
                "status": "success",
                "message": f"Peer {peer_name} enabled",
                "output": output
            })
        except Exception as e:
            self.send_error_response(500, f"Error enabling peer: {str(e)}")

    def handle_peer_export(self, peer_name: str) -> None:
        """Handle /peer/export/<peer-name> endpoint."""
        if not self.validate_peer_name(peer_name):
            self.send_error_response(400, "Invalid peer name format")
            return
            
        interface = self.get_interface_for_client_ip()
        if not interface:
            self.send_error_response(403, "Forbidden: Unable to determine interface for your IP")
            return

        try:
            output = self.execute_command(["wgctl", "export", peer_name, "for", interface])
            self.send_json_response(200, {
                "status": "success",
                "peer_name": peer_name,
                "config": output
            })
        except Exception as e:
            self.send_error_response(500, f"Error exporting peer config: {str(e)}")
    
    def normalize_path(self, path: str) -> str:
        """Normalize the path by handling trailing slashes."""
        # Remove query string if present
        path = path.split('?')[0]
        # Remove trailing slash if present (unless it's just '/')
        if path != '/' and path.endswith('/'):
            path = path[:-1]
        return path
    
    def do_OPTIONS(self) -> None:
        """Handle OPTIONS requests for CORS preflight."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Access-Control-Max-Age', '86400')  # 24 hours
        self.end_headers()

    def do_GET(self) -> None:
        """Handle GET requests."""
        # Normalize path (remove trailing slash)
        path = self.normalize_path(self.path)

        try:
            # Serve HTML file at root
            if path == '/':
                self.serve_static_file('/var/www/html/peervision.html')
            # Handle different endpoints
            elif path == '/interface/show':
                self.handle_show_endpoint()
            elif path == '/interface/apply':
                self.handle_apply_endpoint()
            # Peer export endpoint
            elif path.startswith('/peer/export/'):
                peer_name = path.split('/peer/export/')[1]
                self.handle_peer_export(peer_name)
            else:
                self.send_error_response(404, f"Not Found: {path}")
        except Exception as e:
            self.send_error_response(500, f"Internal Server Error: {str(e)}")
            
    def do_POST(self) -> None:
        """Handle POST requests."""
        # Normalize path (remove trailing slash)
        path = self.normalize_path(self.path)

        try:
            # Handle peer management endpoints
            if path.startswith('/peer/add/'):
                peer_name = path.split('/peer/add/')[1]
                self.handle_peer_add(peer_name)
            elif path.startswith('/peer/del/'):
                peer_name = path.split('/peer/del/')[1]
                self.handle_peer_delete(peer_name)
            elif path.startswith('/peer/disable/'):
                peer_name = path.split('/peer/disable/')[1]
                self.handle_peer_disable(peer_name)
            elif path.startswith('/peer/enable/'):
                peer_name = path.split('/peer/enable/')[1]
                self.handle_peer_enable(peer_name)
            # Also accept POST for these endpoints
            elif path == '/interface/apply':
                self.handle_apply_endpoint()
            else:
                self.send_error_response(404, f"Not Found: {path}")
        except Exception as e:
            self.send_error_response(500, f"Internal Server Error: {str(e)}")

    
class ThreadedHTTPServer(HTTPServer):
    """Handle requests in a separate thread."""
    def handle_error(self, request, client_address):
        """Handle errors during request processing."""
        # Print error to stderr but continue running
        sys.stderr.write(f"Error processing request from {client_address}: {sys.exc_info()[1]}\n")


def run_server(host: str = '0.0.0.0', port: int = 8000) -> None:
    """Run the HTTP server."""
    server_address = (host, port)
    
    try:
        # Check that commands are available
        subprocess.run(["which", "wgctl"], capture_output=True, check=True)
        subprocess.run(["which", "wgstat"], capture_output=True, check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        sys.stderr.write("Error: Required commands 'wgctl' and/or 'wgstat' not available\n")
        sys.exit(1)
    
    try:
        httpd = ThreadedHTTPServer(server_address, WireGuardAPIHandler)
        print(f"Starting WireGuard API server on {host}:{port}")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.server_close()
    except Exception as e:
        sys.stderr.write(f"Error starting server: {str(e)}\n")
        sys.exit(1)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='WireGuard API Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to')

    args = parser.parse_args()
    run_server(args.host, args.port)