import http.server
import json
import signal
import socketserver
import sys

PORT = 8082


class CustomHandler(http.server.SimpleHTTPRequestHandler):

    def do_GET(self):
        if self.path == '/':
            # Read data from sessions.txt
            sessions = {}
            filename = sys.argv[1]  # Read filename from command-line argument
            with open(filename, 'r') as f:
                for line in f:
                    session_data = json.loads(line.strip())
                    session_cookie = session_data['session_cookie']
                    if session_cookie in sessions:
                        session = sessions[session_cookie]
                        command = session_data['last_comm']
                        session['commands'].append(command)
                    else:

                        sessions[session_cookie] = {
                            'login_timestamp': session_data['login_timestamp'],
                            'uid': session_data['uid'],
                            'source_addr': session_data['source_addr'],
                            'source_port': session_data['source_port'],
                            'init_pid': session_data['init_pid'],
                            'session_cookie': session_cookie,
                            'commands': [session_data['last_comm']]
                        }

            # Generate HTML tables
            html = ''
            for session_cookie in sessions:
                session = sessions[session_cookie]
                html += '<link rel="stylesheet" href="stylesheet.css">'
                html += '<h2>Session for uid {} from {}:{} at {} ns from boot time</h2>'.format(session['uid'],
                                                                                                session['source_addr'],
                                                                                                session['source_port'],
                                                                                                session['login_timestamp'])
                html += '<table>'
                html += '<tr><th>Nanoseconds from boot time</th><th>Command</th><th>Argv1</th><th>Argv2</th><th>Argv3</th' \
                        '><th>Argv5' \
                        '</th><th>Argv5</th><th>Argv6</th></tr>'
                for command in session['commands']:
                    if command['timestamp'] == 0:
                        continue
                    if command['suspect']:
                        html += '<tr style="background-color: red; color: white">'
                    else:
                        html += '<tr>'
                    html += '<td>{} ns</td>'.format(command['timestamp'])
                    html += '<td>{}</td>'.format(command['command'])
                    html += '<td>{}</td>'.format(command['argv'][0])
                    html += '<td>{}</td>'.format(command['argv'][1])
                    html += '<td>{}</td>'.format(command['argv'][2])
                    html += '<td>{}</td>'.format(command['argv'][3])
                    html += '<td>{}</td>'.format(command['argv'][4])
                    html += '<td>{}</td>'.format(command['argv'][5])
                    html += '</tr>'
                html += '</table>'

            # Generate full HTML page
            page = '<html><head><title>Sessions and Commands</title></head><body>{}</body></html>'.format(html)

            # Send HTTP response
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(bytes(page, 'utf-8'))
        else:
            super().do_GET()


# Function for signal handling
def signal_handler(sig, frame):
    print('\nShutting down the server..')
    httpd.shutdown()
    httpd.server_close()
    sys.exit(0)


# Registering signal handler
signal.signal(signal.SIGINT, signal_handler)

# Start server
Handler = CustomHandler

if len(sys.argv) < 2:
    print("Usage: python server.py <filename>")
    sys.exit(0)

with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
    print("Serving at port", PORT)
    print("Visit http://localhost:", PORT, sep='')
    httpd.serve_forever()
