import socketserver
import socket
import json
class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.data = self.request.recv(2048).strip()
        print("{} wrote:".format(self.client_address[0]))
        print(self.data)
        self.request.sendall(self.data.upper())
        while True:
            json_response = {}
            self.request.sendall(self.data.upper())

if __name__ == "__main__":
    HOST, PORT = socket.gethostname(), 11000

    server = socketserver.TCPServer((HOST, PORT), MyTCPHandler)
    server.serve_forever()