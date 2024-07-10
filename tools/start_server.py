import argparse
from cryze_server import server

def main():
    # Create the parser
    parser = argparse.ArgumentParser(description='Setup the Cryze server.')
    parser.add_argument('--url', dest='url', type=str, default='0.0.0.0', help='URL to run the server on')
    parser.add_argument('--port', dest='port', type=int, default=3030, help='Port to run the server on')
    args = parser.parse_args()

    server_instance = server.CryzeWebsocketServer()
    server_instance.start(url=args.url, port=args.port)

if __name__ == "__main__":
    main()