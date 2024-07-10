import asyncio
import websockets
import json

class EchoServer:
    def __init__(self):
        self.max_size = 2**30  # 1GB
        self.server = None
        self.connected = set()
        self.subscriptions = {}  # New: Dictionary to manage subscriptions

    async def handle_subscription(self, message, websocket):
        try:
            data = json.loads(message)
            if data['type'] == 'Subscribe':
                topic = data['topic']
                if topic not in self.subscriptions:
                    self.subscriptions[topic] = set()
                self.subscriptions[topic].add(websocket)
                await websocket.send(json.dumps({"type": "Acknowledgement", "message": f"Subscribed to {topic}"}))
            elif data['type'] == 'Unsubscribe':
                topic = data['topic']
                if topic in self.subscriptions and websocket in self.subscriptions[topic]:
                    self.subscriptions[topic].remove(websocket)
                    await websocket.send(json.dumps({"type": "Acknowledgement", "message": f"Unsubscribed from {topic}"}))
        except json.JSONDecodeError:
            pass  # Ignore non-JSON messages or bad format

    async def echo(self, websocket):
        async for message in websocket:
            try:
                if isinstance(message, bytes):
                    # Handle binary frame data
                    await self.broadcast(websocket, message,  'video-stream', is_binary=True)
                else:
                    data = json.loads(message)
                    topic = data['topic']
                    await self.handle_subscription(message, websocket)
                    await self.broadcast(websocket, message, topic)
            except json.JSONDecodeError:
                print("Bad JSON")
            except KeyError as e:
                print("No topic: " + str(e))
            except Exception as e:
                print("Error in echo: " + str(e))

    async def broadcast(self,websocket, message, topic=None, is_binary=False):
        # Broadcast to all clients subscribed to the relevant topic
        try:
            if topic in self.subscriptions:
                subscribers = self.subscriptions[topic]
                if is_binary:
                    tasks = [asyncio.create_task(ws.send(message)) for ws in subscribers if ws.open]
                else:
                    print(f"Broadcasting to {topic}")
                    tasks = [asyncio.create_task(ws.send(message)) for ws in subscribers if ws.open and ws != websocket]
                if tasks:
                    await asyncio.wait(tasks)

        except json.JSONDecodeError:
            print("Bad JSON")
        except KeyError as e:
            print("No topic: " + str(e))
        except Exception as e:
            print("Error in broadcast: " + str(e))

    async def on_connect(self, websocket, path):
        print(f"New connection: {path}")
        self.connected.add(websocket)

    async def on_disconnect(self, websocket, path):
        print(f"Disconnected: {path}")
        self.connected.remove(websocket)
        # Remove from all subscriptions
        for subscribers in self.subscriptions.values():
            subscribers.discard(websocket)

    async def handler(self, websocket, path):
        try:
            await self.on_connect(websocket, path)
            await self.echo(websocket)
        except Exception as e:
            print(f"Echo failed: {e}")
        finally:
            await self.on_disconnect(websocket, path)

    def start(self):
        self.server = websockets.serve(self.handler, "0.0.0.0", 3030, max_size=None, max_queue=5)
        print("Running server! with max size: " + str(self.max_size) + " bytes")
        asyncio.get_event_loop().run_until_complete(self.server)
        asyncio.get_event_loop().run_forever()

EchoServer().start()
