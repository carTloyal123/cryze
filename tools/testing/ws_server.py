# Python
import asyncio
import websockets

class EchoServer:
    def __init__(self):
        self.server = None
        self.connected = set()

    async def echo(self, websocket, path):
        async for message in websocket:
            print(f"Received: {message}")
            await self.broadcast(message)

    async def broadcast(self, message):
        if self.connected:  # asyncio.wait doesn't accept an empty list
            tasks = []
            for ws in self.connected:
                if ws.open:
                    tasks.append(asyncio.create_task(ws.send(message)))
                else:
                    self.connected.remove(ws)
            if tasks:
                await asyncio.wait(tasks)

    async def on_connect(self, websocket, path):
        print(f"New connection: {path}")
        self.connected.add(websocket)

    async def on_disconnect(self, websocket, path):
        print(f"Disconnected: {path}")
        self.connected.remove(websocket)

    async def handler(self, websocket, path):
        try:
            await self.on_connect(websocket, path)
            try:
                await self.echo(websocket, path)
            except Exception as e:
                print(f"Echo failed: {e}")
            finally:
                await self.on_disconnect(websocket, path)
        except Exception as e:
            print(f"Handler failed: {e}")

    def start(self):
        self.server = websockets.serve(self.handler, "0.0.0.0", 3030)
        print("Running server!")
        asyncio.get_event_loop().run_until_complete(self.server)
        asyncio.get_event_loop().run_forever()

EchoServer().start()