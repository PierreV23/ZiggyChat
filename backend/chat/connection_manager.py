from collections import defaultdict

class ConnectionManager:
    def __init__(self):
        # Store connections by user tag
        self.user_connections = defaultdict(dict)
        
        # Store user tags by connection (for clean up on disconnect)
        self.connection_users = {}

    async def add_connection(self, tag, token, websocket):
        self.user_connections[tag][token] = websocket
        self.connection_users[websocket] = (tag, token)

    async def remove_connection(self, websocket):
        if websocket in self.connection_users:
            tag, token = self.connection_users[websocket]
            if tag in self.user_connections and token in self.user_connections[tag]:
                del self.user_connections[tag][token]
                if not self.user_connections[tag]:  # Clean up empty tags
                    del self.user_connections[tag]
            del self.connection_users[websocket]

    async def send_to_user(self, tag, message):
        if tag in self.user_connections:
            for connection in self.user_connections[tag].values():
                await connection.send_json(message)

# Global instance
manager = ConnectionManager()