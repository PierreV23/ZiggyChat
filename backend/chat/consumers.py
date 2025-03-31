# backend/chat/consumers.py
import asyncio
from channels.generic.websocket import AsyncWebsocketConsumer


# consumers.py
from channels.generic.websocket import AsyncWebsocketConsumer
import json


from channels.generic.websocket import AsyncJsonWebsocketConsumer
from .connection_manager import manager

class MyConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        self.tag = self.scope['url_route']['kwargs'].get('tag')
        self.token = self.scope['url_route']['kwargs'].get('token')
        
        if not self.tag or not self.token:
            await self.close()
            return
            
        # Add to connection manager
        await manager.add_connection(self.tag, self.token, self)
        await self.accept()

    async def disconnect(self, close_code):
        # Remove from connection manager
        await manager.remove_connection(self)

    async def receive_json(self, content):
        # Handle incoming messages if needed
        pass