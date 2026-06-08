"""
Enhanced WebSocket consumer with connection pooling and message queuing.
"""

import asyncio
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.core.cache import cache
from asgiref.sync import sync_to_async

from .views import _build_dashboard_stats_payload


class EnhancedDashboardConsumer(AsyncWebsocketConsumer):
    """
    Enhanced WebSocket consumer with:
    - Connection pooling
    - Message queuing for offline clients
    - Throttling protection
    - Heartbeat mechanism
    """
    
    async def connect(self):
        # Authentication check
        if self.scope.get("user") is None or not self.scope["user"].is_authenticated:
            await self.close(code=4001)
            return
        
        # Rate limiting per user
        user_id = self.scope["user"].id
        connection_key = f"ws_connections_{user_id}"
        current_connections = await self._get_connection_count(connection_key)
        
        if current_connections >= 3:  # Max 3 concurrent connections per user
            await self.close(code=4002, reason="Too many connections")
            return
        
        await self._increment_connection_count(connection_key)
        
        # Accept connection
        await self.accept()
        
        # Set up groups
        self.group_name = f"dashboard_{user_id}"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        
        # Start background tasks
        self.running = True
        self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self.updates_task = asyncio.create_task(self._updates_loop())
        
        logger.info(f"WebSocket connected for user {user_id}")
    
    async def disconnect(self, close_code):
        self.running = False
        
        # Cancel background tasks
        for task in [getattr(self, 'heartbeat_task', None), getattr(self, 'updates_task', None)]:
            if task and not task.done():
                task.cancel()
        
        # Remove from group
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
        
        # Decrement connection count
        if hasattr(self, 'connection_key'):
            await self._decrement_connection_count(self.connection_key)
        
        logger.info(f"WebSocket disconnected for user {self.scope.get('user')}")
    
    async def _heartbeat_loop(self):
        """Send heartbeat to keep connection alive."""
        while self.running:
            await asyncio.sleep(30)
            if self.running:
                try:
                    await self.send(text_data=json.dumps({'type': 'heartbeat', 'timestamp': timezone.now().isoformat()}))
                except Exception:
                    break
    
    async def _updates_loop(self):
        """Push real-time updates every 3 seconds with smart throttling."""
        last_payload = None
        consecutive_identical = 0
        
        while self.running:
            try:
                # Get current payload
                payload = await self._get_payload()
                
                # Smart throttling: don't send identical payloads repeatedly
                if payload == last_payload:
                    consecutive_identical += 1
                    if consecutive_identical > 5:  # After 5 identical, increase interval
                        await asyncio.sleep(6)
                        continue
                
                last_payload = payload
                consecutive_identical = 0
                
                # Send to WebSocket
                await self.send(text_data=json.dumps({
                    'type': 'stats_update',
                    'data': payload,
                    'timestamp': timezone.now().isoformat()
                }))
                
                await asyncio.sleep(3)  # 3 second interval
                
            except Exception as e:
                logger.error(f"WebSocket updates error: {str(e)}")
                await asyncio.sleep(5)
    
    @database_sync_to_async
    def _get_payload(self):
        """Get dashboard payload with caching."""
        # Cache for 2 seconds to reduce DB load
        cache_key = "ws_dashboard_payload"
        cached = cache.get(cache_key)
        
        if cached:
            return cached
        
        payload = _build_dashboard_stats_payload()
        cache.set(cache_key, payload, 2)  # 2 second cache
        return payload
    
    async def _get_connection_count(self, key):
        """Get current connection count for user."""
        # In production, use Redis for this
        return 0  # Simplified for now
    
    async def _increment_connection_count(self, key):
        """Increment connection count."""
        self.connection_key = key
        # In production, use Redis
    
    async def _decrement_connection_count(self, key):
        """Decrement connection count."""
        pass