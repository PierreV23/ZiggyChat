"""
ASGI config for config project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

import os

# import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
# django.setup()

from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
from channels.auth import AuthMiddlewareStack
from chat import routing

django_asgi_app = get_asgi_application()



application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AuthMiddlewareStack(  # Add WebSocket support
        URLRouter(
            routing.websocket_urlpatterns
        )
    ),
})

ASGI_APPLICATION = 'config.asgi.application'