from rest_framework import serializers
from .models import Message

class MessageSerializer(serializers.ModelSerializer):
    sender = serializers.StringRelatedField(source='sender.tag')
    receiver = serializers.StringRelatedField(source='receiver.tag')
    
    class Meta:
        model = Message
        fields = ['content_to', 'content_from', 'sender', 'receiver', 'timestamp']