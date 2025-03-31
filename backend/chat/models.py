from django.db import models
from django.utils import timezone

class User(models.Model):
    tag = models.CharField(max_length=21, primary_key=True)
    nickname = models.CharField(max_length=21, blank=True)
    public_key = models.TextField()
    profile_picture = models.ImageField(upload_to='profiles/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_hidden = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        # Set nickname to tag if not provided
        if not self.nickname:
            self.nickname = self.tag
        super().save(*args, **kwargs)

class Keys(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    encrypted_private_key = models.BinaryField()
    # public_key removed (now in User model)

class Token(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=64)
    valid_until = models.DateTimeField()

class Credentials(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    password_hash = models.CharField(max_length=255)

class Message(models.Model):
    content_to = models.BinaryField()
    content_from = models.BinaryField()
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    timestamp = models.DateTimeField(auto_now_add=True)