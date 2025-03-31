from django.contrib import admin

# Register your models here.
from .models import User, Keys, Credentials, Message

# Register your models
admin.site.register(User)
admin.site.register(Keys)
admin.site.register(Credentials)
admin.site.register(Message)