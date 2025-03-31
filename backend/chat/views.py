import os
import re
from django.shortcuts import render
from django.http import HttpResponse

from chat.serializers import MessageSerializer
from chat.models import Message, User

def index(request):
    return render(request, 'chat/index.html')

def chat(request):
    return render(request, 'chat/chat.html')

def register(request):
    return render(request, 'chat/register.html')

def login(request):
    return render(request, 'chat/login.html')

def failed_auth(request):
    return render(request, 'chat/failed_auth.html')

def settings_page(request):
    return render(request, 'chat/settings.html')

from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.hashers import check_password
import base64
from .models import User, Keys, Credentials, Token
from django.utils import timezone
from datetime import timedelta

@api_view(['POST'])
def user_login(request):
    tag = request.data.get('tag')
    h1_pass = request.data.get('h1_pass')  # Frontend hashed password
    
    if not tag or not h1_pass:
        return Response(
            {'status': 'error', 'message': 'Tag and password required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    h1_pass = base64.b64decode(h1_pass)
    
    try:
        # Get user and credentials
        user = User.objects.get(tag=tag)
        credentials = Credentials.objects.get(user=user)
        
        # Verify password
        if not check_password(h1_pass, credentials.password_hash):
            return Response(
                {'status': 'error', 'message': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Get encrypted private key (contains salt + iv + ciphertext)
        keys = Keys.objects.get(user=user)
        encrypted_data = keys.encrypted_private_key
        
        # Create or update token
        token = Token.objects.create(
            user=user,
            token = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8'),
            valid_until = timezone.now() + timedelta(days=30)
        )
        print(token.token)
        
        # if not created:
        #     token.valid_until = timezone.now() + timedelta(days=30)
        #     token.save()
        
        return Response({
            'status': 'success',
            'message': 'Successfully logged in.',
            'token': token.token,
            'encrypted_private_key': base64.b64encode(encrypted_data)
        })
        
    except User.DoesNotExist:
        return Response({'status': 'error', 'message': 'User not found'}, status=404)
    except Exception as e:
        return Response({'status': 'error', 'message': str(e)}, status=500)

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q

@api_view(['GET'])
def get_messages(request, tag, token, other_user_tag):
    
    try:
        if not is_authorized(tag, token):
            return Response(
                {'status': 'error', 'message': 'Token expired'},
                status=status.HTTP_401_UNAUTHORIZED
            )
    except User.DoesNotExist:
        return Response(
            {'status': 'error', 'message': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Token.DoesNotExist:
        return Response(
            {'status': 'error', 'message': 'Invalid token'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # user = get_object_or_404(User, tag=tag)
    
    messages = Message.objects.filter(
        (Q(sender__tag=tag) & Q(receiver__tag=other_user_tag)) |
        (Q(sender__tag=other_user_tag) & Q(receiver__tag=tag))
    ).order_by('timestamp')
    
    return Response(MessageSerializer(messages, many=True).data)


from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.hashers import make_password
from .models import User, Keys, Credentials
import base64

@api_view(['POST'])
# @authentication_classes([])
# @permission_classes([])
def register_user(request):
    required_fields = ['tag', 'nickname', 'public_key', 'encrypted_private_key', 'h1_pass']
    print(request.data['public_key'])
    
    if not all(field in request.data for field in required_fields):
        return Response(
            {'status': 'error', 'message': 'Missing required fields'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    pattern = r'[0-9a-zA-Z_]+'
    if (not re.fullmatch(pattern, request.data['tag'])):
        return Response(
            {'status': 'error', 'message': 'Illegal username'},
            status=status.HTTP_400_BAD_REQUEST
        )

    if User.objects.filter(tag=request.data['tag']).exists():
        return Response(
            {'status': 'error', 'message': 'User tag already exists'},
            status=status.HTTP_409_CONFLICT
        )
    
    try:
        # Decode base64 strings to binary
        public_key = request.data['public_key']
        encrypted_private_key = base64.b64decode(request.data['encrypted_private_key'])
        h1_pass = base64.b64decode(request.data['h1_pass'])
        
        # Create user
        user = User.objects.create(
            tag=request.data['tag'],
            nickname=request.data.get('nickname', request.data['tag']),
            public_key=public_key
        )
        
        # Store keys and credentials
        Keys.objects.create(
            user=user,
            encrypted_private_key=encrypted_private_key
        )
        
        Credentials.objects.create(
            user=user,
            password_hash=make_password(h1_pass)  # h1_pass is already bytes
        )
        
        return Response({
            'status': 'success',
            'message': 'User sucessfully creates',
            'user': user.tag,
            'nickname': user.nickname
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        # print(e)
        # print(str(e))
        # raise Exception(e)

        return Response(
            {'status': 'error', 'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


from .connection_manager import manager

@api_view(['POST'])
def send_message(request):
    required_fields = ['sender', 'receiver', 'content_to', 'content_from', 'token'] # token ook
    
    if not all(field in request.data for field in required_fields):
        return Response(
            {'status': 'error', 'message': 'Missing required fields'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    sender = request.data['sender']
    receiver = request.data['receiver']
    
    if not is_authorized(sender, request.data["token"]):
            return Response(
                {'status': 'error', 'message': 'Token expired'},
                status=status.HTTP_401_UNAUTHORIZED
            )
    # check if sender is authorized with token

    # check if sender and receiver both exist

    sender_u = User.objects.get(tag=sender)
    receiver_u = User.objects.get(tag=receiver)
    # get_object_or_404(User, tag=tag)

    Message.objects.create(
            sender = sender_u,
            receiver = receiver_u,
            content_to = base64.b64decode(request.data['content_to']),
            content_from = base64.b64decode(request.data['content_from'])
        )
    import asyncio
    asyncio.run(manager.send_to_user(sender, {
        "sender": sender,
        "receiver": receiver,
        "content_to": request.data['content_to'],
        "content_from": request.data['content_from'],
    }))

    # import asyncio
    if sender != receiver:
        asyncio.run(manager.send_to_user(receiver, {
            "sender": sender,
            "receiver": receiver,
            "content_to": request.data['content_to'],
            "content_from": request.data['content_from'],
        }))

    print({
        "sender": sender,
        "receiver": receiver,
        "content_to": request.data['content_to'],
        "content_from": request.data['content_from'],
    })

    return Response({'status': 'success'})


from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from .models import User, Token

def is_authorized(tag, token) -> bool:
    user = User.objects.get(tag=tag)
    token = Token.objects.get(user=user, token=token)
    return token.valid_until > timezone.now()


@api_view(['POST'])
def auth_me(request):
    required_fields = ['tag', 'token']
    
    if not all(field in request.data for field in required_fields):
        return Response(
            {'status': 'error', 'message': 'Missing required fields'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    tag = request.data['tag']
    tok = request.data['token']

    try:
        if not is_authorized(tag, tok):
            return Response(
                {'status': 'error', 'message': 'Token expired'},
                status=status.HTTP_401_UNAUTHORIZED
            )
    except User.DoesNotExist:
        return Response(
            {'status': 'error', 'message': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Token.DoesNotExist:
        return Response(
            {'status': 'error', 'message': 'Invalid token'},
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    
    return Response({
        'status': 'success',
        'message': 'Authentication successful',
    }, status=status.HTTP_200_OK)




    
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.db.models import Q, Max, F
from django.core.serializers.json import DjangoJSONEncoder
from .models import User, Message
import json

from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.db.models import Q, Max, F, OuterRef, Subquery
from .models import User, Message

def get_recent_chats(request, tag, token):

    try:
        if not is_authorized(tag, token):
            return Response(
                {'status': 'error', 'message': 'Token expired'},
                status=status.HTTP_401_UNAUTHORIZED
            )
    except User.DoesNotExist:
        return Response(
            {'status': 'error', 'message': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Token.DoesNotExist:
        return Response(
            {'status': 'error', 'message': 'Invalid token'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    user = get_object_or_404(User, tag=tag)
    
    # Subquery to get the latest message timestamp between user and each partner
    latest_message = Message.objects.filter(
        Q(sender=user, receiver=OuterRef('pk')) | 
        Q(receiver=user, sender=OuterRef('pk'))
    ).order_by('-timestamp').values('timestamp')[:1]
    
    # Find all users who have either sent messages to or received messages from this user
    chat_partners = (
        User.objects
        .filter(
            # Users who either sent messages to or received messages from this user
            Q(sent_messages__receiver=user) | Q(received_messages__sender=user)
        )
        .distinct()
        # Exclude the user themselves
        # .exclude(tag=tag)
        # Annotate with the most recent message timestamp for sorting
        .annotate(last_message_time=Subquery(latest_message))
        # Order by the most recent message timestamp
        .order_by('-last_message_time')
        # Values we want to return
        .values('tag', 'nickname', 'last_message_time')
    )
    
    # Return as JSON response
    return JsonResponse(list(chat_partners), safe=False)


def fetch_user(request, tag):
    try:
        user = User.objects.get(tag=tag)
    except User.DoesNotExist:
        return Response(
            {'status': 'error', 'message': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )


    return JsonResponse({
            'status': 'success',
            'message': 'User fetched',
            'tag': tag,
            'nickname': user.nickname,
            'creation_date': user.created_at,
            'public_key': user.public_key,
        })

def fetch_self(request, tag, token):
    try:
        if not is_authorized(tag, token):
            return Response(
                {'status': 'error', 'message': 'Token expired'},
                status=status.HTTP_401_UNAUTHORIZED
            )
    except User.DoesNotExist:
        return Response(
            {'status': 'error', 'message': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Token.DoesNotExist:
        return Response(
            {'status': 'error', 'message': 'Invalid token'},
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    user = User.objects.get(tag=tag)

    keys = Keys.objects.get(user=user)
    encrypted_data = keys.encrypted_private_key
    encrypted_data = base64.b64encode(encrypted_data).decode('utf-8')


    return JsonResponse({
            'status': 'success',
            'message': 'User fetched',
            'tag': tag,
            'nickname': user.nickname,
            'creation_date': user.created_at,
            'public_key': user.public_key,
            'encrypted_private_key': encrypted_data,
            'is_hidden': user.is_hidden,

        })


def set_hidden(request, tag, sethid, token):
    t = sethid == 'true'

    try:
        if not is_authorized(tag, token):
            return Response(
                {'status': 'error', 'message': 'Token expired'},
                status=status.HTTP_401_UNAUTHORIZED
            )
    except User.DoesNotExist:
        return Response(
            {'status': 'error', 'message': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Token.DoesNotExist:
        return Response(
            {'status': 'error', 'message': 'Invalid token'},
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    user = User.objects.get(tag=tag)
    user.is_hidden = t
    user.save()

    return JsonResponse(
            {'status': 'success', 'message': 'Success'},
        )


from django.http import HttpResponse, Http404
from django.shortcuts import get_object_or_404
from django.conf import settings
import os
from .models import User

def user_image(request, tag):
    try:
        user = get_object_or_404(User, tag=tag)
        if user.is_hidden:
            raise Exception
        
        # Check if user has a profile picture
        if user.profile_picture:
            # Open the image file
            image_path = user.profile_picture.path
            with open(image_path, 'rb') as f:
                response = HttpResponse(f.read(), content_type="image/png")  # Adjust content_type if needed
            return response
        
        # Serve default image if no profile picture
        print((settings.BASE_DIR, 'images', 'default_profile.png'))
        default_image_path = os.path.join(settings.BASE_DIR, 'chat', 'static', 'images', 'default_profile.png')
        with open(default_image_path, 'rb') as f:
            response = HttpResponse(f.read(), content_type="image/png")
        return response
    
    except Exception as e:
        # Fallback to default image if any error occurs
        default_image_path = os.path.join(settings.BASE_DIR, 'chat', 'static', 'images', 'default_profile.png')
        with open(default_image_path, 'rb') as f:
            response = HttpResponse(f.read(), content_type="image/png")
        return response



from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import User
from rest_framework.decorators import api_view
import base64


@api_view(['POST'])
@authentication_classes([])
@permission_classes([])   
def update_profile_picture(request):
    required_fields = ['tag', 'token', 'image']
    
    if not all(field in request.data for field in required_fields):
        return JsonResponse(
            {'status': 'error', 'message': 'Missing required fields'},
            status=400
        )
    
    tag = request.data['tag']
    token = request.data['token']
    image_data = request.data['image']
    
    # Verify user authentication
    try:
        if not is_authorized(tag, token):
            return JsonResponse(
                {'status': 'error', 'message': 'Token expired'},
                status=401
            )
    except User.DoesNotExist:
        return JsonResponse(
            {'status': 'error', 'message': 'User not found'},
            status=404
        )
    except Token.DoesNotExist:
        return JsonResponse(
            {'status': 'error', 'message': 'Invalid token'},
            status=401
        )
    
    try:
        # Get the user
        user = User.objects.get(tag=tag)
        
        # If there's an existing profile picture, delete it
        if user.profile_picture:
            user.profile_picture.delete(save=False)
        
        # Decode base64 image
        if ',' in image_data:
            # Handle data URL format (e.g., "data:image/png;base64,...")
            image_data = image_data.split(',')[1]
        
        # Convert base64 to file
        import io
        from django.core.files.images import ImageFile
        
        # Decode the base64 string
        image_bytes = base64.b64decode(image_data)
        image_file = io.BytesIO(image_bytes)
        
        # Save the image to the user's profile
        filename = f"profile_{tag}.png"
        user.profile_picture.save(filename, ImageFile(image_file), save=True)
        
        return JsonResponse({
            'status': 'success',
            'message': 'Profile picture updated successfully',
            'image_url': request.build_absolute_uri(user.profile_picture.url)
        })
        
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': f'Failed to update profile picture: {str(e)}',
        }, status=500)


from django.http import JsonResponse
from django.db.models import Count, Q
from .models import User, Message, Token
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view

@api_view(['GET'])
def get_user_stats(request, tag, token):
    try:
        # Verify user authentication
        if not is_authorized(tag, token):
            return Response(
                {'status': 'error', 'message': 'Token expired'},
                status=status.HTTP_401_UNAUTHORIZED
            )
    except User.DoesNotExist:
        return Response(
            {'status': 'error', 'message': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Token.DoesNotExist:
        return Response(
            {'status': 'error', 'message': 'Invalid token'},
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    user = User.objects.get(tag=tag)
    
    # Count messages sent by the user
    sent_count = Message.objects.filter(sender=user).count()
    
    # Count messages received by the user
    received_count = Message.objects.filter(receiver=user).count()
    
    # Count unique people the user has talked to (excluding themselves)
    people_talked_to = set()
    
    # Add all users who received messages from this user
    senders = Message.objects.filter(sender=user).values_list('receiver__tag', flat=True).distinct()
    people_talked_to.update(senders)
    
    # Add all users who sent messages to this user
    receivers = Message.objects.filter(receiver=user).values_list('sender__tag', flat=True).distinct()
    people_talked_to.update(receivers)
    
    # Remove the user themselves from the count if present
    if tag in people_talked_to:
        people_talked_to.remove(tag)
    
    return JsonResponse({
        'status': 'success',
        'statistics': {
            'unique_contacts': len(people_talked_to),
            'messages_sent': sent_count or 0,
            'messages_received': received_count or 0,
            'total_messages': (sent_count + received_count) or 0
        }
    })