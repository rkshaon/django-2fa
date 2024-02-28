from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import renderers
from rest_framework import status
from two_factor.views import QRGeneratorView
from two_factor.views import SetupView

from io import BytesIO
import base64
from PIL import Image
from io import BytesIO
import urllib.parse
from urllib.parse import quote

import pyotp
import base64
import qrcode
import secrets
import binascii
import re

from django.contrib.auth.models import User
from django_otp.plugins.otp_totp.models import TOTPDevice



def generate_image_from_base64(base64_string, output_filename):
    image_data = base64.b64decode(base64_string)
    image = Image.open(BytesIO(image_data))
    image.save(output_filename)


def generate_secret_key(length=20, encoded=False):
    secret_key = secrets.token_bytes(length)
    # return b'\xb5\xde\x93\x7f\x15\xd7\x9f\xadX{\xe5\xac\\P\xf6#\xb1$J\xf9'
    # return "LPGTHBSQCOFJC45VPEKJFSRBVOWBGJNG"    
    secret_key = "RUFFGUERPVIP6JCOGMYTU7U6Y7H7XUTN"

    # Remove any non-hexadecimal characters from the string
    hex_string = re.sub(r'[^a-fA-F0-9]', '', secret_key)

    # If the length of the hex string is odd, pad it with a leading zero
    if len(hex_string) % 2 != 0:
        hex_string = "0" + hex_string

    bytes_string = bytes.fromhex(hex_string)

    return secret_key
    if encoded:
        print(f"1. secret_key: {secret_key}, type: {type(secret_key)}")
        secret_key = secret_key.encode('utf-8')
        # print(f"2. secret_key: {secret_key}, type: {type(secret_key)}")
        # secret_key = binascii.hexlify(secret_key).decode("utf-8")
        # print(f"3. secret_key: {secret_key}, type: {type(secret_key)}")
        return secret_key
    else:
        return secret_key

    # print(secret_key, type(secret_key))
    secret_key = base64.b32encode(secret_key).decode()
    # print(secret_key, type(secret_key))
    return secret_key


def verify_otp(secret, otp_value):
    totp = pyotp.TOTP(secret)

    return totp.verify(otp_value)


class TFASetupView(APIView):
    def get(self, request, *args, **kwargs):
        username = 'rkshaon'
        secret = generate_secret_key()
        secret = re.sub(r'[^a-fA-F0-9]', '', secret)
        
        if len(secret) % 2 != 0:
            secret = "0" + secret

        secret = bytes.fromhex(secret)
        secret = base64.b64encode(secret).decode()
        secret = secret.encode('utf-8')
        secret = secret.hex()
        secret = bytes.fromhex(secret).decode('utf-8')
        secret = base64.b32encode(secret.encode('utf-8'))
        secret = secret.decode('utf-8')
        secret = urllib.parse.quote(secret, safe='')
        
        otpauth_url = f"otpauth://totp/{username}?secret={secret}&algorithm=SHA1&digits=6&period=30"

        qr = qrcode.make(otpauth_url)
        buffered = BytesIO()
        qr.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode()
        qr.save(f"{username}.png")
        base64_string = qr_base64
        output_filename = f"{username}.png"
        
        generate_image_from_base64(base64_string, output_filename)

        return Response({'qr_code': qr_base64})
    
    def post(self, request, *args, **kwargs):
        username = 'rkshaon'
        user = User.objects.get(username=username)
        secret = generate_secret_key()
        otp_value = request.data.get('otp')
        secret = re.sub(r'[^a-fA-F0-9]', '', secret)
        
        if len(secret) % 2 != 0:
            secret = "0" + secret

        secret = bytes.fromhex(secret)
        secret = base64.b64encode(secret).decode()
        secret = secret.encode('utf-8')
        secret = secret.hex()
        v_secret = secret

        if len(v_secret) % 2 != 0:
            v_secret = "0" + v_secret

        v_secret = bytes.fromhex(v_secret)
        v_secret = base64.b32encode(v_secret)
        v_secret = v_secret.decode('utf-8')
        
        otp_verified = verify_otp(v_secret, otp_value)

        if otp_verified:
            device = TOTPDevice.objects.create(user=user, name=username, confirmed=True, key=secret)
            device.save()
            return Response({'message': 'OTP verification successful.'})
        else:
            return Response({'message': 'OTP verification failed.'}, status=status.HTTP_400_BAD_REQUEST)


class TFADisableView(APIView):
    def post(self, request, *args, **kwargs):
        user = User.objects.get(username='rkshaon')
        devices = TOTPDevice.objects.filter(user=user)

        for device in devices:
            device.delete()

        return Response({'message': '2FA disabled.'})
    

class TFALoginView(APIView):
    def post(self, request, *args, **kwargs):
        user = User.objects.get(username='rkshaon')
        devices = TOTPDevice.objects.filter(user=user)
        otp_value = request.data.get('otp')
        otp_verified = False

        for device in devices:
            hex_string = device.key

            if len(hex_string) % 2 != 0:
                hex_string = "0" + hex_string

            bytes_string = bytes.fromhex(hex_string)
            bytes_string = base64.b32encode(bytes_string)            
            string = bytes_string.decode('utf-8')

            otp_verified = verify_otp(string, otp_value)

            if otp_verified:
                break

        if otp_verified:
            return Response({
                'status': True,
                'message': 'OTP verification successful.'
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'status': False,
                'message': 'OTP verification failed.'
            }, status=status.HTTP_400_BAD_REQUEST)