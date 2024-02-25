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
    secret_key = "LPGTHBSQCOFJC45VPEKJFSRBVOWBGJNA"

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
        account_label = f"{request.get_host()} {username}"
        otpauth_url = f'otpauth://totp/{account_label}?secret={secret}&digits=6&issuer={username}'
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
        secret = generate_secret_key(encoded=True)        
        otp_value = request.data.get('otp')
        otp_verified = verify_otp(secret, otp_value)

        # Remove any non-hexadecimal characters from the string
        hex_string = re.sub(r'[^a-fA-F0-9]', '', secret)

        # If the length of the hex string is odd, pad it with a leading zero
        if len(hex_string) % 2 != 0:
            hex_string = "0" + hex_string

        bytes_string = bytes.fromhex(hex_string)
        secret = base64.b32encode(bytes_string).decode()
        secret = secret.encode('utf-8')
        secret = secret.hex()

        if otp_verified:
            device = TOTPDevice.objects.create(user=request.user, name=username, confirmed=True, key=secret)
            device.save()
            return Response({'message': 'OTP verification successful.'})
        else:
            return Response({'message': 'OTP verification failed.'}, status=status.HTTP_400_BAD_REQUEST)


class TFADisableView(APIView):
    def post(self, request, *args, **kwargs):
        user = User.objects.get(username='admin')
        devices = TOTPDevice.objects.filter(user=user)

        for device in devices:
            device.delete()
            
        return Response({'message': '2FA disabled.'})