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

# from otp_totp.models import 



def generate_image_from_base64(base64_string, output_filename):
    image_data = base64.b64decode(base64_string)
    image = Image.open(BytesIO(image_data))
    image.save(output_filename)


def generate_secret_key(length=20):
    secret_key = secrets.token_bytes(length)
    # return b'\xb5\xde\x93\x7f\x15\xd7\x9f\xadX{\xe5\xac\\P\xf6#\xb1$J\xf9'
    return "LPGTHBSQCOFJC45VPEKJFSRBVOWBGJNG"
    print(secret_key)
    return base64.b32encode(secret_key).decode()


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
        secret = generate_secret_key()
        otp_value = request.data.get('otp')
        otp_verified = verify_otp(secret, otp_value)

        if otp_verified:
            return Response({'message': 'OTP verification successful.'})
        else:
            return Response({'message': 'OTP verification failed.'}, status=status.HTTP_400_BAD_REQUEST)
