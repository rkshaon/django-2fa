from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import renderers
from two_factor.views import QRGeneratorView
from two_factor.views import SetupView

from io import BytesIO
import base64
from PIL import Image
from io import BytesIO

import base64
import qrcode
import secrets



def generate_image_from_base64(base64_string, output_filename):
    image_data = base64.b64decode(base64_string)
    image = Image.open(BytesIO(image_data))
    image.save(output_filename)


def generate_secret_key(length=20):
    secret_key = secrets.token_bytes(length)
    return base64.b32encode(secret_key).decode()


class TFASetupView(APIView):
    def get(self, request, *args, **kwargs):
        username = 'rkshaon'
        secret = generate_secret_key()
        account_label = f"{request.get_host()} {username}"
        otpauth_url = f'otpauth://totp/{account_label}?secret={secret}&digits=6&issuer={username}'

        # Generate QR code
        qr = qrcode.make(otpauth_url)

        # Convert image to base64
        buffered = BytesIO()
        qr.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode()

        # Save QR code image to file
        qr.save("qr_code.png")
        base64_string = qr_base64
        output_filename = f"{username}.png"
        
        generate_image_from_base64(base64_string, output_filename)

        return Response({'qr_code': qr_base64})