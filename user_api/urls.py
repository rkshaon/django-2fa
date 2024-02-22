from django.urls import path

from user_api import views



urlpatterns = [
    # path('2fa-qr-code', views.APIQRView.as_view()),
    path('2fa-qr-code', views.TFASetupView.as_view(), name='2fa-qr-code')
]