from django.urls import path

from user_api import views



urlpatterns = [
    path('2fa-qr-code', views.TFASetupView.as_view(), name='2fa-qr-code'),
    path('2fa-qr-code/disable', views.TFADisableView.as_view(), name='2fa-qr-code-disable')
]