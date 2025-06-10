import hmac
import hashlib
from django.test import TestCase, Client
from django.urls import reverse
from django.conf import settings
import json

class WebhookSignatureTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.secret = getattr(settings, 'WEBHOOK_SECRET', 'dev_webhook_secret')
        self.url = reverse('webhook-receive')

    def _sign(self, payload: bytes) -> str:
        return hmac.new(self.secret.encode(), payload, hashlib.sha256).hexdigest()

    def test_valid_signature(self):
        data = {'event': 'test', 'value': 123}
        payload = json.dumps(data).encode()
        signature = self._sign(payload)
        response = self.client.post(self.url, data=payload, content_type='application/json', HTTP_X_SIGNATURE=signature)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Webhook received and verified', response.json().get('message', ''))

    def test_invalid_signature(self):
        data = {'event': 'test', 'value': 123}
        payload = json.dumps(data).encode()
        signature = 'bad' + self._sign(payload)[3:]
        response = self.client.post(self.url, data=payload, content_type='application/json', HTTP_X_SIGNATURE=signature)
        self.assertEqual(response.status_code, 400)
        self.assertIn('Invalid signature', response.json().get('error', ''))

    def test_missing_signature(self):
        data = {'event': 'test', 'value': 123}
        payload = json.dumps(data).encode()
        response = self.client.post(self.url, data=payload, content_type='application/json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('Missing X-Signature', response.json().get('error', ''))
