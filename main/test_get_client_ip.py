from django.test import TestCase, RequestFactory
from .utils import get_client_ip

class GetClientIpTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_get_client_ip_from_x_forwarded_for(self):
        request = self.factory.get('/')
        request.META['HTTP_X_FORWARDED_FOR'] = '203.0.113.1, 70.41.3.18, 150.172.238.178'
        ip = get_client_ip(request)
        self.assertEqual(ip, '203.0.113.1')

    def test_get_client_ip_from_remote_addr(self):
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '198.51.100.42'
        ip = get_client_ip(request)
        self.assertEqual(ip, '198.51.100.42')

    def test_get_client_ip_fallback(self):
        request = self.factory.get('/')
        # No IP headers set
        ip = get_client_ip(request)
        self.assertEqual(ip, '127.0.0.1')
