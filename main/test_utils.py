from django.test import TestCase
from . import utils

class UtilsTests(TestCase):
    def test_format_currency(self):
        self.assertEqual(utils.format_currency(123.456), 'USD 123.46')
        self.assertEqual(utils.format_currency(0, 'EUR'), 'EUR 0.00')
        self.assertEqual(utils.format_currency(99.9, 'JPY'), 'JPY 99.90')

    def test_truncate_string(self):
        self.assertEqual(utils.truncate_string('short', 10), 'short')
        self.assertEqual(utils.truncate_string('this is a long string', 10), 'this is...')
        self.assertEqual(utils.truncate_string('', 5), '')
        self.assertEqual(utils.truncate_string('abc', 3), 'abc')
        self.assertEqual(utils.truncate_string('abcdef', 3), '...')

    def test_safe_get_value(self):
        d = {'a': 1, 'b': 2}
        self.assertEqual(utils.safe_get_value(d, 'a'), 1)
        self.assertEqual(utils.safe_get_value(d, 'c', 99), 99)
        self.assertIsNone(utils.safe_get_value(None, 'a'))
        self.assertIsNone(utils.safe_get_value(123, 'a'))

    def test_verify_webhook_signature(self):
        payload = b'{"test": 123}'
        secret = 'mysecret'
        correct_sig = utils.hmac.new(secret.encode(), payload, utils.hashlib.sha256).hexdigest()
        self.assertTrue(utils.verify_webhook_signature(payload, correct_sig, secret))
        self.assertFalse(utils.verify_webhook_signature(payload, 'bad' + correct_sig[3:], secret))
