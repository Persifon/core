import secrets
from django.http import JsonResponse, HttpRequest
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache  # or use your own DB/session storage

# Example TTL for payloads if using Django's cache (in seconds)
DEFAULT_PAYLOAD_TTL = 300  # 5 minutes

@csrf_exempt
def generate_payload(request: HttpRequest):
    """
    Generates a random payload (nonce) and associates it with the user's
    public TON address. The user will sign this payload on the client side
    and send back the signature to the verify endpoint.
    """
    if request.method == "GET":
        public_address = request.GET.get("public_address")
        if not public_address:
            return JsonResponse({"error": "Missing public_address."}, status=400)
        
        # Generate a random payload (nonce)
        payload = secrets.token_hex(16)  # 32-character hex string

        # Store the payload in a short-term cache or database keyed by public_address
        # In production, consider something more robust (i.e. storing multiple nonces
        # in case user tries multiple sign attempts, or using session-based approach, etc.)
        cache_key = f"ton_nonce_{public_address}"
        cache.set(cache_key, payload, timeout=DEFAULT_PAYLOAD_TTL)

        return JsonResponse({
            "message": "ok",
            "payload": payload
        }, status=201)
    
    return JsonResponse({"error": "Method not allowed"}, status=405)


@csrf_exempt
def verify_signature(request: HttpRequest):
    """
    Verifies a signature for a given payload (nonce) against the user's
    public TON address.
    """
    if request.method == "POST":
        data = request.POST or request.json if hasattr(request, 'json') else {}
        public_address = data.get("public_address")
        signature = data.get("signature")

        if not public_address or not signature:
            return JsonResponse({"error": "Missing required parameters."}, status=400)
        
        # Retrieve the original payload from cache/db
        cache_key = f"ton_nonce_{public_address}"
        original_payload = cache.get(cache_key)
        if not original_payload:
            return JsonResponse({"error": "No payload found or it has expired."}, status=400)

        # ----
        #  Perform actual TON cryptographic verification here
        #  The code below is placeholder logic. You must replace it with
        #  proper verification using your TON library or cryptographic method.
        # ----

        # Example of pseudo-verification function
        if _mock_verify_ton_signature(public_address, signature, original_payload):
            # If valid, you may choose to remove the used payload from cache
            cache.delete(cache_key)
            return JsonResponse({"message": "Signature valid!"}, status=200)
        else:
            return JsonResponse({"error": "Invalid signature."}, status=400)

    return JsonResponse({"error": "Method not allowed"}, status=405)


def _mock_verify_ton_signature(public_address: str, signature: str, payload: str) -> bool:
    """
    This function is a placeholder. Replace it with actual crypto-based 
    signature checks, potentially using a TON library or direct cryptographic 
    primitives that TON uses.
    """
    # For example, you'd do something like:
    # 1. Derive the public key from `public_address`.
    # 2. Convert signature and payload to bytes.
    # 3. Use an ECDSA or relevant scheme to validate the signature.
    #
    # Here, we're faking a pass/fail check:
    return signature.endswith(payload[-4:])