\
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .serealizers import POSAcquiringTransactionRequestSerializer, TransactionDetailSerializer # Corrected typo: serealizers -> serializers
from .permissions import IsPOSTerminal
from .services import POSService # Import the POSService
import logging # Import logging

logger = logging.getLogger(__name__) # Initialize logger

class POSAcquiringView(APIView):
    """
    API view for POS terminals to submit acquiring transactions.
    Uses POSService to handle business logic.
    """
    permission_classes = [IsPOSTerminal]

    def post(self, request, *args, **kwargs):
        serializer = POSAcquiringTransactionRequestSerializer(data=request.data)
        if not serializer.is_valid():
            logger.warning("Invalid POS acquiring request: %s from %s", serializer.errors, request.META.get('REMOTE_ADDR'))
            return Response({
                'error': 'Invalid request data.',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        validated_data = serializer.validated_data
        pos_terminal = getattr(request, 'pos_terminal', None)

        if not pos_terminal: # Safeguard, IsPOSTerminal should prevent this
            api_key_info = getattr(request, 'api_key_object', None)
            logger.error("POS Terminal not identified in POSAcquiringView. API Key: %s", api_key_info)
            return Response({'error': 'POS Terminal not identified or not active.'}, status=status.HTTP_403_FORBIDDEN)

        merchant_account = pos_terminal.merchant_account

        try:
            new_transaction = POSService.acquire_transaction(
                validated_data=validated_data,
                merchant_account=merchant_account,
                pos_terminal=pos_terminal
            )
            
            response_serializer = TransactionDetailSerializer(new_transaction)
            logger.info("POS transaction %s successfully acquired for terminal %s", new_transaction.id, pos_terminal.terminal_id_code)
            return Response({
                'message': 'POS transaction acquired successfully.',
                'data': response_serializer.data
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            terminal_id_for_log = pos_terminal.terminal_id_code if pos_terminal else "Unknown"
            logger.error("Error processing POS transaction for terminal %s: %s", terminal_id_for_log, str(e), exc_info=True)
            return Response({
                'error': 'Failed to process POS transaction.',
                'details': 'An internal error occurred.' # Generic error for production
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

