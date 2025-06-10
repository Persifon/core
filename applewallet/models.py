from django.db import models

class Pass(models.Model):
    # In this example, the serial number uniquely identifies a pass.
    serial_number = models.CharField(max_length=255, primary_key=True)
    pass_type_id = models.CharField(max_length=255)
    authentication_token = models.CharField(max_length=255)
    updated_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.serial_number