from rest_framework import serializers

from reNgine.safe_serializers import SafeModelSerializer
from targetApp.models import *


class HistoricalIPSerializer(SafeModelSerializer):
    class Meta:
        model = HistoricalIP
        fields = ['ip', 'location', 'owner', 'last_seen']


class RelatedDomainSerializer(SafeModelSerializer):
    class Meta:
        model = RelatedDomain
        fields = '__all__'


class NameServersSerializer(SafeModelSerializer):
    class Meta:
        model = NameServer
        fields = ['name']


class DomainRegistrarSerializer(SafeModelSerializer):
    class Meta:
        model = Registrar
        fields = ['name', 'phone', 'email', 'url']


class DomainRegistrationSerializer(SafeModelSerializer):
    class Meta:
        model = DomainRegistration
        fields = [
            'name',
            'organization',
            'address',
            'city',
            'state',
            'zip_code',
            'country',
            'email',
            'phone',
            'fax'
        ]

class DomainWhoisStatusSerializer(SafeModelSerializer):
    class Meta:
        model = WhoisStatus
        fields = ['name']


class DomainDNSRecordSerializer(SafeModelSerializer):
    class Meta:
        model = DNSRecord
        fields = ['name', 'type']
