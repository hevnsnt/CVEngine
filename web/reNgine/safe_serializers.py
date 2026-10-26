from django.contrib.auth import get_user_model
from rest_framework import serializers


class UserNameOnly(serializers.ModelSerializer):
	class Meta:
		model = get_user_model()
		fields = ['username']


class SafeModelSerializer(serializers.ModelSerializer):
	"""A ModelSerializer that never expands a user. ``depth`` turns every foreign key into a nested copy of the whole row, and a user's
	row holds the password hash, the e-mail address and the permission flags: a serializer that reaches a user (a finding's ``assignee``
	or ``remediation_by``, a scan's ``initiated_by``) returns the username only."""

	def build_nested_field(self, field_name, relation_info, nested_depth):
		if relation_info.related_model is get_user_model():
			return UserNameOnly, {'read_only': True}
		return super().build_nested_field(field_name, relation_info, nested_depth)
