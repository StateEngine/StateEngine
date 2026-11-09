"""Counterexamples for uncertainty and service-incarnation acceptance checks."""
import copy
import unittest

from secode_external import acceptance, capabilities, service_identity


class ReadbackChecks(unittest.TestCase):
    def setUp(self):
        self.service = {'incarnation': 'one-lifetime', 'serviceInstance': 'private',
                        'generation': 0, 'registrationVersion': '0.1.0'}
        self.reply = {'service': self.service, 'data': {
            'id': 'msg_original', 'sessionID': 'ses_original', 'text': 'Original input',
            'admittedSeq': 1, 'delivery': 'queue', 'metadata': {'origin': 'seat-startup'}}}

    def read(self, value):
        return acceptance(value, self.service, 'ses_original', 'msg_original', 'Original input')

    def test_configured_generation_zero_is_valid_but_not_a_service_incarnation(self):
        self.assertEqual(service_identity(self.reply), self.service)
        self.assertEqual(self.read(self.reply)['id'], 'msg_original')
        changed = copy.deepcopy(self.reply)
        changed['service']['incarnation'] = 'another-lifetime'
        with self.assertRaisesRegex(RuntimeError, 'changed service incarnation'):
            self.read(changed)

    def test_absent_acceptance_is_uncertain_and_never_resend_permission(self):
        for value in (None,):
            with self.assertRaisesRegex(RuntimeError, 'uncertain input must not be replayed'):
                self.read({**self.reply, 'data': value})

    def test_same_key_does_not_authorize_changed_prompt_session_or_delivery(self):
        for field, value in (('sessionID', 'ses_other'), ('text', 'Replacement input'),
                             ('id', 'msg_replacement'), ('delivery', 'execute'),
                             ('metadata', {}), ('admittedSeq', True), ('admittedSeq', 0)):
            changed = copy.deepcopy(self.reply)
            changed['data'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(RuntimeError):
                self.read(changed)

    def test_partial_unreadable_or_boolean_generation_is_not_a_measured_zero(self):
        for value in (None, True, -1, '0'):
            changed = copy.deepcopy(self.reply)
            changed['service']['generation'] = value
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                service_identity(changed)

    def test_missing_incarnation_cannot_be_replaced_by_the_configured_service_name(self):
        for field in ('incarnation', 'serviceInstance', 'registrationVersion'):
            changed = copy.deepcopy(self.reply)
            del changed['service'][field]
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                service_identity(changed)

    def test_bare_external_host_flag_does_not_prove_keyed_or_notice_support(self):
        with self.assertRaises(RuntimeError):
            capabilities({'schema': 'secode.external-host-capabilities.v1', 'external_host': True})


if __name__ == '__main__':
    unittest.main(verbosity=2)
