import mock
from unittest.mock import patch

import lib.charm.vault_pki as vault_pki
import unit_tests.test_utils


class TestLibCharmVaultPKI(unit_tests.test_utils.CharmTestCase):

    def setUp(self):
        super(TestLibCharmVaultPKI, self).setUp()
        self.obj = vault_pki
        self.patches = []
        self.patch_all()

    @patch.object(vault_pki.vault, 'is_backend_mounted')
    def test_configure_pki_backend(self, is_backend_mounted):
        client_mock = mock.MagicMock()
        is_backend_mounted.return_value = False
        vault_pki.configure_pki_backend(
            client_mock,
            'my_backend',
            ttl=42)
        client_mock.enable_secret_backend.assert_called_once_with(
            backend_type='pki',
            config={'max-lease-ttl': 42},
            description='Charm created PKI backend',
            mount_point='my_backend')

    @patch.object(vault_pki.vault, 'is_backend_mounted')
    def test_configure_pki_backend_default_ttl(self, is_backend_mounted):
        client_mock = mock.MagicMock()
        is_backend_mounted.return_value = False
        vault_pki.configure_pki_backend(
            client_mock,
            'my_backend')
        client_mock.enable_secret_backend.assert_called_once_with(
            backend_type='pki',
            config={'max-lease-ttl': '87600h'},
            description='Charm created PKI backend',
            mount_point='my_backend')

    @patch.object(vault_pki.vault, 'is_backend_mounted')
    def test_configure_pki_backend_noop(self, is_backend_mounted):
        client_mock = mock.MagicMock()
        is_backend_mounted.return_value = True
        vault_pki.configure_pki_backend(
            client_mock,
            'my_backend',
            ttl=42)
        self.assertFalse(client_mock.enable_secret_backend.called)

    def test_is_ca_ready(self):
        client_mock = mock.MagicMock()
        vault_pki.is_ca_ready(client_mock, 'my_backend')
        client_mock.read.assert_called_once_with('my_backend/cert/crl')

    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_chain(self, get_local_client):
        client_mock = mock.MagicMock()
        client_mock.read.return_value = {
            'data': {
                'certificate': 'somecert'}}
        get_local_client.return_value = client_mock
        self.assertEqual(
            vault_pki.get_chain('my_backend'),
            'somecert')
        client_mock.read.assert_called_once_with(
            'my_backend/cert/ca_chain')

    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_chain_default_pki(self, get_local_client):
        client_mock = mock.MagicMock()
        client_mock.read.return_value = {
            'data': {
                'certificate': 'somecert'}}
        get_local_client.return_value = client_mock
        self.assertEqual(
            vault_pki.get_chain(),
            'somecert')
        client_mock.read.assert_called_once_with(
            'charm-pki-local/cert/ca_chain')

    @patch.object(vault_pki.hookenv, 'leader_get')
    def test_get_ca(self, leader_get):
        leader_get.return_value = 'ROOTCA'
        self.assertEqual(vault_pki.get_ca(), 'ROOTCA')

    @patch.object(vault_pki, 'is_ca_ready')
    @patch.object(vault_pki, 'configure_pki_backend')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_create_server_certificate(self, get_local_client,
                                       configure_pki_backend, is_ca_ready):
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        is_ca_ready.return_value = True
        vault_pki.create_server_certificate('bob.example.com')
        client_mock.write.assert_called_once_with(
            'charm-pki-local/issue/local',
            common_name='bob.example.com'
        )

    @patch.object(vault_pki, 'is_ca_ready')
    @patch.object(vault_pki, 'configure_pki_backend')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_create_server_certificate_sans(self, get_local_client,
                                            configure_pki_backend,
                                            is_ca_ready):
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        is_ca_ready.return_value = True
        vault_pki.create_server_certificate(
            'bob.example.com',
            ip_sans=['10.10.10.10', '192.197.45.23'],
            alt_names=['localunit', 'public.bob.example.com'])
        client_mock.write.assert_called_once_with(
            'charm-pki-local/issue/local',
            alt_names='localunit,public.bob.example.com',
            common_name='bob.example.com',
            ip_sans='10.10.10.10,192.197.45.23'
        )

    @patch.object(vault_pki.vault, 'is_backend_mounted')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_csr(self, get_local_client, is_backend_mounted):
        is_backend_mounted.return_value = True
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        client_mock.write.return_value = {
            'data': {
                'csr': 'somecert'}}
        self.assertEqual(vault_pki.get_csr(), 'somecert')
        client_mock.write.assert_called_once_with(
            'charm-pki-local/intermediate/generate/internal',
            common_name=('Vault Intermediate Certificate Authority'
                         ' (charm-pki-local)'),
            ttl='87599h')

    @patch.object(vault_pki, 'configure_pki_backend')
    @patch.object(vault_pki.vault, 'is_backend_mounted')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_csr_config_backend(self, get_local_client, is_backend_mounted,
                                    configure_pki_backend):
        is_backend_mounted.return_value = False
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        client_mock.write.return_value = {
            'data': {
                'csr': 'somecert'}}
        self.assertEqual(vault_pki.get_csr(), 'somecert')
        client_mock.write.assert_called_once_with(
            'charm-pki-local/intermediate/generate/internal',
            common_name=('Vault Intermediate Certificate Authority'
                         ' (charm-pki-local)'),
            ttl='87599h')
        configure_pki_backend.assert_called_once_with(
            client_mock,
            'charm-pki-local')

    @patch.object(vault_pki.vault, 'is_backend_mounted')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_get_csr_explicit(self, get_local_client, is_backend_mounted):
        is_backend_mounted.return_value = False
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        client_mock.write.return_value = {
            'data': {
                'csr': 'somecert'}}
        self.assertEqual(
            vault_pki.get_csr(
                ttl='2h',
                country='GB',
                province='Kent',
                organizational_unit='My Department',
                organization='My Company'),
            'somecert')
        client_mock.write.assert_called_once_with(
            'charm-pki-local/intermediate/generate/internal',
            common_name=('Vault Intermediate Certificate Authority '
                         '(charm-pki-local)'),
            country='GB',
            organization='My Company',
            ou='My Department',
            province='Kent',
            ttl='2h')

    @patch.object(vault_pki.vault, 'get_access_address')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_upload_signed_csr(self, get_local_client, get_access_address):
        get_access_address.return_value = 'https://vault.local:8200'
        client_mock = mock.MagicMock()
        get_local_client.return_value = client_mock
        local_url = 'https://vault.local:8200/v1/charm-pki-local'
        write_calls = [
            mock.call(
                'charm-pki-local/config/urls',
                issuing_certificates='{}/ca'.format(local_url),
                crl_distribution_points='{}/crl'.format(local_url)),
            mock.call(
                'charm-pki-local/roles/local',
                allowed_domains='exmaple.com',
                allow_subdomains=True,
                enforce_hostnames=False,
                allow_any_name=True,
                max_ttl='87598h')
        ]
        vault_pki.upload_signed_csr('MYPEM', 'exmaple.com')
        client_mock._post.assert_called_once_with(
            'v1/charm-pki-local/intermediate/set-signed',
            json={'certificate': 'MYPEM'})
        client_mock.write.assert_has_calls(write_calls)

    @patch.object(vault_pki.vault, 'get_access_address')
    @patch.object(vault_pki.vault, 'get_local_client')
    def test_upload_signed_csr_explicit(self, get_local_client,
                                        get_access_address):
        client_mock = mock.MagicMock()
        get_access_address.return_value = 'https://vault.local:8200'
        get_local_client.return_value = client_mock
        local_url = 'https://vault.local:8200/v1/charm-pki-local'
        write_calls = [
            mock.call(
                'charm-pki-local/config/urls',
                issuing_certificates='{}/ca'.format(local_url),
                crl_distribution_points='{}/crl'.format(local_url)),
            mock.call(
                'charm-pki-local/roles/local',
                allowed_domains='exmaple.com',
                allow_subdomains=False,
                enforce_hostnames=True,
                allow_any_name=False,
                max_ttl='42h')
        ]
        vault_pki.upload_signed_csr(
            'MYPEM',
            'exmaple.com',
            allow_subdomains=False,
            enforce_hostnames=True,
            allow_any_name=False,
            max_ttl='42h')
        client_mock._post.assert_called_once_with(
            'v1/charm-pki-local/intermediate/set-signed',
            json={'certificate': 'MYPEM'})
        client_mock.write.assert_has_calls(write_calls)

    def test_sort_sans(self):
        self.assertEqual(
            vault_pki.sort_sans([
                '10.0.0.10',
                '10.0.0.20',
                '10.0.0.10',
                'admin.local',
                'admin.local',
                'public.local']),
            (['10.0.0.10', '10.0.0.20'], ['admin.local', 'public.local']))
