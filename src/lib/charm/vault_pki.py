import charmhelpers.contrib.network.ip as ch_ip
import charmhelpers.core.hookenv as hookenv

from . import vault

CHARM_PKI_MP = "charm-pki-local"


def configure_pki_backend(client, name, ttl=None):
    """Ensure a pki backend is enabled

    :param client: Vault client
    :type client: hvac.Client
    :param name: Name of backend to enable
    :type name: str
    :param ttl: TTL
    :type ttl: str
    """
    if not vault.is_backend_mounted(client, name):
        client.enable_secret_backend(
            backend_type='pki',
            description='Charm created PKI backend',
            mount_point=name,
            # Default ttl to 1 Year
            config={'max-lease-ttl': ttl or '87600h'})


def is_ca_ready(client, name):
    """Check if CA is ready for use

    :returns: Whether CA is ready
    :rtype: bool
    """
    return client.read('charm-pki-local/roles/local') is not None


def get_chain(name=None):
    """Check if CA is ready for use

    :returns: Whether CA is ready
    :rtype: bool
    """
    client = vault.get_local_client()
    if not name:
        name = CHARM_PKI_MP
    return client.read('{}/cert/ca_chain'.format(name))['data']['certificate']


def get_ca():
    """Check if CA is ready for use

    :returns: Whether CA is ready
    :rtype: bool
    """
    return hookenv.leader_get('root-ca')


def create_server_certificate(cn, ip_sans=None, alt_names=None):
    """Create a certificate and key for the given cn inc sans if requested

    :param cn: Common name to use for certifcate
    :type cn: string
    :param ip_sans: List of IP address to create san records for
    :type ip_sans: [str1,...]
    :param alt_names: List of names to create san records for
    :type alt_names: [str1,...]
    :raises: vault.VaultNotReady
    :returns: The newly created cert, issuing ca and key
    :rtype: tuple
    """
    client = vault.get_local_client()
    configure_pki_backend(client, CHARM_PKI_MP)
    if is_ca_ready(client, CHARM_PKI_MP):
        config = {
            'common_name': cn}
        if ip_sans:
            config['ip_sans'] = ','.join(ip_sans)
        if alt_names:
            config['alt_names'] = ','.join(alt_names)
        bundle = client.write(
            '{}/issue/local'.format(CHARM_PKI_MP),
            **config)['data']
    else:
        raise vault.VaultNotReady("CA not ready")
    return bundle


def get_csr(ttl=None, country=None, province=None,
            organization=None, organizational_unit=None):
    """Generate a csr for the vault Intermediate Authority

    Depending on the configuration of the CA signing this CR some of the
    fields embedded in the CSR may have to match the CA.

    :param ttl: TTL
    :type ttl: string
    :param country: The C (Country) values in the subject field of the CSR
    :type country: string
    :param province: The ST (Province) values in the subject field of the CSR.
    :type province: string
    :param organization: The O (Organization) values in the subject field of
                         the CSR
    :type organization: string
    :param organizational_unit: The OU (OrganizationalUnit) values in the
                                subject field of the CSR.
    :type organizational_unit: string
    :returns: Certificate signing request
    :rtype: string
    """
    client = vault.get_local_client()
    if not vault.is_backend_mounted(client, CHARM_PKI_MP):
        configure_pki_backend(client, CHARM_PKI_MP)
    config = {
        'common_name': ("Vault Intermediate Certificate Authority "
                        "({})".format(CHARM_PKI_MP)),
        #  Year - 1 hour
        'ttl': ttl or '87599h',
        'country': country,
        'province': province,
        'ou': organizational_unit,
        'organization': organization}
    config = {k: v for k, v in config.items() if v}
    csr_info = client.write(
        '{}/intermediate/generate/internal'.format(CHARM_PKI_MP),
        **config)
    return csr_info['data']['csr']


def upload_signed_csr(pem, allowed_domains, allow_subdomains=True,
                      enforce_hostnames=False, allow_any_name=True,
                      max_ttl=None):
    """Upload signed csr to intermediate pki

    :param pem: signed csr in pem format
    :type pem: string
    :param allow_subdomains: Specifies if clients can request certificates with
                             CNs that are subdomains of the CNs:
    :type allow_subdomains: bool
    :param enforce_hostnames: Specifies if only valid host names are allowed
                              for CNs, DNS SANs, and the host part of email
                              addresses.
    :type enforce_hostnames: bool
    :param allow_any_name: Specifies if clients can request any CN
    :type allow_any_name: bool
    :param max_ttl: Specifies the maximum Time To Live
    :type max_ttl: str
    """
    client = vault.get_local_client()
    # Set the intermediate certificate authorities signing certificate to the
    # signed certificate.
    # (hvac module doesn't expose a method for this, hence the _post call)
    client._post(
        'v1/{}/intermediate/set-signed'.format(CHARM_PKI_MP),
        json={'certificate': pem})
    # Generated certificates can have the CRL location and the location of the
    # issuing certificate encoded.
    addr = vault.get_access_address()
    client.write(
        '{}/config/urls'.format(CHARM_PKI_MP),
        issuing_certificates="{}/v1/{}/ca".format(addr, CHARM_PKI_MP),
        crl_distribution_points="{}/v1/{}/crl".format(addr, CHARM_PKI_MP)
    )
    # Configure a role which maps to a policy for accessing this pki
    if not max_ttl:
        max_ttl = '87598h'
    client.write(
        '{}/roles/local'.format(CHARM_PKI_MP),
        allowed_domains=allowed_domains,
        allow_subdomains=allow_subdomains,
        enforce_hostnames=enforce_hostnames,
        allow_any_name=allow_any_name,
        max_ttl=max_ttl)


def sort_sans(sans):
    """Split SANS into IP sans and name SANS

    :param sans: List of SANS
    :type sans: list
    :returns: List of IP sans and list of Name SANS
    :rtype: ([], [])
    """
    ip_sans = {s for s in sans if ch_ip.is_ip(s)}
    alt_names = set(sans).difference(ip_sans)
    return sorted(list(ip_sans)), sorted(list(alt_names))
