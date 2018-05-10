import base64
import psycopg2
import subprocess
import tenacity


from charmhelpers.contrib.charmsupport.nrpe import (
    NRPE,
    add_init_service_checks,
    get_nagios_hostname,
    get_nagios_unit_name,
)

from charmhelpers.core.hookenv import (
    DEBUG,
    ERROR,
    config,
    log,
    network_get_primary_address,
    open_port,
    status_set,
    unit_private_ip,
    application_version_set,
    atexit,
    local_unit,
)

from charmhelpers.core.host import (
    service,
    service_restart,
    service_running,
    write_file,
)

from charmhelpers.core.templating import (
    render,
)

from charms.reactive import (
    hook,
    is_state,
    remove_state,
    set_state,
    when,
    when_file_changed,
    when_not,
    when_any,
)

from charms.reactive.relations import (
    endpoint_from_flag,
)

from charms.reactive.flags import (
    is_flag_set,
    set_flag,
    clear_flag,
)

from charms.layer import snap

import lib.charm.vault as vault
import lib.charm.vault_pki as vault_pki

# See https://www.vaultproject.io/docs/configuration/storage/postgresql.html

VAULT_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS vault_kv_store (
  parent_path TEXT COLLATE "C" NOT NULL,
  path        TEXT COLLATE "C",
  key         TEXT COLLATE "C",
  value       BYTEA,
  CONSTRAINT pkey PRIMARY KEY (path, key)
);
"""

VAULT_INDEX_DDL = """
CREATE INDEX IF NOT EXISTS parent_path_idx ON vault_kv_store (parent_path);
"""


OPTIONAL_INTERFACES = [
    ['etcd'],
]
REQUIRED_INTERFACES = [
    ['shared-db', 'db.master']
]

VAULT_CONFIG = '/var/snap/vault/common/vault.hcl'
VAULT_SYSTEMD_CONFIG = '/etc/systemd/system/vault.service'


def ssl_available(config):
    if '' in (config['ssl-cert'], config['ssl-key']):
        return False
    return True


def save_etcd_client_credentials(etcd, key, cert, ca):
    """Save etcd TLS key, cert and ca to disk"""
    credentials = etcd.get_client_credentials()
    write_file(key, credentials['client_key'], perms=0o600)
    write_file(cert, credentials['client_cert'], perms=0o600)
    write_file(ca, credentials['client_ca'], perms=0o600)


def validate_snap_channel(channel):
    """Validate a provided snap channel

    Any prefix is ignored ('0.10' in '0.10/stable' for example).

    :param: channel: string of the snap channel to validate
    :returns: boolean: whether provided channel is valid
    """
    channel_suffix = channel.split('/')[-1]
    if channel_suffix not in ('stable', 'candidate', 'beta', 'edge'):
        return False
    return True


@when_not('snap.installed.vault')
def snap_install():
    channel = config('channel') or 'stable'
    if validate_snap_channel(channel):
        clear_flag('snap.channel.invalid')
        snap.install('vault', channel=channel)
    else:
        set_flag('snap.channel.invalid')


@when('config.changed.channel')
@when('snap.installed.vault')
def snap_refresh():
    channel = config('channel') or 'stable'
    if validate_snap_channel(channel):
        clear_flag('snap.channel.invalid')
        snap.refresh('vault', channel=channel)
        if vault.can_restart():
            log("Restarting vault", level=DEBUG)
            service_restart('vault')
            if config('auto-unlock'):
                vault.prepare_vault()
    else:
        set_flag('snap.channel.invalid')


def configure_vault(context):
    log("Running configure_vault", level=DEBUG)
    context['disable_mlock'] = config()['disable-mlock']
    context['ssl_available'] = is_state('vault.ssl.available')

    if is_flag_set('etcd.tls.available'):
        etcd = endpoint_from_flag('etcd.available')
        log("Etcd detected, adding to context", level=DEBUG)
        context['etcd_conn'] = etcd.connection_string()
        context['etcd_tls_ca_file'] = '/var/snap/vault/common/etcd-ca.pem'
        context['etcd_tls_cert_file'] = '/var/snap/vault/common/etcd-cert.pem'
        context['etcd_tls_key_file'] = '/var/snap/vault/common/etcd.key'
        save_etcd_client_credentials(etcd,
                                     key=context['etcd_tls_key_file'],
                                     cert=context['etcd_tls_cert_file'],
                                     ca=context['etcd_tls_ca_file'])
        context['api_addr'] = vault.get_api_url()
        context['cluster_addr'] = vault.get_cluster_url()
        log("Etcd detected, setting api_addr to {}".format(
            context['api_addr']))
    else:
        log("Etcd not detected", level=DEBUG)
    log("Rendering vault.hcl.j2", level=DEBUG)
    render(
        'vault.hcl.j2',
        VAULT_CONFIG,
        context,
        perms=0o600)
    log("Rendering vault systemd configuation", level=DEBUG)
    render(
        'vault.service.j2',
        VAULT_SYSTEMD_CONFIG,
        {},
        perms=0o644)
    service('enable', 'vault')
    log("Opening vault port", level=DEBUG)
    open_port(8200)
    set_flag('configured')


@when('snap.installed.vault')
@when('db.master.available')
@when('vault.schema.created')
@when('vault.ssl.configured')
def configure_vault_psql(psql):
    context = {
        'storage_name': 'psql',
        'psql_db_conn': psql.master,
    }
    configure_vault(context)


@when('snap.installed.vault')
@when('shared-db.available')
@when('vault.ssl.configured')
def configure_vault_mysql(mysql):
    if local_unit() not in mysql.allowed_units():
        log("Deferring vault configuration until"
            " MySQL access is granted", level=DEBUG)
        return
    context = {
        'storage_name': 'mysql',
        'mysql_db_relation': mysql,
    }
    configure_vault(context)


@when('config.changed.disable-mlock')
def disable_mlock_changed():
    remove_state('configured')


@hook('upgrade-charm')
def upgrade_charm():
    remove_state('configured')
    remove_state('vault.nrpe.configured')
    remove_state('vault.ssl.configured')


@when('db.connected')
def request_db(pgsql):
    pgsql.set_database('vault')


@when('shared-db.connected')
def mysql_setup(database):
    """Handle the default database connection setup
    """
    db = {
        'database': 'vault',
        'username': 'vault',
    }
    database.configure(**db)


@when('db.master.available')
@when_not('vault.schema.created')
def create_vault_table(pgsql):
    status_set('maintenance', 'connecting to database')
    conn = psycopg2.connect(str(pgsql.master))
    cur = conn.cursor()
    status_set('maintenance', 'creating vault table')
    cur.execute(VAULT_TABLE_DDL)
    status_set('maintenance', 'creating vault index')
    cur.execute(VAULT_INDEX_DDL)
    status_set('maintenance', 'committing database schema')
    conn.commit()
    cur.close()
    conn.close()
    set_state('vault.schema.created')
    status_set('active', 'database schema created and committed')


@when_not('db.master.available')
def database_not_ready():
    remove_state('vault.schema.created')


@when('snap.installed.vault')
@when_not('vault.ssl.configured')
def configure_ssl():
    c = config()
    if ssl_available(c):
        status_set('maintenance', 'installing SSL key and cert')
        ssl_key = base64.decodestring(c['ssl-key'].encode())
        write_file('/var/snap/vault/common/vault.key', ssl_key, perms=0o600)
        ssl_cert = base64.decodestring(c['ssl-cert'].encode())
        if c['ssl-chain']:
            ssl_cert = ssl_cert + base64.decodestring(c['ssl-chain'].encode())
        write_file('/var/snap/vault/common/vault.crt', ssl_cert, perms=0o600)
        set_state('vault.ssl.available')
    else:
        remove_state('vault.ssl.available')

    if c['ssl-ca']:
        ssl_ca = base64.decodestring(c['ssl-ca'].encode())
        write_file('/usr/local/share/ca-certificates/vault-ca.crt',
                   ssl_ca, perms=0o644)
        subprocess.check_call(['update-ca-certificates', '--fresh'])

    set_state('vault.ssl.configured')
    remove_state('configured')


@when('config.changed.ssl-cert')
def ssl_cert_changed():
    remove_state('vault.ssl.configured')


@when('config.changed.ssl-chain')
def ssl_chain_changed():
    remove_state('vault.ssl.configured')


@when('config.changed.ssl-key')
def ssl_key_changed():
    remove_state('vault.ssl.configured')


@when('config.changed.ssl-ca')
def ssl_ca_changed():
    remove_state('vault.ssl.configured')


@when('configured')
@when('nrpe-external-master.available')
@when_not('vault.nrpe.configured')
def update_nagios(svc):
    status_set('maintenance', 'configuring Nagios checks')
    hostname = get_nagios_hostname()
    current_unit = get_nagios_unit_name()
    nrpe = NRPE(hostname=hostname)
    add_init_service_checks(nrpe, ['vault'], current_unit)
    write_file(
        '/usr/lib/nagios/plugins/check_vault_version.py',
        open('files/nagios/check_vault_version.py', 'rb').read(),
        perms=0o755)
    nrpe.add_check(
        'vault_version',
        'Check running vault server version is same as installed snap',
        '/usr/lib/nagios/plugins/check_vault_version.py',
    )
    nrpe.write()
    set_state('vault.nrpe.configured')


@when('config.changed.nagios_context')
def nagios_context_changed():
    remove_state('vault.nrpe.configured')


@when('config.changed.nagios_servicegroups')
def nagios_servicegroups_changed():
    remove_state('vault.nrpe.configured')


@when('ha.connected')
def cluster_connected(hacluster):
    """Configure HA resources in corosync"""
    vip = config('vip')
    dns_record = config('dns-ha-access-record')
    if vip and dns_record:
        set_flag('config.dns_vip.invalid')
        log("Unsupported configuration. vip and dns-ha cannot both be set",
            level=ERROR)
        return
    else:
        clear_flag('config.dns_vip.invalid')
    if vip:
        hacluster.add_vip('vault', vip)
    elif dns_record:
        try:
            ip = network_get_primary_address('access')
        except NotImplementedError:
            ip = unit_private_ip()
        hacluster.add_dnsha('vault', ip, dns_record, 'access')
    hacluster.bind_resources()


@when_file_changed(VAULT_CONFIG, VAULT_SYSTEMD_CONFIG)
def file_change_auto_unlock_mode():
    log("Calling opportunistic_restart", level=DEBUG)
    vault.opportunistic_restart()
    if config('auto-unlock'):
        vault.prepare_vault()


@when('leadership.is_leader')
@when('endpoint.secrets.new-request')
def configure_secrets_backend():
    """ Process requests for setup and access to simple kv secret backends """
    @tenacity.retry(wait=tenacity.wait_exponential(multiplier=1, max=10),
                    stop=tenacity.stop_after_attempt(10),
                    reraise=True)
    def _check_vault_status(client):
        if (not service_running('vault') or
                not client.is_initialized() or
                client.is_sealed()):
            return False
        return True

    # NOTE: use localhost listener as policy only allows 127.0.0.1 to
    #       administer the local vault instances via the charm
    client = vault.get_client(url=vault.VAULT_LOCALHOST_URL)

    status_ok = _check_vault_status(client)
    if not status_ok:
        log('Unable to process new secret backend requests,'
            ' deferring until vault is fully configured', level=DEBUG)
        return

    charm_role_id = vault.get_local_charm_access_role_id()
    if charm_role_id is None:
        log('Charm access to vault not configured, deferring'
            ' secrets backend setup', level=DEBUG)
        return
    client.auth_approle(charm_role_id)

    secrets = endpoint_from_flag('endpoint.secrets.new-request')
    requests = secrets.requests()

    # Configure KV secret backends
    backends = set([request['secret_backend']
                    for request in requests])
    for backend in backends:
        if not backend.startswith('charm-'):
            continue
        vault.configure_secret_backend(client, name=backend)

    # Configure AppRoles for application unit access
    for request in requests:
        # NOTE: backends must start with charm-
        backend_name = request['secret_backend']
        if not backend_name.startswith('charm-'):
            continue

        unit = request['unit']
        hostname = request['hostname']
        access_address = request['access_address']
        isolated = request['isolated']
        unit_name = unit.unit_name.replace('/', '-')
        policy_name = approle_name = 'charm-{}'.format(unit_name)

        if isolated:
            policy_template = vault.SECRET_BACKEND_HCL
        else:
            policy_template = vault.SECRET_BACKEND_SHARED_HCL

        vault.configure_policy(
            client,
            name=policy_name,
            hcl=policy_template.format(backend=backend_name,
                                       hostname=hostname)
        )

        approle_id = vault.configure_approle(
            client,
            name=approle_name,
            cidr='{}/32'.format(access_address),
            policies=[policy_name])

        secrets.set_role_id(unit=unit,
                            role_id=approle_id)

    clear_flag('endpoint.secrets.new-request')


@when('secrets.connected')
def send_vault_url_and_ca():
    secrets = endpoint_from_flag('secrets.connected')
    if is_flag_set('ha.available'):
        vault_url = vault.get_api_url(address=config('vip'))
    else:
        vault_url = vault.get_api_url()
    secrets.publish_url(vault_url=vault_url)

    if config('ssl-ca'):
        secrets.publish_ca(vault_ca=config('ssl-ca'))


@when('snap.installed.vault')
def prime_assess_status():
    atexit(_assess_status)


def _assess_interface(interface, optional,
                      missing_interfaces, incomplete_interfaces):
    """Assess a named interface for presence and completeness

    Uses reactive flags 'connected' and 'available' to indicate whether
    an interface is present and complete.

    :param: interface: Name of interface to assess.
    :param: options: Boolean indicating whether interface is optional
    :param: missing_interfaces: List of missing interfaces to update
    :param: incomplete_interfaces: List of incomplete interfaces to update
    :returns: bool, bool: Tuple of booleans indicating (missing, incomplete)
    """
    log("Assessing interface {}".format(interface), level=DEBUG)
    base_name = interface.split('.')[0]
    connected = (
        is_flag_set('{}.connected'.format(interface)) or
        is_flag_set('{}.connected'.format(base_name))
    )
    missing = False
    incomplete = False
    if not connected:
        if not optional:
            missing_interfaces.append(base_name)
        missing = True
        incomplete = True
    elif connected and not is_flag_set('{}.available'.format(interface)):
        incomplete_interfaces.append(base_name)
        incomplete = True
    return (missing, incomplete)


def _assess_interface_groups(interfaces, optional,
                             missing_interfaces, incomplete_interfaces):
    """Assess the relation state of a list of interface groups

    :param: interfaces: List of interface groups
    :param: options: Boolean indicating whether interfaces are optional
    :param: missing_interfaces: List of missing interfaces to update
    :param: incomplete_interfaces: List of incomplete interfaces to update
    """
    for interface_group in interfaces:
        log("Processing interface group: {}".format(interface_group),
            level=DEBUG)
        _potentially_missing = []
        _potentially_incomplete = []
        for interface in interface_group:
            missing, incomplete = _assess_interface(
                interface=interface, optional=optional,
                missing_interfaces=_potentially_missing,
                incomplete_interfaces=_potentially_incomplete)
            if not missing and not incomplete:
                break
        else:
            # NOTE(jamespage): If an interface group has an incomplete
            #                  interface then the end user has made a
            #                  choice as to which interface to use, so
            #                  don't flag any interfaces as missing.
            if (not optional and
                    _potentially_missing and not _potentially_incomplete):
                formatted_interfaces = [
                    "'{}'".format(i) for i in _potentially_missing
                ]
                missing_interfaces.append(
                    "{} missing".format(' or '.join(formatted_interfaces))
                )

            # NOTE(jamespage): Only display interfaces as incomplete if
            #                  if they are not in the missing interfaces
            #                  list for this interface group.
            if _potentially_incomplete:
                filtered_interfaces = [
                    i for i in _potentially_incomplete
                    if i not in _potentially_missing
                ]
                formatted_interfaces = [
                    "'{}'".format(i) for i in filtered_interfaces
                ]
                incomplete_interfaces.append(
                    "{} incomplete".format(' or '.join(formatted_interfaces))
                )


def _assess_status():
    """Assess status of relations and services for local unit"""
    if is_flag_set('snap.channel.invalid'):
        status_set('blocked',
                   'Invalid snap channel '
                   'configured: {}'.format(config('channel')))
        return
    if is_flag_set('config.dns_vip.invalid'):
        status_set('blocked',
                   'vip and dns-ha-access-record configured')
        return

    health = None
    if service_running('vault'):
        health = vault.get_vault_health()
        application_version_set(health.get('version'))

    _missing_interfaces = []
    _incomplete_interfaces = []

    _assess_interface_groups(REQUIRED_INTERFACES, optional=False,
                             missing_interfaces=_missing_interfaces,
                             incomplete_interfaces=_incomplete_interfaces)

    _assess_interface_groups(OPTIONAL_INTERFACES, optional=True,
                             missing_interfaces=_missing_interfaces,
                             incomplete_interfaces=_incomplete_interfaces)

    if _missing_interfaces or _incomplete_interfaces:
        state = 'blocked' if _missing_interfaces else 'waiting'
        status_set(state, ', '.join(_missing_interfaces +
                                    _incomplete_interfaces))
        return

    if not service_running('vault'):
        status_set('blocked', 'Vault service not running')
        return

    if not health['initialized']:
        status_set('blocked', 'Vault needs to be initialized')
        return

    if health['sealed']:
        status_set('blocked', 'Unit is sealed')
        return

    if config('disable-mlock'):
        status_set(
            'active',
            'WARNING: DISABLE-MLOCK IS SET -- SECRETS MAY BE LEAKED'
        )
    else:
        status_set(
            'active',
            'Unit is ready '
            '(active: {})'.format(str(not health['standby']).lower())
        )


@when('leadership.is_leader')
@when_any('certificates.server.cert.requested',
          'certificates.reissue.requested')
def create_server_cert():
    if not vault.vault_ready_for_clients():
        log('Unable to process new secret backend requests,'
            ' deferring until vault is fully configured', level=DEBUG)
        return
    reissue_requested = is_flag_set('certificates.reissue.requested')
    tls = endpoint_from_flag('certificates.available')
    server_requests = tls.get_server_requests()
    # Iterate over all items in the map.
    for unit_name, request in server_requests.items():
        cn = request.get('common_name')
        sans = request.get('sans')
        # Process request for a single certificate
        if cn and sans:
            ip_sans, alt_names = vault_pki.sort_sans(request.get('sans'))
            # Create the server certificate based on the info in request.
            try:
                bundle = vault_pki.get_server_certificate(
                    cn,
                    ip_sans=ip_sans,
                    alt_names=alt_names,
                    reissue=reissue_requested)
            except vault.VaultNotReady:
                # Cannot continue if vault is not ready
                return
            # Set the certificate and key for the unit on the relationship.
            tls.set_server_cert(
                unit_name,
                bundle['certificate'],
                bundle['private_key'])
        # Process request for a batch of certificates
        cert_requests = request.get('cert_requests')
        if cert_requests:
            for cn, crequest in cert_requests.items():
                ip_sans, alt_names = vault_pki.sort_sans(crequest.get('sans'))
                try:
                    bundle = vault_pki.get_server_certificate(
                        cn,
                        ip_sans=list(ip_sans),
                        alt_names=list(alt_names),
                        reissue=reissue_requested)
                    tls.add_server_cert(
                        unit_name,
                        cn,
                        bundle['certificate'],
                        bundle['private_key'])
                except vault.VaultNotReady:
                    # Cannot continue if vault is not ready
                    return
            tls.set_server_multicerts(unit_name)
        tls.set_ca(vault_pki.get_ca())
        chain = vault_pki.get_chain()
        if chain:
            tls.set_chain(chain)
    clear_flag('certificates.reissue.requested')
