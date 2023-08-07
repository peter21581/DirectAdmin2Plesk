#!/opt/plesk/python/2.7/bin/python
import logging
import os
import pymysql
import utils
from utils import (sql_to_dict, filter_dict, check_dir, check_document_root, log, warn, show_warnings, close_warn,
                   get_lines, get_file_content)
# from OpenSSL import crypto
from colors import Color
from context import try_safe, print_issues, Context
from plesk_migrator.sdk.parsers.cron import Cron
from plesk_migrator.sdk.utils import (
    is_ipv4, is_ipv6, safe_format, safe_idn_decode
)


class DirectAdminDumper(object):
    """Dump data from Directadmin panel
    
    :type _warnings: dict
    :type _panel_conf: dict
    :type _connections: dict
    """

    DIRECTADMIN_CONF = "/usr/local/directadmin/conf/directadmin.conf"

    def __init__(self):
        self._warnings = {}
        self._panel_conf = {}
        self._connections = {}

    def create_dump(self):
        """
        :rtype: dict 
        """
        self._panel_conf = self._get_panel_conf()
        self._setup_connections()
        self._get_mysql_version()
        try:
            log('-- START DUMP --')
            dump = {}
            context = Context()
            with try_safe(error_message='Failed to get subscriptions owned by administrator', context=context):
                dump.update(filter_dict(
                    subscriptions=self._get_subscriptions(context)
                ))
            with try_safe(error_message='Failed to get customers owned by administrator', context=context):
                dump.update(filter_dict(
                    customers=self._get_customers(context)
                ))
            with try_safe(error_message='Failed to get resellers', context=context):
                dump.update(filter_dict(
                    resellers=self._get_resellers(context)
                ))
            with try_safe(error_message='Failed to get database servers', context=context):
                dump.update(filter_dict(
                    database_servers=self._get_database_servers()
                ))
            log('-- FINISH DUMP --')
        finally:
            self._close_connections()
        try:
            show_warnings(self._warnings)
            print_issues()
        except Exception as e:
            print(safe_format(u'Failed to print the final report:\r\n{error}', error=e))
            logging.exception("Exception")
        return dump

    def _get_panel_conf(self):
        """
        :rtype: dict 
        """
        log("Getting DirectAdmin config")
        options = {}
        if not os.path.isfile(self.DIRECTADMIN_CONF):
            warn(
                self._warnings,
                safe_format(
                    'DirectAdmin config file "{file}" is not found',
                    file=self.DIRECTADMIN_CONF
                ),
                color=Color.red
            )
            return options
        options.update(filter_dict(
            mysql_conf=utils.get_value(
                self._warnings,
                self.DIRECTADMIN_CONF,
                "mysqlconf"
            )
        ))
        if "mysql_conf" not in options:
            warn(
                self._warnings,
                safe_format(
                    '"mysql_conf" parameter is not found in DirectAdmin config file "{file}"',
                    file=self.DIRECTADMIN_CONF
                ),
                color=Color.red
            )
            return options
        else:
            if not os.path.isfile(options["mysql_conf"]):
                warn(
                    self._warnings,
                    safe_format(
                        'DirectAdmin\'s MySQL config file "{file}" is not found',
                        file=options["mysql_conf"]
                    ),
                    color=Color.red
                )
                return options
            options.update(filter_dict(
                mysql_user=utils.get_value(
                    self._warnings,
                    options["mysql_conf"],
                    "user"
                ),
                mysql_password=utils.get_value(
                    self._warnings,
                    options["mysql_conf"],
                    "passwd"
                ),
                mysql_host=utils.get_value(
                    self._warnings,
                    options["mysql_conf"],
                    "host",
                    skip_error=True,
                    default_value='localhost'
                ),
                mysql_port=utils.get_value(
                    self._warnings,
                    options["mysql_conf"],
                    "port",
                    skip_error=True,
                    default_value='3306'
                )
            ))
            if "mysql_user" not in options:
                warn(
                    self._warnings,
                    safe_format(
                        '"user" parameter is not found in DirectAdmin\'s MySQL config file "{file}""',
                        file=options["mysql_conf"]
                    ),
                    color=Color.yellow
                )
            if "mysql_password" not in options:
                warn(
                    self._warnings,
                    safe_format(
                        '"passwd" parameter is not found in DirectAdmin\'s MySQL config file "{file}""',
                        file=options["mysql_conf"]
                    ),
                    color=Color.yellow
                )
            if "mysql_host" not in options:
                warn(
                    self._warnings,
                    safe_format(
                        '"host" parameter is not found in DirectAdmin\'s MySQL config file "{file}""',
                        file=options["mysql_conf"]
                    ),
                    color=Color.yellow
                )
            if "mysql_port" not in options:
                warn(
                    self._warnings,
                    safe_format(
                        '"port" parameter is not found in DirectAdmin\'s MySQL config file "{file}""',
                        file=options["mysql_conf"]
                    ),
                    color=Color.yellow
                )
        return options

    def _get_mysql_version(self):
        log("Determining DirectAdmin database vendor and version")
        if not self._connections.get("du"):
            log("Connection is not found, breaking")
            return
        source_mysql_version = sql_to_dict(
            '''SELECT lower(version()) as version''',
            self._connections["du"]
        )
        if len(source_mysql_version) == 0 or type(source_mysql_version[0].get('version')) is not str:
            log("Can not determine DB server version, breaking")
            return
        db_server_version = source_mysql_version[0].get('version')
        self._connections["du_options"]["is_mysql5.7+"] = False
        if 'mariadb' not in db_server_version:
            # version() may return string like '[0-9]+\.[0-9]+\.[0-9]+(-string)?'
            if tuple(db_server_version.split('-')[0].split('.')) > tuple(["5", "7", "0"]):
                self._connections["du_options"]["is_mysql5.7+"] = True

    def _setup_connections(self):
        connections = {}
        log("Connecting DirectAdmin database")
        user = self._panel_conf.get("mysql_user")
        passwd = self._panel_conf.get("mysql_password")
        host = self._panel_conf.get("mysql_host")
        port = self._panel_conf.get("mysql_port")
        try:
            n_port = int(port)
        except Exception:
            n_port = 3306
            warn(
                self._warnings,
                safe_format(
                    'Can\'t convert MySQL port "{port}" to integer, default port 3306 will be used', port=port
                ),
                color=Color.yellow
            )
        try:
            if os.path.exists("/var/lib/mysql/mysql.sock"):
                connection = pymysql.connect(
                user=user,
                passwd=passwd,
                unix_socket="/var/lib/mysql/mysql.sock",
                db="mysql"
                )
            else:
                connection = pymysql.connect(
                user=user,
                passwd=passwd,
                host=host,
                port=n_port,
                db="mysql"
            )
            connections.update(dict(
                du=connection,
                du_options=dict(
                    user=user,
                    passwd=passwd,
                    host=host,
                    port=port,
                    db="mysql"
                )
            ))
        except Exception as e:
            warn(
                self._warnings,
                safe_format(
                    'Failed to connect to DirectAdmin database'
                    ' with [login]@[host]:[port] "{login}@{host}:{port}" and password "{passwd}":\r\n'
                    '{details}\r\n'
                    'Database content will not be dumped',
                    login=user,
                    host=host,
                    port=str(port),
                    passwd='*****' if passwd is not None else None,
                    details=e
                ),
                color=Color.red
            )
            logging.exception("Exception")
        self._connections = connections

    def _close_connections(self):
        if "du" in self._connections:
            log("Closing connection to DirectAdmin database")
            try:
                self._connections["du"].close()
            except Exception as e:
                warn(
                    self._warnings,
                    safe_format(
                        'Failed to close connection to DirectAdmin database:\r\n'
                        '{details}',
                        details=e
                    ),
                    color=Color.yellow
                )
                logging.exception("Exception")

    def _get_database_servers(self):
        """
        :rtype: dict 
        """
        if "du" not in self._connections:
            return None
        database_servers = []
        database_server = dict(
            type='mysql',
            host=self._panel_conf.get("mysql_host"),
            port=self._panel_conf.get("mysql_port"),
            admin=filter_dict(
                login=self._panel_conf.get("mysql_user"),
                password=self._panel_conf.get("mysql_password")
            )
        )
        database_servers.append(database_server)
        return database_servers

    def _get_resellers(self, context):
        """
        :type context: context.Context
        :rtype: list 
        """
        da_resellers = []
        da_admins = []
        with try_safe(error_message='Failed to get list of resellers', context=context):
            da_resellers.extend(get_lines(
                self._warnings,
                "/usr/local/directadmin/data/admin/reseller.list"
            ))
        # Additional DirectAdmin administrators will become Resellers in Plesk
        with try_safe(
                error_message='Failed to get list of additional DirectAdmin administrators',
                context=context
        ):
            da_admins.extend(get_lines(
                self._warnings,
                "/usr/local/directadmin/data/admin/admin.list"
            ))
            if 'admin' in da_admins:
                da_admins.remove('admin')
        all_da_resellers = da_resellers + da_admins
        resellers = []
        for da_reseller in all_da_resellers:
            child_context = context.clone(reseller=da_reseller)
            with try_safe(error_message='Failed to get reseller', context=child_context):
                new_reseller = self._get_reseller(child_context)
                resellers.append(new_reseller)
        return resellers

    def _get_reseller(self, context):
        """
        :type context: context.Context
        :rtype: dict 
        """
        reseller_warn = warn(self._warnings, safe_format(u"Reseller '{name}'", name=context.reseller))
        reseller = dict(login=context.reseller)
        with try_safe(error_message='Failed to get password for reseller', context=context):
            password = self._get_password(context.reseller)
            if password is not None:
                reseller.update(dict(
                    password=password,
                    password_type="hash"
                ))
        suspended = None
        with try_safe(error_message='Failed to get suspension status for reseller', context=context):
            suspended = self._get_user_suspension_status(context.reseller)
            if suspended == 'yes':
                reseller.update(filter_dict(
                    disabled_by=["client"]
                ))
        with try_safe(error_message='Failed to get customers owned by reseller', context=context):
            reseller.update(filter_dict(
                customers=self._get_customers(context)
            ))
        with try_safe(error_message='Failed to get subscriptions owned by reseller', context=context):
            reseller.update(filter_dict(
                subscriptions=self._get_subscriptions(context, owner_suspended=suspended)
            ))
        with try_safe(error_message='Failed to get contact info for reseller', context=context):
            reseller.update(filter_dict(
                contact_info=self._get_contact_info(user=context.reseller)
            ))
        close_warn(self._warnings, reseller_warn)
        return reseller

    def _get_customers(self, context):
        """
        :type context: context.Context
        :rtype: list 
        """
        owner = self._get_owner_from_context(context)
        da_customers = get_lines(
            self._warnings,
            "/usr/local/directadmin/data/users/{reseller}/users.list".format(
                reseller=owner
            )
        )
        customers = []
        for da_customer in da_customers:
            child_context = context.clone(customer=da_customer)
            with try_safe(error_message='Failed to get customer', context=child_context):
                new_customer = self._get_customer(child_context)
                customers.append(new_customer)
        return customers

    def _get_customer(self, context):
        """
        :type context: context.Context
        :rtype: dict 
        """
        customer_warn = warn(self._warnings, safe_format(u"Customer '{name}'", name=context.customer))
        customer = dict(login=context.customer)
        with try_safe(error_message='Failed to get password for customer', context=context):
            password = self._get_password(context.customer)
            if password is not None:
                customer.update(dict(
                    password=password,
                    password_type="hash"
                ))
        suspended = None
        with try_safe(error_message='Failed to get suspension status for customer', context=context):
            suspended = self._get_user_suspension_status(context.customer)
            if suspended == 'yes':
                customer.update(filter_dict(
                    disabled_by=["client"]
                ))
        with try_safe(error_message='Failed to get subscriptions owned by customer', context=context):
            customer.update(filter_dict(
                subscriptions=self._get_subscriptions(context, owner_suspended=suspended)
            ))
        with try_safe(error_message='Failed to get contact info for customer', context=context):
            customer.update(filter_dict(
                contact_info=self._get_contact_info(user=context.customer)
            ))
        close_warn(self._warnings, customer_warn)
        return customer

    def _get_contact_info(self, user):
        """
        :type user: str | unicode
        :rtype: dict 
        """
        return filter_dict(
            name=user,
            email=utils.get_value(
                self._warnings,
                "/usr/local/directadmin/data/users/{user}/user.conf".format(
                    user=user
                ),
                "email"
            )
        )

    @staticmethod
    def _get_owner_from_context(context):
        """
        :type context: context.Context
        :rtype: str | unicode | None 
        """
        if context.customer is not None:
            return context.customer
        if context.reseller is not None:
            return context.reseller
        return 'admin'

    def _get_subscriptions(self, context, owner_suspended=None):
        """
        :type context: context.Context
        :type owner_suspended: str | unicode | None
        :rtype: list
        """
        da_subscriptions = []
        owner = self._get_owner_from_context(context)
        da_domains = get_lines(
            self._warnings,
            "/usr/local/directadmin/data/users/{user}/domains.list".format(
                user=owner
            )
        )
        for da_domain in da_domains:
            if "yes" == utils.get_value(
                    self._warnings,
                    "/usr/local/directadmin/data/users/{user}/domains/{domain}.conf".format(
                        user=owner,
                        domain=da_domain
                    ),
                    "defaultdomain"
            ):
                da_subscriptions = [da_domain]
                break
        subscriptions = []
        for da_subscription in da_subscriptions:
            child_context = context.clone(subscription=da_subscription)
            with try_safe(error_message='Failed to get subscription', context=child_context):
                new_subscription = self._get_subscription(child_context, owner_suspended=owner_suspended)
                subscriptions.append(new_subscription)
        return subscriptions

    def _get_subscription(self, context, owner_suspended):
        """
        :type context: context.Context
        :type owner_suspended: str | unicode | None
        :rtype: dict 
        """
        idn_subscription = safe_idn_decode(context.subscription)
        subscription_warn = warn(
            self._warnings,
            safe_format(u"Subscription '{name}'", name=idn_subscription)
        )
        owner = self._get_owner_from_context(context)
        subscription = dict(
            name=idn_subscription,
            sys_user=dict(
                login=owner
            )
        )
        with try_safe(error_message='Failed to change system user login for system user "admin"', context=context):
            if owner == "admin":
                subscription["sys_user"]["login"] = "directadmin"
                warn(
                    self._warnings,
                    "System user name 'admin' is reserved by Plesk. "
                    "Login 'admin' will be replaced to 'directadmin'.",
                    Color.red
                )
        with try_safe(error_message='Failed to get password for system user of subscription', context=context):
            password = self._get_password(owner)
            if password is not None:
                subscription['sys_user'].update(dict(
                    password=password,
                    password_type="hash"
                ))
        with try_safe(error_message='Failed to get shell for system user of subscription', context=context):
            shell = self._get_shell(owner)
            if shell is not None:
                subscription['sys_user'].update(dict(
                    shell=shell
                ))
        with try_safe(error_message='Failed to get suspension status for domain', context=context):
            suspended = self._get_user_suspension_status(owner)
            if suspended == 'yes':
                subscription.update(dict(
                    domain_disabled_by=["client"]
                ))
        with try_safe(error_message='Failed to get suspension status for subscription', context=context):
            if owner_suspended == 'yes':
                subscription.update(dict(
                    subscription_disabled_by=["client"]
                ))
        with try_safe(error_message='Failed to get document root of subscription', context=context):
            relative_path = os.path.join('domains', context.subscription, 'public_html')
            path = os.path.join('/home', owner, relative_path)
            error_message = check_dir(path)
            if error_message is None:
                subscription.update(dict(
                    target_document_root=relative_path
                ))
            else:
                warn(self._warnings, u'Failed to get document root of subscription: ' + error_message, Color.yellow)
        with try_safe(error_message='Failed to get location of subscription\'s web files', context=context):
            subscription.update(filter_dict(
                web_files=self._get_web_files(owner)
            ))
        with try_safe(error_message='Failed to get addon domains of subscription', context=context):
            subscription.update(filter_dict(
                addon_domains=self._get_addon_domains(context)
            ))
        with try_safe(error_message='Failed to get subdomains of subscription', context=context):
            subscription.update(filter_dict(
                subdomains=self._get_subdomains(context)
            ))
        with try_safe(error_message='Failed to get aliases of subscription', context=context):
            subscription.update(filter_dict(
                aliases=self._get_domain_aliases(context)
            ))
        with try_safe(error_message='Failed to get databases of subscription', context=context):
            subscription.update(filter_dict(
                databases=self._get_databases(context)
            ))
        with try_safe(error_message='Failed to get database users of subscription', context=context):
            subscription.update(filter_dict(
                database_users=self._get_database_users(context)
            ))
        with try_safe(error_message='Failed to get mail service of subscription', context=context):
            subscription.update(filter_dict(
                mail_service=self._get_mail_service(context)
            ))
        with try_safe(error_message='Failed to get DNS zone of subscription', context=context):
            subscription.update(filter_dict(
                dns_zone=self._get_dns_zone(context)
            ))
        with try_safe(error_message='Failed to get FTP users of subscription', context=context):
            subscription.update(filter_dict(
                ftp_users=self._get_ftp_users(context)
            ))
        with try_safe(error_message='Failed to get SSL certificates of subscription', context=context):
            certificates = self._get_certificates(context)
            if len(certificates) > 0:
                subscription.update(dict(
                    certificates=certificates,
                    web_hosting_settings=dict(
                        ssl=self._get_ssl_status(context),
                        ssl_certificate=idn_subscription
                    )
                ))
        with try_safe(error_message='Failed to get limits of subscription', context=context):
            subscription.update(filter_dict(
                limits=self._get_limits(context)
            ))
        with try_safe(error_message='Failed to get protected directories of subscription', context=context):
            subscription.update(filter_dict(
                protected_directories=self._get_protected_directories(context)
            ))
        with try_safe(error_message='Failed to get scheduled tasks of subscription', context=context):
            subscription.update(filter_dict(
                scheduled_tasks=self._get_scheduled_tasks(context)
            ))
        with try_safe(error_message='Failed to get IP addresses of subscription', context=context):
            subscription.update(filter_dict(
                ip_addresses=self._get_ip_addresses(context)
            ))
        with try_safe(error_message='Failed to get file exclusions of subscription', context=context):
            if "web_files" in subscription and len(subscription["web_files"]) > 0:
                protected_directories = []
                all_domains_in_subscription = (
                    [subscription] +
                    subscription.get("addon_domains", []) +
                    subscription.get("subdomains", [])
                )
                for domain in all_domains_in_subscription:
                    if "target_document_root" in domain:
                        for protected_directory in domain.get("protected_directories", []):
                            target_document_root = domain["target_document_root"]
                            path = protected_directory.get("path", '')
                            protected_directories.append(os.path.join(
                                "/", target_document_root.lstrip('/'), path.lstrip('/')
                            ))
                if protected_directories:
                    for protected_directoriy in protected_directories:
                        web_files = subscription["web_files"][0]  # type: dict
                        exclude = web_files.get("exclude", [])
                        exclude.append(
                            os.path.join(protected_directoriy + '.htaccess')
                        )
                if owner == "admin":
                    web_files = subscription["web_files"][0]  # type: dict
                    web_files.update(dict(
                        source_system_user_login="admin"
                    ))
        close_warn(self._warnings, subscription_warn)
        return subscription

    def _get_web_files(self, owner):
        """
        :type owner: str | unicode 
        :rtype: list | None 
        """
        path = os.path.join('/home', owner)
        error_message = check_dir(path)
        if error_message is None:
            web_files = []
            web_files_element = dict(
                source=path,
                target="{webspace_root}",
                exclude=[
                    "/.*",
                    "/Maildir",
                    "/imap"
                ]
            )
            if owner == "admin":
                web_files_element.update(dict(
                    source_system_user_login="admin"
                ))
            web_files.append(web_files_element)
            return web_files
        else:
            warn(
                self._warnings,
                u'Failed to get location of subscription\'s web files: ' + error_message,
                Color.yellow
            )
            return None

    def _get_addon_domains(self, context):
        """
        :type context: context.Context
        :rtype: list 
        """
        owner = self._get_owner_from_context(context)
        da_domains = get_lines(
            self._warnings,
            "/usr/local/directadmin/data/users/{user}/domains.list".format(
                user=owner
            )
        )
        addon_domains = []

        # Domain forwardings for subscription
        with try_safe(
                error_message='Failed to get addon domains with forwarding to subscription',
                context=context
        ):
            addon_domains.extend(self._get_domain_forwardings(context))

        # Addon domains and forwardings for addon domains
        for da_domain in da_domains:
            if da_domain == context.subscription:
                continue

            child_context = context.clone(addon_domain=da_domain)
            with try_safe(
                    error_message='Failed to get addon domains with forwarding to domain',
                    context=child_context
            ):
                addon_domains.extend(self._get_domain_forwardings(child_context))
            with try_safe(error_message='Failed to get addon domain', context=child_context):
                new_addon_domain = self._get_addon_domain(child_context)
                addon_domains.append(new_addon_domain)

        return addon_domains

    def _get_addon_domain(self, context):
        """
        :type context: context.Context
        :rtype: dict 
        """
        idn_addon_domain = safe_idn_decode(context.addon_domain)
        addon_domain_warn = warn(
            self._warnings,
            safe_format(u"addon domain '{name}'", name=idn_addon_domain)
        )
        owner = self._get_owner_from_context(context)
        addon_domain = dict(name=idn_addon_domain)
        with try_safe(error_message='Failed to get document root of addon domain', context=context):
            relative_path = os.path.join('domains', context.addon_domain, 'public_html')
            path = os.path.join('/home', owner, relative_path)
            error_message = check_dir(path)
            if error_message is None:
                addon_domain.update(dict(
                    target_document_root=relative_path
                ))
            else:
                warn(self._warnings, u'Failed to get document root of addon domain: ' + error_message, Color.yellow)
        with try_safe(error_message='Failed to get aliases of addon domain', context=context):
            addon_domain.update(filter_dict(
                aliases=self._get_domain_aliases(context)
            ))
        with try_safe(error_message='Failed to get DNS zone of addon domain', context=context):
            addon_domain.update(filter_dict(
                dns_zone=self._get_dns_zone(context)
            ))
        with try_safe(error_message='Failed to get mail service of addon domain', context=context):
            addon_domain.update(filter_dict(
                mail_service=self._get_mail_service(context)
            ))
        with try_safe(error_message='Failed to get protected directories of addon domain', context=context):
            addon_domain.update(filter_dict(
                protected_directories=self._get_protected_directories(context)
            ))
        with try_safe(error_message='Failed to get SSL certificates of addon domain', context=context):
            certificates = self._get_certificates(context)
            if len(certificates) > 0:
                addon_domain.update(dict(
                    certificates=certificates,
                    web_hosting_settings=dict(
                        ssl=self._get_ssl_status(context),
                        ssl_certificate=context.addon_domain
                    )
                ))
        with try_safe(error_message='Failed to get IP addresses of addon domain', context=context):
            addon_domain.update(filter_dict(
                ip_addresses=self._get_ip_addresses(context)
            ))
        with try_safe(error_message='Failed to get suspension status for addon domain', context=context):
            suspended = self._get_domain_suspension_status(context)
            if suspended == 'yes':
                addon_domain.update(dict(
                    disabled_by=["client"]
                ))
        close_warn(self._warnings, addon_domain_warn)
        return addon_domain

    def _get_subdomains(self, context):
        """
        :type context: context.Context
        :rtype: list 
        """
        owner = self._get_owner_from_context(context)
        da_domains = get_lines(
            self._warnings,
            "/usr/local/directadmin/data/users/{user}/domains.list".format(
                user=owner
            )
        )
        subdomains = []
        for da_domain in da_domains:
            if "yes" == utils.get_value(
                    self._warnings,
                    "/usr/local/directadmin/data/users/{user}/domains/{domain}.conf".format(
                        user=owner,
                        domain=da_domain
                    ),
                    "defaultdomain"
            ):
                domain_context = context.clone()
            else:
                domain_context = context.clone(addon_domain=da_domain)
            da_subdomains = get_lines(
                self._warnings,
                "/usr/local/directadmin/data/users/{user}/domains/{domain}.subdomains".format(
                    user=owner,
                    domain=da_domain
                )
            )
            for da_subdomain in da_subdomains:
                child_context = domain_context.clone(subdomain=da_subdomain)
                with try_safe(error_message='Failed to get subdomain', context=child_context):
                    new_subdomain = self._get_subdomain(child_context)
                    subdomains.append(new_subdomain)
        return subdomains

    def _get_subdomain(self, context):
        """
        :type context: context.Context
        :rtype: dict 
        """
        if context.addon_domain is not None:
            domain = context.addon_domain
        else:
            domain = context.subscription
        idn_domain = safe_idn_decode(domain)
        idn_subdomain = safe_idn_decode(context.subdomain)
        subdomain_warn = warn(
            self._warnings,
            safe_format(u"subdomain '{subdomain}.{domain}'", subdomain=idn_subdomain, domain=idn_domain)
        )
        owner = self._get_owner_from_context(context)
        subdomain = dict(name=u"{subdomain}.{domain}".format(subdomain=idn_subdomain, domain=idn_domain))
        with try_safe(error_message='Failed to get document root of subdomain', context=context):
            relative_path = os.path.join('domains', domain, 'public_html', context.subdomain)
            path = os.path.join('/home', owner, relative_path)
            error_message = check_dir(path)
            if error_message is None:
                subdomain.update(dict(
                    target_document_root=relative_path
                ))
            else:
                warn(self._warnings, u'Failed to get document root of subdomain: ' + error_message, Color.yellow)
        with try_safe(error_message='Failed to get protected directories of subdomain', context=context):
            subdomain.update(filter_dict(
                protected_directories=self._get_protected_directories(context)
            ))
        close_warn(self._warnings, subdomain_warn)
        return subdomain

    def _get_domain_forwardings(self, context):
        """
        :type context: context.Context
        :rtype: list 
        """
        owner = self._get_owner_from_context(context)
        if context.addon_domain is not None:
            domain = context.addon_domain
        else:
            domain = context.subscription
        da_aliases = get_lines(
            self._warnings,
            "/usr/local/directadmin/data/users/{user}/domains/{domain}.pointers".format(
                user=owner,
                domain=domain
            ),
            skip_error=True
        )
        forwardings = []
        for da_alias in da_aliases:
            splitted_line = da_alias.split('=', 1)
            if len(splitted_line) != 2:
                continue
            da_alias_name, da_alias_type = splitted_line
            if da_alias_type == "pointer":
                child_context = context.clone(addon_domain=da_alias_name)
                with try_safe(
                        error_message='Failed to get addon domain with forwarding to domain',
                        context=child_context
                ):
                    suspended = self._get_domain_suspension_status(context)
                    new_forwarding = self._get_domain_forwarding(child_context, domain, suspended)
                    forwardings.append(new_forwarding)
        return forwardings

    def _get_domain_forwarding(self, context, domain, suspended):
        """
        :type context: context.Context
        :type domain: str | unicode
        :type suspended: str | unicode | none
        :rtype: dict 
        """
        idn_alias_name = safe_idn_decode(context.addon_domain)
        idn_domain = safe_idn_decode(domain)
        forwarding_warn = warn(
            self._warnings,
            safe_format(
                u"{src} redirect to 'http://{trg}'",
                src=idn_alias_name,
                trg=idn_domain
            )
        )
        forwarding = dict(
            name=idn_alias_name,
            forwarding_url="http://{trg}".format(trg=idn_domain)
        )
        if suspended == 'yes':
            forwarding.update(dict(
                disabled_by=["client"]
            ))
        with try_safe(error_message='Failed to get DNS zone for addon domain with forwarding', context=context):
            forwarding.update(filter_dict(
                dns_zone=self._get_dns_zone(context)
            ))
        close_warn(self._warnings, forwarding_warn)
        return forwarding

    def _get_domain_aliases(self, context):
        """
        :type context: context.Context
        :rtype: list 
        """
        owner = self._get_owner_from_context(context)
        if context.addon_domain is not None:
            domain = context.addon_domain
        else:
            domain = context.subscription
        da_aliases = get_lines(
            self._warnings,
            "/usr/local/directadmin/data/users/{user}/domains/{domain}.pointers".format(
                user=owner,
                domain=domain
            ),
            skip_error=True
        )
        aliases = []
        for da_alias in da_aliases:
            splitted_line = da_alias.split('=', 1)
            if len(splitted_line) != 2:
                continue
            da_alias_name, da_alias_type = splitted_line
            if da_alias_type == "alias":
                child_context = context.clone(alias=da_alias_name)
                with try_safe(error_message='Failed to get alias', context=child_context):
                    new_alias = self._get_domain_alias(child_context)
                    aliases.append(new_alias)
        return aliases

    def _get_domain_alias(self, context):
        """
        :type context: context.Context
        :rtype: dict 
        """
        idn_alias_name = safe_idn_decode(context.alias)
        alias_warn = warn(
            self._warnings,
            safe_format(u"alias '{name}'", name=idn_alias_name)
        )
        alias = dict(name=idn_alias_name)
        with try_safe(error_message='Failed to get DNS zone for addon domain with forwarding', context=context):
            alias.update(filter_dict(
                dns_zone=self._get_dns_zone(context)
            ))
        close_warn(self._warnings, alias_warn)
        return alias

    def _get_user_suspension_status(self, user):
        """
        :type user: str | unicode 
        :rtype: str | unicode | None 
        """
        return utils.get_value(
            self._warnings,
            "/usr/local/directadmin/data/users/{user}/user.conf".format(user=user),
            "suspended"
        )

    def _get_domain_suspension_status(self, context):
        """
        :type context: context.Context
        :rtype: str | unicode | None 
        """
        owner = self._get_owner_from_context(context)
        if context.addon_domain is not None:
            domain = context.addon_domain
        else:
            domain = context.subscription
        return utils.get_value(
            self._warnings,
            "/usr/local/directadmin/data/users/{user}/domains/{domain}.conf".format(
                user=owner,
                domain=domain
            ),
            "suspended"
        )

    def _get_ssl_status(self, context):
        """
        :type context: context.Context
        :rtype: bool
        """
        owner = self._get_owner_from_context(context)
        if context.addon_domain is not None:
            domain = context.addon_domain
        else:
            domain = context.subscription
        ssl_enabled = utils.get_value(
            self._warnings,
            "/usr/local/directadmin/data/users/{user}/domains/{domain}.conf".format(
                user=owner,
                domain=domain
            ),
            "ssl"
        )
        return ssl_enabled.lower() == "on"

    def _get_databases(self, context):
        """
        :type context: context.Context
        :rtype: list | None
        """
        if "du" not in self._connections:
            return None
        owner = self._get_owner_from_context(context)
        da_databases = sql_to_dict(
            '''SELECT DISTINCT (Db) Db
            FROM db
            WHERE Db like "{name}_%"'''.format(name=owner),
            self._connections["du"]
        )
        databases = []
        for da_database in da_databases:
            database_name = da_database["Db"].replace('\\', '')
            child_context = context.clone(database=database_name)
            with try_safe(error_message='Failed to get database', context=child_context):
                database = self._get_database(child_context)
                databases.append(database)
        return databases

    def _get_database(self, context):
        """
        :type context: context.Context
        :rtype: dict 
        """
        database_name = context.database
        database_warn = warn(
            self._warnings,
            safe_format(
                u"database '{name}'",
                name=database_name
            )
        )
        database = dict(
            name=database_name,
            type="mysql"
        )
        with try_safe(error_message='Failed to get information about server of database', context=context):
            database.update(dict(
                server=filter_dict(
                    type='mysql',
                    host=self._connections["du_options"].get("host"),
                    port=self._connections["du_options"].get("port")
                )
            ))
        close_warn(self._warnings, database_warn)
        return database

    def _get_database_users(self, context):
        """
        :type context: context.Context
        :rtype: list | None 
        """
        if "du" not in self._connections:
            return None
        owner = self._get_owner_from_context(context)
        password_field = 'Password'
        if self._connections["du_options"]["is_mysql5.7+"] is True:
            password_field = 'authentication_string'
        da_database_users = sql_to_dict(
            '''SELECT DISTINCT User, {password_field}
            FROM user
            WHERE User like "{name}_%"'''.format(name=owner, password_field=password_field),
            self._connections["du"]
        )
        database_users = []
        for da_database_user in da_database_users:
            database_user_name = da_database_user["User"]
            database_user_password = da_database_user[password_field]
            child_context = context.clone(database_user=database_user_name)
            with try_safe(error_message='Failed to get database user', context=child_context):
                database_user = self._get_database_user(child_context, database_user_password)
                database_users.append(database_user)
        return database_users

    def _get_database_user(self, context, password):
        """
        :type context: context.Context
        :rtype: dict 
        """
        database_user_name = context.database_user
        database_user_warn = warn(
            self._warnings,
            safe_format(u"dbuser '{user}'", user=database_user_name)
        )
        database_user = dict(login=database_user_name)
        with try_safe(error_message='Failed to get information about server of database user', context=context):
            database_user.update(dict(
                server=filter_dict(
                    type='mysql',
                    host=self._connections["du_options"].get("host"),
                    port=self._connections["du_options"].get("port")
                )
            ))
        with try_safe(error_message='Failed to get password for database user', context=context):
            if password is not None:
                database_user.update(dict(
                    password=password,
                    password_type="hash"
                ))
        close_warn(self._warnings, database_user_warn)
        return database_user

    def _get_mail_service(self, context):
        """
        :type context: context.Context
        :rtype: dict 
        """
        mail_service = {}
        if context.addon_domain is not None:
            domain = context.addon_domain
            subscription = context.subscription
        else:
            domain = context.subscription
            subscription = None
        with try_safe(error_message='Failed to get catch all action of mail service', context=context):
            mail_service.update(filter_dict(
                catch_all_action=self._get_catch_all_action(domain)
            ))
        with try_safe(error_message='Failed to get mailboxes of domain', context=context):
            mail_service.update(filter_dict(
                mail_users=self._get_mailboxes(context, domain, subscription)
            ))
        return mail_service

    def _get_catch_all_action(self, domain):
        """
        :type domain: str | unicode
        :rtype: dict 
        """
        lines = get_lines(
            self._warnings,
            "/etc/virtual/{domain}/aliases".format(domain=domain),
            skip_error=True
        )
        catch_all_action = {}
        for line in lines:
            splitted_line = line.split(':', 1)
            if len(splitted_line) != 2:
                continue
            da_alias_name = splitted_line[0].strip()
            da_alias_value = splitted_line[1].strip()
            if da_alias_name != '*':
                continue
            if da_alias_value == ':fail:':
                catch_all_action.update(filter_dict(
                    name="bounce"
                ))
            elif da_alias_value == ':blackhole:':
                catch_all_action.update(filter_dict(
                    name="reject"
                ))
            else:
                if '@' not in da_alias_value:
                    da_alias_value += '@' + domain
                catch_all_action.update(filter_dict(
                    name="forward",
                    forward_email=da_alias_value
                ))
        return catch_all_action

    def _get_mailboxes(self, context, domain, subscription=None):
        """
        :type context: context.Context
        :type domain: str | unicode
        :type subscription: str | unicode | none
        :rtype: list 
        """
        mailboxes = []
        owner = self._get_owner_from_context(context)

        # If subscription is not passed, that means that we are dumping a default domain and will convert it to
        # subscription.
        # Dump default mailbox of user account only for subscription, not for addon domains.
        if subscription is None:
            with try_safe(error_message='Failed to get default mailbox of subscription', context=context):
                password = self._get_password(owner)
                account_mailbox = filter_dict(
                    name=owner,
                    password=password,
                    password_type="hash" if password else None,
                    maildir_directory="/home/{customer}/Maildir".format(customer=owner),
                    disk_quota='-1'
                )
                mailboxes.append(account_mailbox)

        # Dump other mailboxes
        idn_domain = safe_idn_decode(domain)
        da_mailboxes = []
        with try_safe(error_message='Failed to get mailboxes of domain', context=context):
            da_mailboxes.extend(self._get_da_mailboxes(owner, domain))
        da_autoresponders = []
        with try_safe(error_message='Failed to get mail autoresponders of domain', context=context):
            da_autoresponders.extend(self._get_da_autoresponders(domain))
        da_aliases = []
        with try_safe(error_message='Failed to get mail aliases of domain', context=context):
            da_aliases.extend(self._get_da_aliases(owner, domain, subscription))
        for da_mailbox in da_mailboxes:
            if subscription is None and da_mailbox["name"] == owner:
                continue
            child_context = context.clone(mailbox=da_mailbox["name"])
            with try_safe(error_message='Failed to get mailbox', context=child_context):
                mailbox_warn = warn(
                    self._warnings,
                    safe_format(
                        u"mailbox '{name}@{domain}'",
                        name=da_mailbox["name"],
                        domain=idn_domain
                    )
                )
                mailbox = filter_dict(
                    name=da_mailbox["name"],
                    password=da_mailbox["password"],
                    password_type="hash" if da_mailbox["password"] else None,
                    directory=check_document_root(
                        da_mailbox["directory"],
                        self._warnings,
                        "mail directory ",
                        da_mailbox["directory"]
                    )
                )
                with try_safe(error_message='Failed to get quota of mailbox', context=context):
                    disk_quota = self._get_mailbox_quota(da_mailbox["name"], domain)
                    if disk_quota is not None:
                        mailbox.update(dict(
                            disk_quota=disk_quota
                        ))
                with try_safe(error_message='Failed to get auto reply of mailbox', context=context):
                    auto_reply = self._get_da_vacation_messages(da_mailbox["name"], domain)
                    mailbox.update(filter_dict(
                        auto_reply=auto_reply
                    ))
                for da_autoresponder in da_autoresponders:
                    if da_autoresponder["name"] == mailbox["name"]:
                        mailbox.update(da_autoresponder)
                for da_alias in da_aliases:
                    if da_alias["name"] == mailbox["name"]:
                        mailbox.update(da_alias)
                close_warn(self._warnings, mailbox_warn)
                mailboxes.append(mailbox)

        mailbox_names = [mbox["name"] for mbox in mailboxes]
        for da_alias in da_aliases:
            if da_alias["name"] not in mailbox_names:
                mailbox = da_alias
                mailbox.update(
                    mailbox=False
                )
                mailboxes.append(mailbox)
        return mailboxes

    def _get_da_mailboxes(self, customer, domain):
        """
        :type customer: str | unicode 
        :type domain: str | unicode
        :rtype: list 
        """
        idn_domain = safe_idn_decode(domain)
        lines = get_lines(
            self._warnings,
            "/etc/virtual/{domain}/passwd".format(domain=domain),
            skip_error=True
        )
        da_mailboxes = []
        for line in lines:
            blocks = line.split(':')
            if len(blocks) < 2:
                continue
            mailbox_name = blocks[0]
            mailbox_password = blocks[1]
            da_mailbox_warn = warn(
                self._warnings,
                safe_format(
                    u"mailbox '{mailbox}@{domain}'",
                    mailbox=mailbox_name,
                    domain=idn_domain
                ),
                display=False
            )
            da_mailbox = dict(
                name=mailbox_name,
                password=mailbox_password.lstrip('!')
            )
            if len(blocks) < 6:
                da_mailbox.update(dict(
                    directory='/home/{user}/imap/{domain}/{mail_user}'.format(
                        user=customer, domain=domain, mail_user=mailbox_name
                    ))
                )
            else:
                mailbox_directory = blocks[5]
                da_mailbox.update(dict(
                    directory=mailbox_directory
                ))
            da_mailboxes.append(da_mailbox)
            close_warn(self._warnings, da_mailbox_warn)
        return da_mailboxes

    def _get_da_autoresponders(self, domain):
        """
        :type domain: str | unicode
        :rtype: list 
        """
        idn_domain = safe_idn_decode(domain)
        lines = get_lines(
            self._warnings,
            "/etc/virtual/{domain}/autoresponder.conf".format(domain=domain),
            skip_error=True
        )
        da_autoresponders = []
        for line in lines:
            splitted_line = line.split(':', 1)
            if len(splitted_line) != 2:
                continue
            mailbox_name, forwarding_address = splitted_line
            da_autoresponder_warn = warn(
                self._warnings,
                safe_format(
                    u"mailbox '{mailbox}@{domain}'",
                    mailbox=mailbox_name,
                    domain=idn_domain
                ),
                display=False
            )
            auto_reply_message = get_file_content(
                self._warnings,
                "/etc/virtual/{domain}/reply/{name}.msg".format(
                    domain=domain,
                    name=mailbox_name
                ),
                skip_error=True
            )
            auto_reply = dict(
                subject="Re: <request_subject>",
                message=auto_reply_message if auto_reply_message is not None else '',
            )
            auto_reply.update(filter_dict(
                forwarding_address=forwarding_address
            ))
            da_autoresponder = dict(
                name=mailbox_name,
                auto_reply=auto_reply
            )
            da_autoresponders.append(da_autoresponder)
            close_warn(self._warnings, da_autoresponder_warn)
        return da_autoresponders

    def _get_da_aliases(self, customer, domain, subscription=None):
        """
        :type customer: str | unicode
        :type domain: str | unicode
        :type subscription: str | unicode | None
        :rtype: list 
        """
        idn_domain = safe_idn_decode(domain)
        lines = get_lines(
            self._warnings,
            "/etc/virtual/{domain}/aliases".format(domain=domain),
            skip_error=True
        )
        da_aliases = []

        # If subscription is passed, that means that we are dumping an addon domain.
        # Create forwarding to default mailbox of default domain only for addon domains
        # not for default domain (subscription).
        if subscription:
            account_alias = dict(
                name=customer,
                forwarding=filter_dict(
                    addresses=[
                        "{customer}@{subscription}".format(
                            customer=customer,
                            subscription=subscription
                        )
                    ]
                )
            )
            da_aliases.append(account_alias)

        # Dump other aliases
        for line in lines:
            splitted_line = line.split(':', 1)
            if len(splitted_line) != 2:
                continue
            da_alias_name = splitted_line[0].strip()
            da_alias_value = splitted_line[1].strip()
            if da_alias_name == '*' or da_alias_name == customer:
                continue
            da_alias_warn = warn(
                self._warnings,
                safe_format(
                    u"mailbox '{mailbox}@{domain}'",
                    mailbox=da_alias_name,
                    domain=idn_domain
                ),
                display=False
            )
            da_alias = filter_dict(
                name=da_alias_name,
                forwarding=filter_dict(
                    addresses=[da_alias_value]
                )
            )
            da_aliases.append(da_alias)
            close_warn(self._warnings, da_alias_warn)
        return da_aliases

    def _get_mailbox_quota(self, mailbox, domain):
        """
        :type mailbox: str | unicode
        :type domain: str | unicode
        :rtype: str | unicode | None 
        """
        lines = get_lines(
            self._warnings,
            "/etc/virtual/{domain}/quota".format(domain=domain),
            skip_error=True
        )
        for line in lines:
            splitted_line = line.split(':', 1)
            if len(splitted_line) != 2:
                continue
            mailbox_name, quota = splitted_line
            if mailbox_name == mailbox:
                return quota if quota != '0' else '-1'
        return None

    def _get_da_vacation_messages(self, mailbox, domain):
        """
        :type mailbox: str | unicode
        :type domain: str | unicode
        :rtype: dict 
        """
        lines = get_lines(
            self._warnings,
            "/etc/virtual/{domain}/vacation.conf".format(domain=domain),
            skip_error=True
        )
        vacation_message = {}
        for line in lines:
            splitted_line = line.split(':', 1)
            if len(splitted_line) != 2:
                continue
            mailbox_name, vacation_string = splitted_line
            if mailbox_name != mailbox:
                continue
            da_vm = {}
            for item in vacation_string.split('&'):
                splitted_item = item.split('=', 1)
                if len(splitted_item) != 2:
                    continue
                param, value = splitted_item
                if param == "endday":
                    da_vm["endday"] = value
                elif param == "endmonth":
                    da_vm["endmonth"] = value
                elif param == "endyear":
                    da_vm["endyear"] = value
            if "endday" in da_vm and "endmonth" in da_vm and "endyear" in da_vm:
                end_date = "{year}-{month}-{day}".format(
                    year=da_vm["endyear"],
                    month=da_vm["endmonth"],
                    day=da_vm["endday"]
                )
            else:
                end_date = None
            if os.path.isfile(
                    "/etc/virtual/{domain}/reply/{mailbox}.msg".format(
                        domain=domain,
                        mailbox=mailbox
                    )
            ):
                enabled = True
                message = get_file_content(
                    self._warnings,
                    "/etc/virtual/{domain}/reply/{mailbox}.msg".format(
                        domain=domain,
                        mailbox=mailbox
                    ),
                    skip_error=True
                )
            else:
                enabled = False
                message = get_file_content(
                    self._warnings,
                    "/etc/virtual/{domain}/reply/{mailbox}.msg_off".format(
                        domain=domain,
                        mailbox=mailbox
                    ),
                    skip_error=True
                )
            if message is None:
                message = ''
            vacation_message.update(dict(
                subject="Re: <request_subject>",
                message=message,
                enabled=enabled
            ))
            vacation_message.update(filter_dict(
                end_date=end_date
            ))
        return vacation_message

    def _get_password(self, user):
        """
        :type user: str | unicode
        :rtype: str | unicode | None 
        """
        lines = get_lines(
            self._warnings,
            "/home/{name}/.shadow".format(
                name=user
            )
        )
        return lines[0].lstrip("!") if len(lines) > 0 else None

    def _get_dns_zone(self, context):
        """
        :type context: context.Context
        :rtype: dict 
        """
        if context.alias is not None:
            domain = context.alias
        elif context.addon_domain is not None:
            domain = context.addon_domain
        else:
            domain = context.subscription
        dns_zone_warn = warn(
            self._warnings,
            safe_format(u"dns zone '{name}'", name=domain),
            display=False
        )
        dns_zone = {}
        dns_zone.update(filter_dict(
            type="master",
            dns_records=self._get_dns_records(context, domain)
        ))
        close_warn(self._warnings, dns_zone_warn)
        return dns_zone

    def _get_dns_records(self, context, domain):
        """
        :type context: context.Context
        :type domain: str | unicode
        :rtype: list 
        """
        da_dns_records = get_lines(
            self._warnings,
            "/var/named/{domain}.db".format(domain=domain),
            skip_error=True
        )
        dns_records = []
        for da_dns_record in da_dns_records:
            with try_safe(error_message='Failed to get DNS record', context=context):
                dns_record = self._get_dns_record(da_dns_record, domain)
                if dns_record is not None:
                    dns_records.append(dns_record)
        return dns_records

    def _get_dns_record(self, dns_record, domain):
        """
        :type dns_record: str | unicode
        :type domain: str | unicode
        :rtype: dict 
        """
        record = safe_idn_decode(dns_record).split(None, 4)
        if len(record) < 5:
            return None
        if record[2] == 'SOA':
            return None
        src = record[0]
        if src.endswith('_domainkey'):
            return None
        rec_type = record[3]
        content = record[4]
        # Max length which can be passed to Plesk cli
        if len(content) > 255:
            return None
        dns_record_warn = warn(
            self._warnings,
            safe_format(
                u"    DNS record '{name} {type} {content}'",
                name=src,
                type=rec_type,
                content=content
            ),
            display=False
        )
        dns_record = {}
        dns_record.update(dict(
            src=src,
            type=rec_type,
            dst=content
        ))
        idn_key = safe_idn_decode(domain)
        if rec_type == "MX":
            splitted_content = content.split(' ', 1)
            if len(splitted_content) == 2:
                opt, dst = splitted_content
                dns_record.update(dict(
                    dst=dst,
                    opt=opt
                ))
                try:
                    if int(opt) > 50:
                        dns_record.update(dict(
                            opt="50"
                        ))
                    elif int(opt) < 0:
                        dns_record.update(dict(
                            opt="0"
                        ))
                except Exception:
                    warn(
                        self._warnings,
                        safe_format(
                            u"      Failed to get priority of MX DNS record '{name} {type} {content}'",
                            name=src,
                            type=rec_type,
                            content=content
                        ),
                        color=Color.yellow
                    )
                    dns_record.update(dict(
                        opt="10"
                    ))
                if not dst.endswith('.'):
                    dns_record.update(dict(
                        dst=dst + '.' + idn_key + '.',
                    ))
        if not src.endswith('.'):
            dns_record.update(dict(
                src=src + '.' + idn_key
            ))
        if dns_record["type"] == "TXT":
            dns_record.update(dict(
                dst=content.strip('"')
            ))
        close_warn(self._warnings, dns_record_warn)
        return dns_record

    def _get_ftp_users(self, context):
        """
        :type context: context.Context
        :rtype: list 
        """
        owner = self._get_owner_from_context(context)
        ftp_passwd_lines = get_lines(
            self._warnings,
            "/etc/proftpd.passwd"
        )
        owner_uid = None
        owner_gid = None
        # Find owner's uid/gid
        for ftp_passwd_line in ftp_passwd_lines:
            splitted_line = ftp_passwd_line.split(':')
            if len(splitted_line) < 4:
                continue
            user = splitted_line[0]
            if user == owner:
                owner_uid = splitted_line[2]
                owner_gid = splitted_line[3]
                break
        ftp_users = []
        # Find users with the same uid/gid as owner has
        if owner_uid and owner_gid:
            for ftp_passwd_line in ftp_passwd_lines:
                splitted_line = ftp_passwd_line.split(':')
                if len(splitted_line) < 6:
                    continue
                user, password, uid, gid, _, home_directory = splitted_line[:6]
                if uid == owner_uid and gid == owner_gid and user != owner:
                    child_context = context.clone(ftp_user=user)
                    with try_safe(error_message='Failed to get FTP user', context=child_context):
                        new_ftp_user = self._get_ftp_user(
                            child_context, password=password, home_directory=home_directory
                        )
                        ftp_users.append(new_ftp_user)
        return ftp_users

    def _get_ftp_user(self, context, password, home_directory):
        """
        :type context: context.Context
        :type password: str | unicode
        :type home_directory: str | unicode | None
        :rtype: dict 
        """
        owner = self._get_owner_from_context(context)
        login = context.ftp_user
        ftp_user_warn = warn(
            self._warnings,
            safe_format(u"ftp user '{name}'", name=login)
        )
        ftp_user = dict(login=login)
        with try_safe(error_message='Failed to get home directory of FTP user', context=context):
            home_directory_prefix = "/home/{user}".format(user=owner)
            if home_directory.startswith(home_directory_prefix):
                ftp_user.update(dict(
                    home_directory=home_directory[len(home_directory_prefix):]
                ))
            else:
                ftp_user.update(dict(
                    home_directory=home_directory
                ))
        with try_safe(error_message='Failed to get password of FTP user', context=context):
            if password is not None:
                ftp_user.update(dict(
                    password=password,
                    password_type="hash"
                ))
            close_warn(self._warnings, ftp_user_warn)
        return ftp_user

    def _get_shell(self, owner):
        """
        :type owner: str | unicode
        :rtype: str | unicode 
        """
        lines = get_lines(
            self._warnings,
            "/etc/passwd",
            skip_error=True
        )
        for line in lines:
            splitted_line = line.split(':')
            if len(splitted_line) < 7:
                continue
            user = splitted_line[0]
            shell = splitted_line[6]
            if user == owner:
                if shell == '/bin/bash':
                    return '/bin/bash'
                else:
                    return '/bin/false'
        return '/bin/false'

    def _get_certificates(self, context):
        """
        :type context: context.Context
        :rtype: list 
        """
        owner = self._get_owner_from_context(context)
        if context.addon_domain is not None:
            domain = context.addon_domain
        else:
            domain = context.subscription
        certificates = []
        certificate = {}
        idn_domain = safe_idn_decode(domain)
        config_filename = "/usr/local/directadmin/data/users/{user}/domains/{domain}.conf".format(
            user=owner,
            domain=domain
        )
        # get certificate
        cert = None
        cert_file = utils.get_value(self._warnings, config_filename, "SSLCertificateFile", skip_error=True)
        if cert_file is not None:
            cert = get_file_content(self._warnings, cert_file, skip_error=True)
            if cert is not None:
                cert = cert.strip()

        # get key
        key = None
        key_file = utils.get_value(self._warnings, config_filename, "SSLCertificateKeyFile", skip_error=True)
        if key_file is not None:
            key = get_file_content(self._warnings, key_file, skip_error=True)
            if key is not None:
                key = key.strip()
            # key_temp = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
            # key_final = crypto.dump_privatekey(crypto.FILETYPE_PEM, key_temp)

        # Certificate and private key are required in Plesk
        if cert is not None and key is not None:
            certificate.update(dict(
                name=idn_domain,
                certificate=cert,
                private_key=key
            ))
            # get ca certificate
            ca_cert = None
            ca_cert_file = utils.get_value(self._warnings, config_filename, "SSLCACertificateFile", skip_error=True)
            if ca_cert_file is not None:
                ca_cert = get_file_content(self._warnings, ca_cert_file, skip_error=True)
                if ca_cert is not None:
                    ca_cert = ca_cert.strip()
            if ca_cert is not None:
                certificate.update(dict(
                    ca_certificate=ca_cert
                ))
            certificates.append(certificate)
        return certificates

    def _get_limits(self, context):
        """
        :type context: context.Context
        :rtype: dict 
        """
        limits = {}
        da_limits = {}
        with try_safe(error_message='Failed to get limits of subscription', context=context):
            owner = self._get_owner_from_context(context)
            lines = get_lines(
                self._warnings,
                "/usr/local/directadmin/data/users/{customer}/user.conf".format(
                    customer=owner
                ),
                skip_error=True
            )
            for line in lines:
                splitted_line = line.split('=', 1)
                if len(splitted_line) != 2:
                    continue
                limit_name, limit_value = splitted_line
                da_limits[limit_name] = limit_value

            with try_safe(error_message='Failed to get "disk_space" limit of subscription', context=context):
                limits.update(dict(
                    disk_space=self._get_limit(da_limits, 'quota', convert_to_bytes=True)
                ))
            with try_safe(error_message='Failed to get "max_traffic" limit of subscription', context=context):
                limits.update(dict(
                    max_traffic=self._get_limit(da_limits, 'bandwidth', convert_to_bytes=True)
                ))
            with try_safe(error_message='Failed to get "max_subdom" limit of subscription', context=context):
                limits.update(dict(
                    max_subdom=self._get_limit(da_limits, 'nsubdomains')
                ))
            with try_safe(error_message='Failed to get "max_box" limit of subscription', context=context):
                limits.update(dict(
                    max_box=self._get_limit(da_limits, 'nemails')
                ))
            with try_safe(error_message='Failed to get "max_maillists" limit of subscription', context=context):
                limits.update(dict(
                    max_maillists=self._get_limit(da_limits, 'nemailml')
                ))
            with try_safe(error_message='Failed to get "max_subftp_users" limit of subscription', context=context):
                limits.update(dict(
                    max_subftp_users=self._get_limit(da_limits, 'ftp')
                ))
            with try_safe(error_message='Failed to get "max_db" limit of subscription', context=context):
                limits.update(dict(
                    max_db=self._get_limit(da_limits, 'mysql')
                ))
            # Domain pointers with redirect (not aliases) will be converted to addon domains,
            # max_site should be dumped as sum of vdomains and domainptr
            with try_safe(
                    error_message='Failed to get "max_site" and "max_dom_aliases" limits of subscription',
                    context=context
            ):
                max_site = self._get_limit(da_limits, 'vdomains')
                max_dom_aliases = self._get_limit(da_limits, 'domainptr')
                if max_site != '-1':
                    if max_dom_aliases == '-1':
                        max_site = '-1'
                    else:
                        max_site = str(int(max_site) + int(max_dom_aliases))
                limits.update(dict(
                    max_site=max_site,
                    max_dom_aliases=max_dom_aliases
                ))
        # Limits which should be set to unlimited if not defined to avoid default Plesk limits
        default_unlimited = [
            'disk_space',
            'max_box',
            'max_mbox',
            'max_db',
            'max_dom_aliases',
            'max_maillists',
            'max_site',
            'max_subdom',
            'max_subftp_users',
            'max_traffic',
            'mbox_quota'
        ]
        for limit in default_unlimited:
            if limit not in limits:
                limits[limit] = '-1'
        return limits

    @staticmethod
    def _get_limit(da_limits, limit_name, convert_to_bytes=False):
        """
        :type da_limits: dict
        :type limit_name: str | unicode
        :type convert_to_bytes: bool
        :rtype: str | unicode
        """
        if limit_name in da_limits and da_limits[limit_name].isdigit():
            if convert_to_bytes:
                return str(int(da_limits[limit_name]) * 1048576)
            return da_limits[limit_name]
        else:
            return '-1'

    def _get_protected_directories(self, context):
        """
        :type context: context.Context
        :rtype: list 
        """
        protected_directories = []
        owner = self._get_owner_from_context(context)
        if context.addon_domain is not None:
            domain = context.addon_domain
        else:
            domain = context.subscription
        da_protected_directories = get_lines(
            self._warnings,
            "/home/{user}/domains/{domain}/.htpasswd/.protected.list".format(
                user=owner,
                domain=domain
            ),
            skip_error=True
        )
        for da_protected_directory in da_protected_directories:
            if context.subdomain is not None:
                correct_path = '/domains/{domain}/public_html/{subdomain}'.format(
                    domain=domain,
                    subdomain=context.subdomain
                )
            else:
                correct_path = '/domains/{domain}/public_html'.format(
                    domain=domain
                )
            if not da_protected_directory.startswith(correct_path + '/') and not da_protected_directory == correct_path:
                continue
            protected_directory_path = os.path.join("/home/{user}".format(user=owner),
                                                    da_protected_directory.lstrip('/'))
            if not os.path.isdir(protected_directory_path):
                warn(
                    self._warnings,
                    safe_format(
                        u"protected directory '{directory}' is not found and will be skipped'",
                        directory=da_protected_directory
                    ),
                    color=Color.yellow
                )
                continue
            protected_directory = {}
            idn_path = safe_idn_decode(da_protected_directory.split(correct_path)[1])
            if not idn_path.startswith('/'):
                idn_path = '/' + idn_path
            protected_directory.update(filter_dict(
                path=idn_path,
                title=self._get_protected_directory_param(
                    owner,
                    da_protected_directory,
                    "AuthName"
                ),
                users=self._get_protected_directory_users(
                    self._get_protected_directory_param(
                        owner,
                        da_protected_directory,
                        "AuthUserFile"
                    )
                )
            ))
            protected_directories.append(protected_directory)
        return protected_directories

    def _get_protected_directory_param(self, user, protected_directory, param):
        """
        :type user: str | unicode
        :type protected_directory: str | unicode
        :type param: str | unicode
        :rtype: str | unicode | None 
        """
        lines = get_lines(
            self._warnings,
            "/home/{user}{directory}/.htaccess".format(
                user=user,
                directory=protected_directory
            )
        )
        for line in lines:
            splitted_line = line.split(' ', 1)
            if len(splitted_line) != 2:
                continue
            opt, val = splitted_line
            if opt == param:
                return val.strip('"')

    def _get_protected_directory_users(self, protected_directory):
        """
        :type protected_directory: str | unicode
        :rtype: list 
        """
        da_protected_directory_users = get_lines(
            self._warnings,
            protected_directory,
            skip_error=True
        )
        protected_directory_users = []
        for da_protected_directory_user in da_protected_directory_users:
            protected_directory_user = {}
            splitted_line = da_protected_directory_user.split(':', 1)
            if len(splitted_line) != 2:
                continue
            login, password = splitted_line
            protected_directory_user.update(filter_dict(
                login=login,
                password=password,
                password_type="hash" if password else None
            ))
            protected_directory_users.append(protected_directory_user)
        return protected_directory_users

    def _get_scheduled_tasks(self, context):
        """
        :type context: context.Context
        :rtype: list 
        """
        owner = self._get_owner_from_context(context)
        cron_file_content = get_file_content(
            self._warnings,
            "/var/spool/cron/{user}".format(
                user=owner
            ),
            skip_error=True
        )
        if cron_file_content is None:
            return None
        scheduled_tasks = []
        parsed_cron = Cron.parse_crontab_content(cron_file_content)
        mailto = parsed_cron.mailto
        for expression in parsed_cron.expressions:
            if mailto and '@' not in mailto:
                mailto += '@' + context.subscription
            scheduled_task = filter_dict(
                type="exec",
                command=expression.command,
                is_active=False,
                minute=expression.minutes,
                hour=expression.hours,
                day_of_week=expression.day_of_week,
                day_of_month=expression.day_of_month,
                month=expression.month,
                notifications_email=mailto,
                notify="every_time"
            )
            scheduled_tasks.append(scheduled_task)
        return scheduled_tasks

    def _get_ip_addresses(self, context):
        """
        :type context: context.Context
        :rtype: list 
        """
        if context.addon_domain is not None:
            domain = context.addon_domain
        else:
            domain = context.subscription
        owner = self._get_owner_from_context(context)
        da_ip_addresses = get_lines(
            self._warnings,
            "/usr/local/directadmin/data/users/{user}/domains/{domain}.ip_list".format(
                user=owner, domain=domain
            )
        )
        ip_addresses = []
        for da_ip_address in da_ip_addresses:
            if is_ipv4(da_ip_address) or is_ipv6(da_ip_address):
                ip_address = dict(
                    type='shared',
                    address=da_ip_address
                )
                ip_addresses.append(ip_address)
        return ip_addresses
