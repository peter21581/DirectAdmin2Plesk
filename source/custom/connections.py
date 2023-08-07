"""Connections to source custom panel servers"""

from parallels.core.migrator_config import PhysicalServerConfig, read_copy_mail_content_settings
from parallels.core.connections.connections import Connections
from parallels.core.connections.source_server import SourceServer
from parallels.core.panels import get_additional_source_panel, is_additional_source_panel
from parallels.core.utils.config_utils import ConfigSection, get_sections_list
from parallels.core.utils.entity import Entity
from parallels.core.utils.common import group_by_id, cached, is_run_on_windows
from parallels.core.utils.windows_mysql_client_deploy import deploy_mysqldump
from parallels.core.utils.windows_mysql_client_deploy import deploy_mysql_client
from parallels.plesk.hosting_description.config import HostingDescriptionConfig
from parallels.plesk.hosting_description.validate.mode import ValidationMode
from parallels.plesk.source.custom import messages


class MigratorConnections(Connections):
    @cached
    def get_source_by_id(self, source_id):
        source_config = self.get_source_config_by_id(source_id)
        if isinstance(source_config, PhysicalServerConfig):
            return CustomPanelSourceServer(source_id, source_config, self._global_context.migrator_server)
        return super(MigratorConnections, self).get_source_by_id(source_id)

    def get_stats_server(self):
        """Get source panel IP address that will be saved in statistics report

        If we don't know it (for example in case of custom migration with absolutely no access
        to the source server) - return None

        :rtype: str | unicode | None
        """
        section_names = self._get_source_config_section_names()
        if len(section_names) == 0:
            return None
        first_section_name = section_names[0]
        first_source_server = self.get_source_server_by_id(first_section_name)
        if first_source_server:
            return first_source_server
        else:
            return None

    def get_plesk_configuration_dump_paths(self):
        """
        :rtype: dict[str | unicode, str | unicode]
        """
        dump_paths = {}

        for section_name in self._get_source_config_section_names():
            if self._config.has_option(section_name, 'plesk-configuration-dump'):
                # for Plesk configuration dump, just provide the path specified in config
                dump_paths[section_name] = self._config.get(section_name, 'plesk-configuration-dump')
            elif (
                    self._config.has_option(section_name, 'hosting-description') or
                    get_additional_source_panel(self._global_context)
            ):
                # for hosting description path, provide path, where Plesk configuration dump will be put
                dump_paths[section_name] = self._global_context.session_files.get_raw_dump_filename(section_name)

        return dump_paths

    def iter_hosting_description_configs(self):
        """
        :rtype: collections.Iterable[parallels.plesk.hosting_description.config.HostingDescriptionConfig]
        """
        for section_name in self._get_source_config_section_names():
            section = ConfigSection(self._config, section_name)
            source_panel = get_additional_source_panel(self._global_context)
            default_description_format = 'yaml'
            default_hosting_description = None
            if is_additional_source_panel(self._global_context):
                default_validation_mode = ValidationMode.WARN
            else:
                default_validation_mode = ValidationMode.STOP
            if source_panel is not None:
                default_description_format = source_panel.hosting_description_format
                default_hosting_description = self._global_context.session_files.get_hosting_description_file(
                    section_name, default_description_format
                )
            if 'hosting-description' in section or source_panel is not None:
                yield HostingDescriptionConfig(
                    source_id=section_name,
                    path=section.get('hosting-description', default_hosting_description),
                    file_format=section.get('description-format', default_description_format).lower(),
                    validation_mode=section.get('validation-mode', default_validation_mode).lower(),
                    mail_settings=read_copy_mail_content_settings(section, is_run_on_windows())
                )

    def iter_database_servers(self):
        """
        :rtype: collections.Iterable[parallels.custom_panel_migrator.connections.DatabaseServerConfig]
        """
        for section_name in self._get_source_database_servers_config_sections():
            section = ConfigSection(self._config, section_name)
            yield DatabaseServerConfig(
                db_server_id=section_name,
                db_type=section.get('type'),
                host=section.get('host'),
                port=section.get('port'),
                login=section.get('login'),
                password=section.get_password('password')
            )

    def get_hosting_description_config(self, server_id):
        """
        :type server_id: str | unicode
        :rtype: parallels.plesk.hosting_description.config.HostingDescriptionConfig
        """
        hosting_description_configs = group_by_id(self.iter_hosting_description_configs(), lambda l: l.source_id)
        return hosting_description_configs[server_id]

    def has_hosting_description_config(self, server_id):
        """
        :type server_id: str | unicode
        :rtype: bool
        """
        hosting_description_configs = group_by_id(self.iter_hosting_description_configs(), lambda l: l.source_id)
        return server_id in hosting_description_configs

    def get_plesk_configuration_dump_path(self, dump_id):
        """Get path to Plesk configuration dump file by its ID (which is the same as section name in configuration file)

        :type dump_id: str | unicode
        :rtype: str | unicode
        """
        dump_paths = self.get_plesk_configuration_dump_paths()
        if dump_id not in dump_paths:
            raise Exception(messages.UNABLE_TO_GET_DUMP_PATH % dump_id)
        return dump_paths[dump_id]

    def _get_source_database_servers_config_sections(self):
        """Get names of sections describing database servers
        :rtype: list[str | unicode]
        """
        return get_sections_list(self._config, 'GLOBAL', 'db-servers')


class DatabaseServerConfig(Entity):
    def __init__(self, db_server_id, db_type, host, port, login, password):
        """
        :type db_server_id: str | unicode
        :type db_type: str | unicode
        :type host: str | unicode
        :type port: str | unicode
        :type login: str | unicode
        :type password: str | unicode
        """
        self._db_server_id = db_server_id
        self._db_type = db_type
        self._host = host
        self._port = port
        self._login = login
        self._password = password

    @property
    def db_server_id(self):
        """Database server ID - name of a section of the server in migrator's configuration file

        :rtype: str | unicode
        """
        return self._db_server_id

    @property
    def db_type(self):
        """Database type - 'mysql' or 'mssql'

        :rtype: str | unicode
        """
        return self._db_type

    @property
    def host(self):
        """Database server host - hostname or IP address

        :rtype: str | unicode
        """
        return self._host

    @property
    def port(self):
        """Database server port

        :rtype: str | unicode
        """
        return self._port

    @property
    def login(self):
        """Administrator login of database server

        :rtype: str | unicode
        """
        return self._login

    @property
    def password(self):
        """Administrator password of database server

        :rtype: str | unicode
        """
        return self._password


class CustomPanelSourceServer(SourceServer):
    """Source server for migration from custom panel"""


    @cached
    def get_path_to_mysqldump(self):
        """
        :rtype: str | unicode
        """
        if self.is_windows():
            return deploy_mysqldump(self)
        else:
            return 'mysqldump'
        
    @cached
    def get_path_to_mysql(self):
        """
        :rtype: str | unicode
        """
        if self.is_windows():
            return deploy_mysql_client(self)
        else:
            return 'mysql'

    def mysql_use_skip_secure_auth(self):
        """Whether to pass --skip-secure-auth flag to MySQL client

        This flag is necessary when client version is greater than server version.
        We deploy own MySQL client, it could be of greater version than server,
        so we should pass the flag.
        """
        return True
