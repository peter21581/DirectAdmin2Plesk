from parallels.core import MigrationNoRepeatError, MigrationError
from parallels.core import safe_format
from parallels.core.actions.base.common_action import CommonAction
from parallels.core.logging import get_logger
from parallels.core.panels import get_additional_source_panel, AdditionalSourcePanelConfig
from parallels.core.runners.base import BaseRunner
from parallels.core.runners.entities import ExecutionOptions
from parallels.core.utils.common_constants import AI_URL
from parallels.core.utils.os_version import detect_os_version, detect_os_architecture, OSArchitecture, OSName
from parallels.core.utils.thirdparties import packages
from parallels.core.utils.thirdparties.deployer import ThirdpartyDeployer
from parallels.plesk.source.custom import messages
from parallels.plesk.source.custom.utils.config_getter import get_configs, ConfigFilter, \
    configs_with_source_server_exist

logger = get_logger(__name__)


class DeployMigratorPython(CommonAction):
    """Deploy required python packages on source"""

    PYTHON_PACKAGES = ['plesk-py27', 'plesk-py27-pyyaml']
    PYTHON_BIN_UNIX = '/opt/plesk/python/2.7/bin/python'

    def get_failure_message(self, global_context):
        """Get message for situation when action failed

        :type global_context: parallels.core.global_context.GlobalMigrationContext
        :rtype: str | unicode
        """
        return messages.ACTION_FAILED_DEPLOY_MIGRATOR_PYTHON

    def get_description(self):
        """Get short description of action as string

        :rtype: str | unicode
        """
        return messages.ACTION_DESCRIPTION_DEPLOY_MIGRATOR_PYTHON

    def filter_action(self, global_context):
        """Check whether we should run this action or not. By default True - action should be executed.

        Arguments:
        - global_context - registry with different objects that reused among different actions

        :type global_context: parallels.core.global_context.GlobalMigrationContext
        :rtype: bool
        """
        source_panel = get_additional_source_panel(global_context)
        if source_panel is None:
            return False
        return (
                configs_with_source_server_exist(global_context)
                and source_panel.execution == AdditionalSourcePanelConfig.EXTENSION_ENTRY_POINT_MIGRATOR_PYTHON
        )

    def run(self, global_context):
        """Run action

        :type global_context: parallels.plesk.source.custom.global_context.CustomPanelGlobalMigrationContext
        :rtype: None
        """
        hd_generation_can_be_skipped = get_configs(global_context, ConfigFilter.HD_GENERATION_CAN_BE_SKIPPED)
        need_deploy_python = get_configs(global_context, ConfigFilter.NEED_DEPLOY_PYTHON)
        for config in hd_generation_can_be_skipped:
            if config not in need_deploy_python:
                logger.finfo(messages.SKIP_INSTALL_PYTHON, hosting_description_file=config.path)

        for hosting_description_config in need_deploy_python:
            source = global_context.conn.get_source_by_id(hosting_description_config.source_id)
            self._install_migrator_python(source)

    @classmethod
    def _install_migrator_python(cls, server):
        """Install python on source server

        :type server: parallels.core.connections.source_server.SourceServer
        :rtype: None
        """
        os_type, version = detect_os_version(server)
        if version is not None:
            version = version.split('.')[0]
        arch = detect_os_architecture(server)
        server_description = server.description()
        logger.finfo(
            messages.SOURCE_OS_DETECTED, source_os_type=os_type, source_os_version=version, source_os_arch=arch,
            source_description=server_description
        )
        debian_oses = {
            (OSName.OS_DEBIAN, '6'): ('squeeze', 'debian/PMM_0.1.10'),
            (OSName.OS_DEBIAN, '7'): ('wheezy', 'debian/PMM_0.1.10'),
            (OSName.OS_DEBIAN, '8'): ('jessie', 'PMM_0.1.11'),
            (OSName.OS_DEBIAN, '9'): ('stretch', 'PMM_0.1.11'),
            (OSName.OS_DEBIAN, '10'): ('buster', 'PMM_0.1.11'),
            (OSName.OS_UBUNTU, '12'): ('precise', 'ubuntu/PMM_0.1.10'),
            (OSName.OS_UBUNTU, '14'): ('trusty', 'ubuntu/PMM_0.1.10'),
            (OSName.OS_UBUNTU, '16'): ('xenial', 'PMM_0.1.11'),
            (OSName.OS_UBUNTU, '18'): ('bionic', 'PMM_0.1.11'),
        }
        redhat_oses = {
            (OSName.OS_CENTOS, '5'): 'PMM_0.1.10',
            (OSName.OS_CENTOS, '6'): 'PMM_0.1.11',
            (OSName.OS_CENTOS, '7'): 'PMM_0.1.11',
            (OSName.OS_CENTOS, '8'): 'PMM_0.1.11',
            (OSName.OS_RHEL, '5'): 'PMM_0.1.10',
            (OSName.OS_RHEL, '6'): 'PMM_0.1.11',
            (OSName.OS_RHEL, '7'): 'PMM_0.1.11',
            (OSName.OS_RHEL, '8'): 'PMM_0.1.11',
            (OSName.OS_CLOUDLINUX, '5'): 'PMM_0.1.10',
            (OSName.OS_CLOUDLINUX, '6'): 'PMM_0.1.11',
            (OSName.OS_CLOUDLINUX, '7'): 'PMM_0.1.11',
            (OSName.OS_CLOUDLINUX, '8'): 'PMM_0.1.11',
            (OSName.OS_CLOUDLINUX, '9'): 'PMM_0.1.11',
        }
        debian_os = debian_oses.get((os_type, version))
        redhat_os = redhat_oses.get((os_type, version))
        if debian_os:
            cls._install_packages_debian(server, os_type, debian_os[0], arch, debian_os[1])
        elif redhat_os:
            cls._install_packages_centos(server, os_type, version, arch, redhat_os)
        elif os_type == OSName.OS_WINDOWS:
            cls._install_packages_windows(server)
        else:
            raise MigrationNoRepeatError(safe_format(
                messages.SOURCE_OS_NOT_SUPPORTED, source_os_type=os_type, source_os_version=version,
                source_os_arch=arch, source_description=server_description
            ))

    @classmethod
    def _install_packages_windows(cls, server):
        """Install required Python packages on Windows OSes

        :type server: parallels.core.connections.source_server.SourceServer
        :rtype: None
        """
        ThirdpartyDeployer.get_instance().deploy(packages.PythonWindowsAdditionalPanels, server)

    @classmethod
    def _check_packages_centos(cls, runner):
        """Check installation of required Python packages on RedHat based OSes

        :type runner: parallels.core.runners.base.BaseRunner
        :rtype: list[str | unicode]
        """
        not_installed_packages = []
        for package in cls.PYTHON_PACKAGES:
            exit_code = runner.execute_command(
                'rpm -q {package}', dict(package=package), ExecutionOptions(ignore_exit_code=True)
            ).exit_code
            if exit_code != 0:
                not_installed_packages.append(package)
        return not_installed_packages

    @classmethod
    def _install_packages_centos(cls, server, os_name, os_version, os_architecture, url_path):
        """Install required Python packages on RedHat based OSes

        :type server: parallels.core.connections.source_server.SourceServer
        :type os_name: str | unicode
        :type os_version: str | unicode
        :type os_architecture: str | unicode
        :type url_path: str | unicode
        :rtype: None
        """
        with server.runner() as runner:
            assert isinstance(runner, BaseRunner)
            not_installed_packages = cls._check_packages_centos(runner)
            server_description = server.description()
            if len(not_installed_packages) > 0:
                logger.finfo(messages.INSTALL_PYTHON, source_description=server_description)
                repo_file = '/etc/yum.repos.d/plesk-migrator.repo'
                if os_architecture == OSArchitecture.X86_64:
                    os_arch = os_architecture
                else:
                    os_arch = 'i386'
                repo_content = safe_format(
                    """[plesk-migrator]
name=Plesk packages for migrator
baseurl={ai_url}/{url_path}/dist-rpm-CentOS-{os_version}-{os_arch}
enabled=1
gpgcheck=1
gpgkey={ai_url}/plesk.gpg
""",
                    ai_url=AI_URL, url_path=url_path, os_version=os_version, os_arch=os_arch
                ).encode('utf-8')
                runner.upload_file_content(repo_file, repo_content)
                python_packages = dict()
                install_command = u'yum install -y -q'
                for num, package in enumerate(cls.PYTHON_PACKAGES):
                    key = 'package_%s' % num
                    install_command += u' {%s}' % key
                    python_packages[key] = package
                runner.execute_command(install_command, python_packages)
                not_installed_packages = cls._check_packages_centos(runner)
                if len(not_installed_packages) > 0:
                    raise MigrationError(safe_format(
                        messages.NOT_INSTALLED_PACKAGES,
                        source_os_type=os_name, source_os_version=os_version, source_os_arch=os_architecture,
                        source_description=server_description, packages=' '.join(not_installed_packages)
                    ))
            else:
                logger.finfo(messages.PYTHON_ALREADY_INSTALLED, source_description=server_description)

    @classmethod
    def _check_packages_debian(cls, runner):
        """Check installation of required Python packages on Debian based OSes

        :type runner: parallels.core.runners.base.BaseRunner
        :rtype: list[str | unicode]
        """
        not_installed_packages = []
        for package in cls.PYTHON_PACKAGES:
            if not cls._package_installed_debian(runner, package):
                not_installed_packages.append(package)
        return not_installed_packages

    @classmethod
    def _package_installed_debian(cls, runner, package):
        """Check installation of required package on Debian based OSes

        :type runner: parallels.core.runners.base.BaseRunner
        :rtype: bool
        """
        exit_code = runner.execute_command(
            'dpkg -s {package}', dict(package=package),
            ExecutionOptions(ignore_exit_code=True)
        ).exit_code
        if exit_code == 0:
            return True
        return False

    @classmethod
    def _install_packages_debian(cls, server, os_name, os_version, os_architecture, url_path):
        """Install required Python packages on Debian based OSes

        :type server: parallels.core.connections.source_server.SourceServer
        :type os_name: str | unicode
        :type os_version: str | unicode
        :type os_architecture: str | unicode
        :type url_path: str | unicode
        :rtype: None
        """
        with server.runner() as runner:
            assert isinstance(runner, BaseRunner)
            server_description = server.description()

            if (os_name, os_version) == ('ubuntu', 'bionic'):
                failed_package = cls._prepare_ubuntu_bionic(runner)
                if failed_package is not None:
                    raise MigrationError(safe_format(
                        messages.NOT_INSTALLED_PACKAGES,
                        source_os_type=os_name, source_os_version=os_version, source_os_arch=os_architecture,
                        source_description=server_description, packages=failed_package
                    ))

            not_installed_packages = cls._check_packages_debian(runner)
            if len(not_installed_packages) > 0:
                logger.finfo(messages.INSTALL_PYTHON, source_description=server_description)
                repo_dir = '/etc/apt/sources.list.d'
                repo_file = 'plesk-migrator.list'
                if os_architecture == OSArchitecture.X86_64:
                    os_arch = '[arch=amd64]'
                else:
                    os_arch = ''
                repo_content = safe_format(
                    "deb {arch} {ai_url}/{url_path} {os_version} all\n",
                    arch=os_arch, ai_url=AI_URL, url_path=url_path, os_version=os_version
                ).encode('utf-8')
                runner.mkdir(repo_dir)
                runner.upload_file_content(server.join_file_path(repo_dir, repo_file), repo_content)
                runner.execute_command(safe_format('wget -qO - {ai_url}/plesk.gpg | apt-key add -', ai_url=AI_URL))
                runner.execute_command(
                    'apt-get update -qq -o Dir::Etc::sourcelist="sources.list.d/plesk-migrator.list" '
                    '-o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup="0"'
                )
                python_packages = dict()
                install_command = (
                    u'apt-get install -y -qq -o APT::Install-Suggests=false -o APT::Install-Recommends=false'
                )
                for num, package in enumerate(cls.PYTHON_PACKAGES):
                    key = 'package_%s' % num
                    install_command += u' {%s}' % key
                    python_packages[key] = package
                runner.execute_command(install_command, python_packages)
                not_installed_packages = cls._check_packages_debian(runner)
                if len(not_installed_packages) > 0:
                    raise MigrationError(safe_format(
                        messages.NOT_INSTALLED_PACKAGES,
                        source_os_type=os_name, source_os_version=os_version, source_os_arch=os_architecture,
                        source_description=server_description, packages=' '.join(not_installed_packages)
                    ))
            else:
                logger.finfo(messages.PYTHON_ALREADY_INSTALLED, source_description=server_description)

    @classmethod
    def _prepare_ubuntu_bionic(cls, runner):
        """Install required 'gnupg' package if it is not installed
        Returns package name if package installation was failed or None if success

        :type runner: parallels.core.runners.base.BaseRunner
        :rtype: str | unicode | None
        """
        package = 'gnupg'
        if cls._package_installed_debian(runner, package):
            return

        runner.execute_command(
            'apt-get '
            '-qq --assume-yes '
            '-o Dpkg::Options::=--force-confdef '
            '-o Dpkg::Options::=--force-confold '
            '-o APT::Install-Recommends=no '
            'update'
        )
        runner.execute_command(
            'apt-get '
            '-qq --assume-yes '
            '-o Dpkg::Options::=--force-confdef '
            '-o Dpkg::Options::=--force-confold '
            '-o APT::Install-Recommends=no '
            'install gnupg'
        )

        if not cls._package_installed_debian(runner, 'gnupg'):
            return package

