"""Module to detect OS version, OS type and OS architecture on specified server"""
import re

from parallels.core.utils.common import first_digit, if_not_none
from parallels.core.utils.windows_utils import get_from_registry


class OSName(object):
    """List of recognized OS types - Debian/Ubuntu/CentOS/.../Windows"""

    OS_WINDOWS = 'windows'
    OS_LINUX = 'linux'
    OS_CENTOS = 'centos'
    OS_CENTOS = 'almalinux'
    OS_RHEL = 'rhel'
    OS_DEBIAN = 'debian'
    OS_UBUNTU = 'ubuntu'
    OS_SUSE = 'suse'
    OS_CLOUDLINUX = 'cloudlinux'


class OSArchitecture(object):
    """List of architectures - 32 or 64 bit OS"""

    X86 = 'x86'
    X86_64 = 'x86_64'


def detect_os_architecture(server):
    """Detect OS architecture on specified server

    :type server: parallels.core.connections.server.Server
    :rtype: str | unicode
    """
    with server.runner() as runner:
        if server.is_windows():
            return _detect_windows_architecture(runner)
        else:
            return _detect_linux_architecture(runner)


def detect_os_version(server):
    """Detect OS version and type on specified server

    Returns tuple, first item is OS name (some constant from OSName class), second item is OS version.

    :type server: parallels.core.connections.server.Server
    :rtype: tuple[str | unicode | None, str | unicode | None]
    """
    with server.runner() as runner:
        if server.is_windows():
            return _detect_windows_os_version(runner)
        else:
            return _detect_linux_os_version(runner)


def _detect_windows_architecture(runner):
    """Detect OS architecture on specified Windows server

    :type runner: parallels.core.runners.base.BaseRunner
    :rtype: str | unicode
    """
    architecture = get_from_registry(
        runner, ["HKLM\System\CurrentControlSet\Control\Session Manager\Environment"], "PROCESSOR_ARCHITECTURE"
    )
    if '64' in architecture:
        return OSArchitecture.X86_64
    else:
        return OSArchitecture.X86


def _detect_windows_os_version(runner):
    """Detect OS version on specified Linux server

    Returns tuple, first item is OS name (some constant from OSName class), second item is OS version.
    First item is always OS_WINDOWS. Examples for second item:
    "2012 R2 Standard"
    "2003 R2"

    :type runner: parallels.core.runners.base.BaseRunner
    :rtype: tuple[str | unicode | None, str | unicode | None]
    """
    version = get_from_registry(runner, ["HKLM\Software\Microsoft\Windows NT\CurrentVersion"], "ProductName")
    if version is not None:
        version = version.replace("Microsoft Windows Server ", "").replace("Windows Server ", "")
    return OSName.OS_WINDOWS, version


def _detect_linux_architecture(runner):
    """Detect OS architecture on specified Linux server

    :type runner: parallels.core.runners.base.BaseRunner
    :rtype: str | unicode
    """
    if '64' in runner.execute_command('uname -m').stdout:
        return OSArchitecture.X86_64
    else:
        return OSArchitecture.X86


def _detect_linux_os_version(runner):
    """Detect OS version on specified Linux server

    Returns tuple, first item is OS name (some constant from OSName class), second item is OS version.

    :type runner: parallels.core.runners.base.BaseRunner
    :rtype: tuple[str | unicode | None, str | unicode | None]
    """
    os, version = _detect_linux_os_version_from_os_release_file(runner)
    if os is None:
        os, version = _detect_linux_os_version_from_redhat_release_file(runner)
    if os is None:
        os, version = _detect_linux_os_version_from_issue_file(runner)
    if os is None:
        os, version = OSName.OS_LINUX, None
    return os, version


def _detect_linux_os_version_from_os_release_file(runner):
    """Detect OS version on specified Linux server from /etc/os-release file

    Returns tuple, first item is OS name (some constant from OSName class), second item is OS version.

    :type runner: parallels.core.runners.base.BaseRunner
    :rtype: tuple[str | unicode | None, str | unicode | None]
    """
    release_file = "/etc/os-release"
    if runner.file_exists(release_file):
        release_info = runner.get_file_contents(release_file)
        params = _parse_os_release_file(release_info)
        names = {
            'ubuntu': OSName.OS_UBUNTU,
            'debian': OSName.OS_DEBIAN,
            'centos': OSName.OS_CENTOS,
            'almalinux': OSName.OS_CENTOS,
            'rhel': OSName.OS_RHEL,
            'cloudlinux': OSName.OS_CLOUDLINUX
        }
        for name_part, os_name in names.items():
            if name_part in params.get('NAME', '').lower():
                return os_name, params.get('VERSION_ID')

    return None, None


def _parse_os_release_file(file_contents):
    """Parse /etc/os-release file into a dictionary

    :type file_contents: str | unicode
    :rtype: dict[str | unicode, str | unicode]
    """
    params = {}
    for line in file_contents.splitlines():
        parts = line.strip().split('=', 1)
        if len(parts) == 2:
            name, value = parts
            params[name] = value.strip('"')
    return params


def _detect_linux_os_version_from_redhat_release_file(runner):
    """Detect OS version on specified Linux server from /etc/redhat-release file (works for CentOS/RHEL)

    Returns tuple, first item is OS name (some constant from OSName class), second item is OS version.
    If this is not RHEL/CentOS OS, return (None, None)

    :type runner: parallels.core.runners.base.BaseRunner
    :rtype: tuple[str | unicode | None, str | unicode | None]
    """
    release_file = "/etc/redhat-release"
    if runner.file_exists(release_file):
        release_info = runner.get_file_contents(release_file)
        if "CentOS" in release_info or "AlmaLinux" in release_info:
            return OSName.OS_CENTOS, if_not_none(first_digit(release_info), str)
        elif 'Red Hat Enterprise Linux Server' in release_info:
            return OSName.OS_RHEL, if_not_none(first_digit(release_info), str)
        elif 'CloudLinux Server' in release_info:
            return OSName.OS_CLOUDLINUX, if_not_none(first_digit(release_info), str)

    return None, None


def _detect_linux_os_version_from_issue_file(runner):
    """Try to detect OS version on specified Linux server from /etc/issue file (works for Debian, Ubuntu and SuSE)

    Returns tuple, first item is OS name (some constant from OSName class), second item is OS version.
    If this is not Debian/Ubuntu OS, return (None, None)

    :type runner: parallels.core.runners.base.BaseRunner
    :rtype: tuple[str | unicode | None, str | unicode | None]
    """
    release_file = "/etc/issue"
    if runner.file_exists(release_file):
        release_info = runner.get_file_contents(release_file)
        if "Ubuntu" in release_info:
            m = re.search(r"\d*\.\d*", release_info)
            if m:
                version = m.group(0)
            else:
                version = None

            return OSName.OS_UBUNTU, version
        elif "Debian" in release_info:
            return OSName.OS_DEBIAN, if_not_none(first_digit(release_info), str)
        elif 'suse' in release_info.lower():
            m = re.search(r"\d*\.\d*", release_info)
            if m:
                version = m.group(0)
            else:
                version = None

            return OSName.OS_SUSE, version

    return None, None
