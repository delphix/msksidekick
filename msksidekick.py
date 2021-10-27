# Author  : Ajay Thotangare
# Created : 05/11/2020
# Purpose : Sidekick for masking server.It heps to
#           1) Load balance masking job
#           2) Sync job/env/global objects/engines
#           3) Backup / Recover metadata to/from filesystem
############################################################################
# Copyright and license:
#
#       Licensed under the Apache License, Version 2.0 (the "License"); you may
#       not use this file except in compliance with the License.
#
#       You may obtain a copy of the License at
#
#               http://www.apache.org/licenses/LICENSE-2.0
#
#       Unless required by applicable law or agreed to in writing, software
#       distributed under the License is distributed on an "AS IS" basis,
#       WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
#       See the License for the specific language governing permissions and
#       limitations under the License.
#
#       Copyright (c) 2020 by Delphix.  All rights reserved.
#
# Description:
#
#   Call this tool to run masking job,backup metadata, sync engines manually or via scheduler.
#
# ================================================================================


import collections
import os
import sys
import traceback
import click
import mskpkg.globals as globals
# import sqlite3
# import atexit

from mskpkg.DxLogging import print_debug
from mskpkg.banner import banner
from mskpkg.masking import masking
from mskpkg.virtualization import virtualization

from pathlib import Path

# atexit.register(print, "Program exited successfully!")

VERSION = "2.0.5"
# con = sqlite3.connect('msksidekick.db')
# cur = con.cursor()

# script_dir = os.path.dirname(os.path.realpath(__file__))
# script_dir = getattr(
#     sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))
# )

# script_dir = Path(__file__).resolve().parent

if getattr(sys, 'frozen', False):
    # If the application is run as a bundle, the PyInstaller bootloader
    # extends the sys module by a flag frozen=True and sets the app
    # path into variable _MEIPASS'.
    # script_dir = sys._MEIPASS
    script_dir = os.path.dirname(sys.executable)

else:
    script_dir = os.path.dirname(os.path.abspath(__file__))

output_dir = "{}/output".format(script_dir)
# print(script_dir)
# print(output_dir)
try:
    # print("output_dir = {}".format(output_dir))
    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
except Exception as e:
    print("Unable to create {} directory in current folder".format(output_dir))
    print(str(e))
    raise


class Config(object):
    def __init__(self):
        self.verbose = False
        self.debug = False


pass_config = click.make_pass_decorator(Config, ensure=True)


class OrderedGroup(click.Group):
    def __init__(self, name=None, commands=None, **attrs):
        super(OrderedGroup, self).__init__(name, commands, **attrs)
        #: the registered subcommands by their exported names.
        self.commands = commands or collections.OrderedDict()

    def list_commands(self, ctx):
        return self.commands


def print_banner():
    bannertext = banner()
    mybannero = bannertext.banner_sl_box_open(text=" ")
    mybannera = bannertext.banner_sl_box_addline(
        text="Masking Sidekick - {}".format(VERSION)
    )
    mybannerc = bannertext.banner_sl_box_close()
    # print(mybannero)
    print(" ")
    print(mybannera)
    print(mybannerc)


def print_debug_banner(txtmsg):
    bannertext = banner()
    mybannero = bannertext.banner_sl_box_open(text=" ")
    mybannera = bannertext.banner_sl_box_addline(txtmsg)
    mybannerc = bannertext.banner_sl_box_close()
    print_debug(" ")
    print_debug(mybannero)
    print_debug(mybannera)
    print_debug(mybannerc)
    print_debug(" ")


def print_exception_exit1():
    message_String = "\nERROR: Exit Code:1\n"
    type_, value_, traceback_ = sys.exc_info()
    whole_message = traceback.format_exception(type_, value_, traceback_)
    res = []
    for sub in whole_message:
        if "raise Exception" not in sub:
            sub = sub.strip()
            res.append(sub.replace("\n", ""))

    message_String = message_String + "\n".join(res[-2:])
    print(message_String, file=sys.stderr)
    sys.exit(1)


# Common Options
# @click.group()
@click.group(cls=OrderedGroup)
@click.option("--verbose", "-v", is_flag=True)
@click.option("--debug", "-d", is_flag=True)
@pass_config
def cli(config, verbose, debug):
    if verbose:
        config.verbose = verbose
    if debug:
        config.debug = debug


# gen-dxtoolsconf
@cli.command()
@pass_config
def version(config):
    """Script Version"""
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")

    print_banner()
    click.echo("Script Version : {}".format(VERSION))


# add_engine
@cli.command()
@click.option(
    "--mskengname",
    "-m",
    default="",
    prompt="Enter Masking Engine name",
    help="Masking Engine name",
)
@click.option(
    "--totalgb",
    "-t",
    default="",
    prompt="Enter total memory in GB for masking engine",
    help="Total memory in GB for masking engine",
)
@click.option(
    "--systemgb",
    "-s",
    default="",
    prompt="Enter system memory in GB for masking engine",
    help="System memory in GB for masking engine",
)
@click.option(
    "--poolname",
    "-p",
    default="Default",
    prompt="Enter Pool Name for Engine",
    help="Pool name to assign engine",
)
# @click.option('--enabled','-e', default='Y', prompt='Enable Masking Engine for pooling',
#            type=click.Choice(['Y', 'N'], case_sensitive=True),
#            help='Add Engine to Pool')
@pass_config
# def add_engine(config, mskengname, totalgb, systemgb, mskaiagntuser, enabled):
def add_engine(config, mskengname, totalgb, systemgb, poolname):
    """This module will add engine to pool"""

    print_banner()
    scriptdir = os.path.dirname(os.path.abspath(__file__))
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")

    globals.arguments["--debug"] = config.debug
    globals.arguments["--config"] = "{}/dxtools.conf".format(scriptdir)

    mskai = masking(
        config,
        mskengname=mskengname,
        totalgb=totalgb,
        systemgb=systemgb,
        poolname=poolname,
    )
    mskai.add_engine()
    sys.exit(0)


# list_engine
@cli.command()
@pass_config
def list_engine(config):
    """This module will list engine from pool"""
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")

    try:
        mskai = masking(config, noparam="noparam")
        mskai.list_engine()
        sys.exit(0)
    except Exception as e:
        print_exception_exit1()


# del_engine
@cli.command()
@click.option(
    "--mskengname",
    "-m",
    default="",
    prompt="Enter Masking Engine name",
    help="Masking Engine name",
)
@pass_config
def del_engine(config, mskengname):
    """This module will remove engine from pool"""
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")
        click.echo("mskengname = {0}".format(mskengname))
    mskai = masking(config, mskengname=mskengname)
    mskai.del_engine()
    sys.exit(0)


# pulljoblist
@cli.command()
@click.option(
    "--mskengname",
    "-m",
    default="all",
    prompt="Enter Masking Engine name",
    help="Masking Engine name",
)
@click.option(
    "--username",
    "-u",
    prompt="Enter Masking username",
    help="Masking mskaiagnt username to connect masking engines",
)
@click.password_option(
    "--password",
    "-p",
    help="Masking mskaiagnt password to connect masking engines",
)
@click.option(
    "--protocol",
    default="https",
    help="Enter protocol http|https to access Masking Engines",
)
@pass_config
def pull_joblist(config, mskengname, username, password, protocol):
    """This module will pull joblist from engine"""
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")
        click.echo("mskengname = {0}".format(mskengname))
        click.echo("username   = {0}".format(username))
        click.echo("protocol   = {0}".format(protocol))

    print_banner()
    mskai = masking(
        config,
        mskengname=mskengname,
        username=username,
        password=password,
        protocol=protocol,
    )
    mskai.pull_joblist()
    sys.exit(0)


# pull_currjoblist
@cli.command()
@click.option(
    "--jobname", "-j", default="", help="Masking Job name from Masking Engine"
)
@click.option(
    "--envname", "-e", default="mskenv", help="Environment Name of Masking Job"
)
@click.option(
    "--username",
    "-u",
    prompt="Enter Masking username",
    help="Masking mskaiagnt username to connect masking engines",
)
@click.password_option(
    "--password",
    "-p",
    default="mskenv",
    help="Masking mskaiagnt password to connect masking engines",
)
@click.option(
    "--protocol",
    default="https",
    help="Enter protocol http|https to access Masking Engines",
)
@click.option("--poolname", default="Default", help="Pool name of engine")
@pass_config
def pull_currjoblist(
        config, jobname, envname, username, password, protocol, poolname
):
    """This module will pull current job execution list from all engines"""

    print_banner()
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")
        print(" jobname  = {0}".format(jobname))
        print(" envname  = {0}".format(envname))
        print(" username = {0}".format(username))
        print(" protocol = {0}".format(protocol))

    try:
        mskai = masking(
            config,
            jobname=jobname,
            envname=envname,
            username=username,
            password=password,
            protocol=protocol,
            poolname=poolname,
        )
        mskai.pull_currjoblist()
        sys.exit(0)
    except Exception as e:
        print_exception_exit1()


# gen-dxtoolsconf
@cli.command()
@click.option(
    "--protocol",
    default="https",
    help="Enter protocol http|https to access Masking Engines",
)
@pass_config
def gen_dxtools_conf(config, protocol):
    """This module will generate dxtools conf file for engine"""
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")

    print_banner()
    mskai = masking(config, protocol=protocol)
    mskai.gen_dxtools_conf()
    sys.exit(0)


# syncjob
@cli.command()
@click.option(
    "--srcmskengname",
    default="",
    prompt="Enter Source Masking Engine name",
    help="Source Masking Engine name",
)
@click.option(
    "--srcenvname",
    default="",
    prompt="Enter Source Masking Engine env name",
    help="Source Masking Engine Environment name",
)
@click.option(
    "--srcjobname",
    default="",
    prompt="Enter Source Masking Engine job name",
    help="Source Masking Engine Job name",
)
@click.option(
    "--tgtmskengname",
    default="",
    prompt="Enter Target Masking Engine name",
    help="Target Masking Engine name",
)
@click.option(
    "--tgtenvname",
    default="",
    prompt="Enter Target Masking Engine env name",
    help="Target Masking Engine Environment name",
)
@click.option(
    "--globalobjsync",
    "-g",
    default=False,
    is_flag=True,
    prompt="Sync global Objects",
    help="Sync global Objects",
)
@click.option(
    "--username",
    "-u",
    prompt="Enter Masking username",
    help="Masking mskaiagnt username to connect masking engines",
)
@click.password_option(
    "--password",
    "-p",
    help="Masking mskaiagnt password to connect masking engines",
)
@click.option(
    "--protocol",
    default="https",
    help="Enter protocol http|https to access Masking Engines",
)
@pass_config
def sync_job(
        config,
        srcmskengname,
        srcenvname,
        srcjobname,
        tgtmskengname,
        tgtenvname,
        globalobjsync,
        username,
        password,
        protocol,
):
    """This module will sync particular job between 2 engines"""

    print_banner()
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")
        print(" srcmskengname = {0}".format(srcmskengname))
        print(" srcenvname    = {0}".format(srcenvname))
        print(" srcjobname    = {0}".format(srcjobname))
        print(" tgtmskengname = {0}".format(tgtmskengname))
        print(" globalobjsync = {0}".format(globalobjsync))
        print(" username      = {0}".format(username))
        print(" protocol      = {0}".format(protocol))

    try:
        mskai = masking(
            config,
            srcmskengname=srcmskengname,
            srcenvname=srcenvname,
            srcjobname=srcjobname,
            tgtmskengname=tgtmskengname,
            tgtenvname=tgtenvname,
            globalobjsync=globalobjsync,
            username=username,
            password=password,
            protocol=protocol,
        )
        mskai.sync_job()
        sys.exit(0)
    except Exception as e:
        print_exception_exit1()


# syncenv
@cli.command()
@click.option(
    "--srcmskengname",
    default="",
    prompt="Enter Source Masking Engine name",
    help="Source Masking Engine name",
)
@click.option(
    "--srcenvname",
    default="",
    prompt="Enter Source Masking Engine env name",
    help="Source Masking Engine Environment name",
)
@click.option(
    "--tgtmskengname",
    default="",
    prompt="Enter Target Masking Engine name",
    help="Target Masking Engine name",
)
@click.option(
    "--tgtenvname",
    default="",
    prompt="Enter Target Masking Engine env name",
    help="Target Masking Engine Environment name",
)
@click.option(
    "--globalobjsync",
    "-g",
    default=False,
    is_flag=True,
    prompt="Sync global Objects",
    help="Sync global Objects",
)
@click.option(
    "--username",
    "-u",
    prompt="Enter Masking username",
    help="Masking mskaiagnt username to connect masking engines",
)
@click.password_option(
    "--password",
    "-p",
    help="Masking mskaiagnt password to connect masking engines",
)
@click.option(
    "--protocol",
    default="https",
    help="Enter protocol http|https to access Masking Engines",
)
@pass_config
def sync_env(
        config,
        srcmskengname,
        srcenvname,
        tgtmskengname,
        tgtenvname,
        globalobjsync,
        username,
        password,
        protocol,
):
    """This module will sync particular env between 2 engines"""

    print_banner()
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")
        print(" srcmskengname = {0}".format(srcmskengname))
        print(" srcenvname    = {0}".format(srcenvname))
        print(" tgtmskengname = {0}".format(tgtmskengname))
        print(" tgtenvname    = {0}".format(tgtenvname))
        print(" globalobjsync = {0}".format(globalobjsync))
        print(" username      = {0}".format(username))
        print(" protocol      = {0}".format(protocol))

    try:
        mskai = masking(
            config,
            srcmskengname=srcmskengname,
            srcenvname=srcenvname,
            tgtmskengname=tgtmskengname,
            tgtenvname=tgtenvname,
            globalobjsync=globalobjsync,
            username=username,
            password=password,
            protocol=protocol,
        )
        mskai.sync_env()
        sys.exit(0)
    except Exception as e:
        print_exception_exit1()


# synceng
@cli.command()
@click.option(
    "--srcmskengname",
    default="",
    prompt="Enter Source Masking Engine name",
    help="Source Masking Engine name",
)
@click.option(
    "--tgtmskengname",
    default="",
    prompt="Enter Target Masking Engine name",
    help="Target Masking Engine name",
)
@click.option(
    "--globalobjsync",
    "-g",
    default=True,
    is_flag=True,
    prompt="Sync global Objects",
    help="Sync global Objects",
)
@click.option(
    "--username",
    "-u",
    prompt="Enter Masking username",
    help="Masking mskaiagnt username to connect masking engines",
)
@click.password_option(
    "--password",
    "-p",
    help="Masking mskaiagnt password to connect masking engines",
)
@click.option(
    "--protocol",
    default="https",
    help="Enter protocol http|https to access Masking Engines",
)
@click.option(
    "--delextra",
    default=False,
    is_flag=True,
    help="Delete extra objects from target",
)
@click.option(
    "--excludenonadmin",
    default="Y",
    type=click.Choice(["Y", "N"], case_sensitive=False),
    help="Exclude to sync non admin users. Supported values Y|N",
)
@pass_config
def sync_eng(
        config,
        srcmskengname,
        tgtmskengname,
        globalobjsync,
        username,
        password,
        protocol,
        delextra,
        excludenonadmin,
):
    """This module will complete sync 2 engines"""

    print_banner()
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")
        print(" srcmskengname   = {0}".format(srcmskengname))
        print(" tgtmskengname   = {0}".format(tgtmskengname))
        print(" globalobjsync   = {0}".format(globalobjsync))
        print(" username        = {0}".format(username))
        print(" protocol        = {0}".format(protocol))
        print(" delextra        = {0}".format(delextra))
        print(" excludenonadmin = {0}".format(excludenonadmin))
        print(" ")
    globalobjsync = True
    try:
        mskai = masking(
            config,
            srcmskengname=srcmskengname,
            tgtmskengname=tgtmskengname,
            globalobjsync=globalobjsync,
            username=username,
            password=password,
            protocol=protocol,
            delextra=delextra,
            excludenonadmin=excludenonadmin,
        )
        mskai.sync_eng()
        sys.exit(0)
    except Exception as e:
        print_exception_exit1()


# sync_globalobj
@cli.command()
@click.option(
    "--srcmskengname",
    default="",
    prompt="Enter Source Masking Engine name",
    help="Source Masking Engine name",
)
@click.option(
    "--tgtmskengname",
    default="",
    prompt="Enter Target Masking Engine name",
    help="Target Masking Engine name",
)
@click.option(
    "--globalobjsync",
    "-g",
    default=False,
    is_flag=True,
    prompt="Sync global Objects",
    help="Sync global Objects",
)
@click.option(
    "--username",
    "-u",
    prompt="Enter Masking username",
    help="Masking mskaiagnt username to connect masking engines",
)
@click.password_option(
    "--password",
    "-p",
    help="Masking mskaiagnt password to connect masking engines",
)
@click.option(
    "--protocol",
    default="https",
    help="Enter protocol http|https to access Masking Engines",
)
@pass_config
def sync_globalobj(
        config,
        srcmskengname,
        tgtmskengname,
        globalobjsync,
        username,
        password,
        protocol,
):
    """This module will sync global objects between 2 engines"""

    print_banner()
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")
        print(" srcmskengname = {0}".format(srcmskengname))
        print(" tgtmskengname = {0}".format(tgtmskengname))
        print(" globalobjsync = {0}".format(globalobjsync))
        print(" username      = {0}".format(username))
        print(" protocol      = {0}".format(protocol))

    try:
        mskai = masking(
            config,
            srcmskengname=srcmskengname,
            tgtmskengname=tgtmskengname,
            globalobjsync=globalobjsync,
            username=username,
            password=password,
            protocol=protocol,
        )
        mskai.sync_globalobj()
        sys.exit(0)
    except Exception as e:
        print_exception_exit1()


# cleanup-eng
@cli.command()
@click.option(
    "--mskengname",
    default="",
    prompt="Enter Source Masking Engine name",
    help="Source Masking Engine name",
)
@click.option(
    "--username",
    "-u",
    prompt="Enter Masking username",
    help="Masking mskaiagnt username to connect masking engines",
)
@click.password_option(
    "--password",
    "-p",
    help="Masking mskaiagnt password to connect masking engines",
)
@click.option(
    "--protocol",
    default="https",
    help="Enter protocol http|https to access Masking Engines",
)
@click.option(
    "--includeadmin",
    default=False,
    is_flag=True,
    help="Include to delete admin users",
)
@pass_config
def cleanup_eng(
        config, mskengname, username, password, protocol, includeadmin
):
    """This module will complete cleanup engine for fresh start"""

    print_banner()
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")
        print(" mskengname    = {0}".format(mskengname))
        print(" username      = {0}".format(username))
        print(" protocol      = {0}".format(protocol))
        print(" includeadmin  = {0}".format(includeadmin))

    try:
        mskai = masking(
            config,
            mskengname=mskengname,
            username=username,
            password=password,
            protocol=protocol,
            includeadmin=includeadmin,
        )
        mskai.cleanup_eng()
        sys.exit(0)
    except Exception as e:
        print_exception_exit1()


# runjob
@cli.command()
@click.option(
    "--jobname",
    "-j",
    default="",
    prompt="Enter Masking Job Name",
    help="Masking Job name from Masking Engine",
)
@click.option(
    "--envname",
    "-e",
    default="mskenv",
    prompt="Enter Environment Name of Masking Job",
    help="Environment Name of Masking Job",
)
@click.option(
    "--run",
    "-r",
    default=False,
    is_flag=True,
    help="Execute Job. In Absence display only decision",
)
@click.option(
    "--mock",
    "-m",
    default=False,
    is_flag=True,
    help="Mock run - just for demos",
)
@click.option(
    "--username",
    "-u",
    prompt="Enter Masking username",
    help="Masking mskaiagnt username to connect masking engines",
)
@click.password_option(
    "--password",
    "-p",
    help="Masking mskaiagnt password to connect masking engines",
)
@click.option(
    "--protocol",
    default="https",
    help="Enter protocol http|https to access Masking Engines",
)
@click.option(
    "--dxtoolkit_path",
    default="",
    prompt="Enter dxtoolkit path",
    help="dxtoolkit full path",
)
@click.option(
    "--poolname", "-p", default="Default", help="Pool name to assign engine"
)
@pass_config
def run_job(
        config,
        jobname,
        envname,
        run,
        mock,
        username,
        password,
        protocol,
        dxtoolkit_path,
        poolname,
):
    """This module will execute masking job on best candidate engine"""

    print_banner()
    scriptdir = os.path.dirname(os.path.abspath(__file__))
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")
        print(" jobname        = {0}".format(jobname))
        print(" envname        = {0}".format(envname))
        print(" run            = {0}".format(run))
        print(" mock           = {0}".format(mock))
        print(" username       = {0}".format(username))
        print(" protocol       = {0}".format(protocol))
        print(" dxtoolkit_path = {0}".format(dxtoolkit_path))
        print(" poolname       = {0}".format(poolname))

    globals.arguments["--debug"] = config.debug
    globals.arguments["--config"] = "{}/dxtools.conf".format(scriptdir)
    globals.arguments["--all"] = True
    globals.arguments["--engine"] = None
    globals.arguments["--logdir"] = "./dx_skel.log"
    globals.arguments["--parallel"] = None
    globals.arguments["--poll"] = "10"
    globals.arguments["--version"] = False
    globals.arguments["--single_thread"] = True
    globals.arguments["--dxtoolkit_path"] = dxtoolkit_path

    try:
        mskai = masking(
            config,
            jobname=jobname,
            envname=envname,
            run=run,
            mock=mock,
            username=username,
            password=password,
            protocol=protocol,
            poolname=poolname,
        )
        if not mock:
            mskai.pull_jobexeclist()
        chk_status = mskai.chk_job_running()
        # print("chk_status={}".format(chk_status))
        if chk_status != 0:
            # print(
            #     " Job {} on Env {} is already running on engine {}. Please retry later".format(
            #         jobname, envname, chk_status
            #     )
            # )
            # sys.exit(1)
            raise Exception(
                "ERROR: Job {} on Env {} is already running on engine {}. Please retry later".format(jobname, envname,
                                                                                                     chk_status))

    except Exception as e:
        print_exception_exit1()

    try:
        print_debug(" ")
        print_debug(" ")
        print_debug(" ")
        print_debug(" ")
        print_debug_banner("Capture CPU usage data...")
        scriptdir = os.path.dirname(os.path.abspath(__file__))
        outputdir = os.path.join(scriptdir, "output")
        print_debug("dxtoolkit_path: {}".format(dxtoolkit_path))
        aive = virtualization(
            config,
            config_file_path="{}/dxtools.conf".format(scriptdir),
            scriptdir=scriptdir,
            outputdir=outputdir,
            protocol=protocol,
            dxtoolkit_path=dxtoolkit_path,
        )
        print_debug("dxtoolkit_path: {}".format(dxtoolkit_path))
        aive.gen_cpu_file()
        print_debug("Capture CPU usage data : done")
        print_debug(" ")
        print_debug(" ")
        print_debug(" ")
        print_debug(" ")
    except Exception as e:
        print_exception_exit1()

    print_debug_banner("Execute Job run module...")
    try:
        mskai = masking(
            config,
            jobname=jobname,
            envname=envname,
            run=run,
            mock=mock,
            username=username,
            password=password,
            protocol=protocol,
            poolname=poolname,
        )
        mskai.run_job()
    except Exception as e:
        print_exception_exit1()
    sys.exit(0)


# test-connectors
@cli.command()
@click.option(
    "--mskengname",
    default="",
    prompt="Enter Source Masking Engine name",
    help="Source Masking Engine name",
)
@click.option(
    "--username",
    "-u",
    prompt="Enter Masking username",
    help="Masking mskaiagnt username to connect masking engines",
)
@click.password_option(
    "--password",
    "-p",
    help="Masking mskaiagnt password to connect masking engines",
)
@click.option(
    "--protocol",
    default="https",
    help="Enter protocol http|https to access Masking Engines",
)
@pass_config
def test_connectors(config, mskengname, username, password, protocol):
    """This module will help to test all connectors"""

    print_banner()
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")
        print(" mskengname = {0}".format(mskengname))
        print(" username      = {0}".format(username))
        print(" protocol      = {0}".format(protocol))

    try:
        mskai = masking(
            config,
            mskengname=mskengname,
            username=username,
            password=password,
            protocol=protocol,
        )
        mskai.test_all_connectors()
    except Exception as e:
        print_exception_exit1()
    sys.exit(0)


# list_green_eng
@cli.command()
@click.option(
    "--username",
    "-u",
    prompt="Enter Masking username",
    help="Masking mskaiagnt username to connect masking engines",
)
@click.password_option(
    "--password",
    "-p",
    help="Masking mskaiagnt password to connect masking engines",
)
@click.option(
    "--mock",
    "-m",
    default=False,
    is_flag=True,
    help="Mock run - just for demos",
)
@click.option(
    "--protocol",
    default="https",
    help="Enter protocol http|https to access Masking Engines",
)
@click.option(
    "--dxtoolkit_path",
    default="",
    prompt="Enter dxtoolkit path",
    help="dxtoolkit full path",
)
@pass_config
def list_eng_usage(config, username, password, protocol, mock, dxtoolkit_path):
    """This module will find green engines"""

    print_banner()
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")
        print(" mock     = {0}".format(mock))
        print(" username = {0}".format(username))
        print(" protocol      = {0}".format(protocol))
        print(" dxtoolkit_path = {0}".format(dxtoolkit_path))

    globals.arguments["--debug"] = config.debug
    globals.arguments["--config"] = "{}/dxtools.conf".format(script_dir)
    globals.arguments["--all"] = True
    globals.arguments["--engine"] = None
    globals.arguments["--logdir"] = "{}/dx_skel.log".format(output_dir)
    globals.arguments["--parallel"] = None
    globals.arguments["--poll"] = "10"
    globals.arguments["--version"] = False
    globals.arguments["--single_thread"] = True
    globals.arguments["--dxtoolkit_path"] = dxtoolkit_path

    try:
        mskai = masking(
            config,
            mock=mock,
            username=username,
            password=password,
            protocol=protocol,
        )
        if not mock:
            mskai.pull_jobexeclist()

    except Exception as e:
        print_exception_exit1()

    try:
        print_debug(" ")
        print_debug("Capture CPU usage data...")
        scriptdir = os.path.dirname(os.path.abspath(__file__))
        outputdir = os.path.join(scriptdir, "output")
        print_debug("dxtoolkit_path: {}".format(dxtoolkit_path))
        aive = virtualization(
            config,
            config_file_path="{}/dxtools.conf".format(script_dir),
            scriptdir=scriptdir,
            outputdir=outputdir,
            protocol=protocol,
            dxtoolkit_path=dxtoolkit_path,
        )
        print_debug("dxtoolkit_path: {}".format(dxtoolkit_path))
        aive.gen_cpu_file()
        print_debug("Capture CPU usage data : done")
        print_debug(" ")
    except Exception as e:
        print("Error in VE module")
        # sys.exit(1)
        # raise Exception("ERROR: Error in VE module")
        print_exception_exit1()

    try:
        mskai = masking(
            config,
            mock=mock,
            username=username,
            password=password,
            protocol=protocol,
        )
        mskai.list_eng_usage()
    except Exception as e:
        print_exception_exit1()
    sys.exit(0)


# offline_backup_eng
@cli.command()
@click.option(
    "--mskengname",
    default="",
    prompt="Enter Masking Engine name",
    help="Masking Engine name",
)
@click.option(
    "--backup_dir", default="", prompt="Enter Backup Path", help="Backup Path"
)
@click.option(
    "--username",
    "-u",
    prompt="Enter Masking username",
    help="Masking mskaiagnt username to connect masking engines",
)
@click.password_option(
    "--password",
    "-p",
    help="Masking mskaiagnt password to connect masking engines",
)
@click.option(
    "--protocol",
    default="https",
    help="Enter protocol http|https to access Masking Engines",
)
@pass_config
def offline_backup_eng(
        config, mskengname, username, password, protocol, backup_dir
):
    """This module will offline backup engine"""

    print_banner()
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")
        print(" mskengname    = {0}".format(mskengname))
        print(" username      = {0}".format(username))
        print(" protocol      = {0}".format(protocol))
        print(" backup_dir    = {0}".format(backup_dir))

    try:
        mskai = masking(
            config,
            mskengname=mskengname,
            username=username,
            password=password,
            protocol=protocol,
            backup_dir=backup_dir,
        )
        mskai.offline_backup_eng()
        sys.exit(0)
    except Exception as e:
        print_exception_exit1()
    sys.exit(0)


# offline_restore_eng
@cli.command()
@click.option(
    "--mskengname",
    default="",
    prompt="Enter Masking Engine name",
    help="Masking Engine name",
)
@click.option(
    "--backup_dir", default="", prompt="Enter Backup Path", help="Backup Path"
)
@click.option(
    "--username",
    "-u",
    prompt="Enter Masking username",
    help="Masking mskaiagnt username to connect masking engines",
)
@click.password_option(
    "--password",
    "-p",
    help="Masking mskaiagnt password to connect masking engines",
)
@click.option(
    "--protocol",
    default="https",
    help="Enter protocol http|https to access Masking Engines",
)
@pass_config
def offline_restore_eng(
        config, mskengname, username, password, protocol, backup_dir
):
    """This module will offline restore engine from backups"""

    print_banner()
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")
        print(" mskengname    = {0}".format(mskengname))
        print(" username      = {0}".format(username))
        print(" protocol      = {0}".format(protocol))
        print(" backup_dir    = {0}".format(backup_dir))

    try:
        mskai = masking(
            config,
            mskengname=mskengname,
            username=username,
            password=password,
            protocol=protocol,
            backup_dir=backup_dir,
        )
        mskai.offline_restore_eng()
    except Exception as e:
        print_exception_exit1()
    sys.exit(0)


# offline_restore_env
@cli.command()
@click.option(
    "--mskengname",
    default="",
    prompt="Enter Masking Engine name",
    help="Masking Engine name",
)
@click.option(
    "--backup_dir", default="", prompt="Enter Backup Path", help="Backup Path"
)
@click.option(
    "--envname",
    "-e",
    default="mskenv",
    prompt="Enter name of Environment to be restored",
    help="Name of Environment to be restored",
)
@click.option(
    "--username",
    "-u",
    prompt="Enter Masking username",
    help="Masking sidekick username to connect masking engines",
)
@click.password_option(
    "--password",
    "-p",
    help="Masking mskaiagnt password to connect masking engines",
)
@click.option(
    "--protocol",
    default="https",
    help="Enter protocol http|https to access Masking Engines",
)
@pass_config
def offline_restore_env(
        config, mskengname, envname, username, password, protocol, backup_dir
):
    """This module will offline restore engine from backups"""

    print_banner()
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")
        print(" mskengname    = {0}".format(mskengname))
        print(" envname       = {0}".format(envname))
        print(" username      = {0}".format(username))
        print(" protocol      = {0}".format(protocol))
        print(" backup_dir    = {0}".format(backup_dir))

    try:
        mskai = masking(
            config,
            mskengname=mskengname,
            envname=envname,
            username=username,
            password=password,
            protocol=protocol,
            backup_dir=backup_dir,
        )
        mskai.offline_restore_env()
    except Exception as e:
        print_exception_exit1()
    sys.exit(0)


# duplicate_connectors
@cli.command()
@click.option(
    "--mskengname",
    default="",
    prompt="Enter Masking Engine name",
    help="Masking Engine name",
)
@click.option(
    "--username",
    "-u",
    prompt="Enter Masking username",
    help="Masking mskaiagnt username to connect masking engines",
)
@click.password_option(
    "--password",
    "-p",
    help="Masking mskaiagnt password to connect masking engines",
)
@click.option(
    "--protocol",
    default="https",
    help="Enter protocol http|https to access Masking Engines",
)
@click.option(
    "--action",
    type=click.Choice(['list', 'resolve']),
    default="list",
    help="List Connector | Rename conflicting connector names ( All conflicting connector names will be renamed )",
)
@pass_config
def duplicate_connectors(
        config, mskengname, username, password, protocol, action
):
    """This module will offline backup engine"""

    print_banner()
    globals.initialize(config.debug, config.verbose, script_dir)
    if config.verbose or config.debug:
        click.echo("Verbose mode enabled")
        print(" mskengname    = {0}".format(mskengname))
        print(" username      = {0}".format(username))
        print(" protocol      = {0}".format(protocol))
        print(" action        = {0}".format(action))
        print(" ")

    try:
        mskai = masking(
            config,
            mskengname=mskengname,
            username=username,
            password=password,
            protocol=protocol,
            action=action,
        )
        mskai.duplicate_connectors()
        sys.exit(0)
    except Exception as e:
        print_exception_exit1()
    sys.exit(0)



if __name__ == "__main__":
    cli()
