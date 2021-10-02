import collections
import csv
import json
import os
import sys
import traceback
import datetime
import pickle
import time
import subprocess
import threading
import inspect
from collections import Counter
from csv import DictReader
from sys import exit

import requests
import colorama
from termcolor import colored, cprint

import mskpkg.globals as globals
from mskpkg.DxLogging import print_debug
from mskpkg.banner import banner

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def dump_func_name(func):
    def echo_func(*func_args, **func_kwargs):
        print_debug("")
        bannertext = banner()
        mybannero = bannertext.banner_sl_box_open(text=" ")
        mybannera = bannertext.banner_sl_box_addline(func.__name__)
        mybannerc = bannertext.banner_sl_box_close()
        print_debug(mybannero)
        print_debug(mybannera)
        print_debug(mybannerc)
        print_debug("")
        return func(*func_args, **func_kwargs)

    return echo_func


class dotdict(dict):
    """dot.notation access to dictionary attributes"""

    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class masking:
    def __init__(self, config, **kwargs):
        # self.scriptname = os.path.basename(__file__)
        # self.scriptdir = getattr(
        #     sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))
        # )
        # self.scriptdir = globals.script_dir_path
        self.enginelistfile = globals.enginelistfile
        self.joblistfile = globals.joblistfile
        self.jobexeclistfile = globals.jobexeclistfile
        self.qualifiedengineslistfile = globals.qualifiedengineslistfile
        self.enginecpulistfile = globals.enginecpulistfile
        self.config = config
        self.src_dummy_conn_app = "COMMON_OTF_MSKJOB_SRC_CONN_APP"
        self.src_dummy_conn_env = "COMMON_OTF_MSKJOB_SRC_CONN_ENV"
        self.systemdomainlist = [
            "ACCOUNT_NO",
            "ACCOUNT_TK",
            "ADDRESS",
            "ADDRESS_LINE2",
            "BENEFICIARY_NO",
            "BIOMETRIC",
            "CERTIFICATE_NO",
            "CITY",
            "COUNTY",
            "CREDIT CARD",
            "CUSTOMER_NO",
            "DOB",
            "DRIVING_LC",
            "EMAIL",
            "FIRST_NAME",
            "IP ADDRESS",
            "LAST_NAME",
            "NAME_TK",
            "NULL_SL",
            "PLATE_NO",
            "PO_BOX",
            "PRECINCT",
            "RANDOM_VALUE_SL",
            "RECORD_NO",
            "SCHOOL_NM",
            "SECURE_SHUFFLE",
            "SECURITY_CODE",
            "SERIAL_NO",
            "SIGNATURE",
            "SSN",
            "SSN_TK",
            "TAX_ID",
            "TELEPHONE_NO",
            "US_COUNTIES_SL",
            "VIN_NO",
            "WEB",
            "ZIP",
        ]
        self.systemalgorithmlist = [
            "AccNoLookup",
            "AccountTK",
            "AddrLine2Lookup",
            "AddrLookup",
            "BusinessLegalEntityLookup",
            "CommentLookup",
            "CreditCard",
            "DateShiftDiscrete",
            "DateShiftFixed",
            "DateShiftVariable",
            "dlpx-core:CM Alpha-Numeric",
            "dlpx-core:CM Digits",
            "dlpx-core:CM Numeric",
            "DrivingLicenseNoLookup",
            "DummyHospitalNameLookup",
            "EmailLookup",
            "FirstNameLookup",
            "FullNMLookup",
            "LastCommaFirstLookup",
            "LastNameLookup",
            "NameTK",
            "NullValueLookup",
            "RandomValueLookup",
            "RepeatFirstDigit",
            "SchoolNameLookup",
            "SecureShuffle",
            "SM-UNI:NUMERIC",
            "SM-UNI:STRING",
            "SM-US_LATAM",
            "SsnTK",
            "TelephoneNoLookup",
            "USCitiesLookup",
            "USCountiesLookup",
            "USstatecodesLookup",
            "USstatesLookup",
            "WebURLsLookup",
            "SSN SM",
            "ACCOUNT",
            "ACCOUNT_TK",
            "ADDRESS",
            "ADDRESS",
            "BUSINESS",
            "COMMENT",
            "CREDIT",
            "DATE",
            "DATE",
            "DATE",
            "DR",
            "DUMMY_HOSPITAL_NAME_SL",
            "EMAIL",
            "FIRST",
            "FULL_NM_SL",
            "LAST_COMMA_FIRST_SL",
            "LAST",
            "NAME_TK",
            "NULL",
            "PHONE",
            "RANDOM_VALUE_SL",
            "SCHOOL",
            "SECURE",
            "SSN_TK",
            "USCITIES_SL",
            "US_COUNTIES_SL",
            "USSTATE_CODES_SL",
            "USSTATES_SL",
            "WEB_URLS_SL",
            "ZIP+4",
        ]

        # if not os.path.exists(self.enginelistfile):
        #    with open(self.enginelistfile, mode='a'): pass
        # if not os.path.exists(self.joblistfile):
        #    with open(self.joblistfile, mode='a'): pass
        # if not os.path.exists(self.jobexeclistfile):
        #    with open(self.jobexeclistfile, mode='a'): pass
        # if not os.path.exists(self.enginecpulistfile):
        #    with open(self.enginecpulistfile, mode='a'): pass

        if "mock" in kwargs.keys():
            self.mock = kwargs["mock"]
        if "jobname" in kwargs.keys():
            self.jobname = kwargs["jobname"]
        if "envname" in kwargs.keys():
            self.envname = kwargs["envname"]
        if "run" in kwargs.keys():
            self.run = kwargs["run"]
        if "username" in kwargs.keys():
            self.username = kwargs["username"]
        if "password" in kwargs.keys():
            self.password = kwargs["password"]
        if "mskengname" in kwargs.keys():
            self.mskengname = kwargs["mskengname"]
        if "totalgb" in kwargs.keys():
            self.totalgb = kwargs["totalgb"]
        if "systemgb" in kwargs.keys():
            self.systemgb = kwargs["systemgb"]
        if "srcmskengname" in kwargs.keys():
            self.srcmskengname = kwargs["srcmskengname"]
        if "srcenvname" in kwargs.keys():
            self.srcenvname = kwargs["srcenvname"]
        if "srcjobname" in kwargs.keys():
            self.srcjobname = kwargs["srcjobname"]
        if "tgtmskengname" in kwargs.keys():
            self.tgtmskengname = kwargs["tgtmskengname"]
        if "tgtenvname" in kwargs.keys():
            self.tgtenvname = kwargs["tgtenvname"]
        if "globalobjsync" in kwargs.keys():
            self.globalobjsync = kwargs["globalobjsync"]
        if "delextra" in kwargs.keys():
            self.delextra = kwargs["delextra"]
        if "poolname" in kwargs.keys():
            self.poolname = kwargs["poolname"]
        if "backup_dir" in kwargs.keys():
            self.backup_dir = kwargs["backup_dir"]
        if "includeadmin" in kwargs.keys():
            self.includeadmin = kwargs["includeadmin"]
        if "excludenonadmin" in kwargs.keys():
            self.excludenonadmin = kwargs["excludenonadmin"]
        if "action" in kwargs.keys():
            self.action = kwargs["action"]
        if "protocol" in kwargs.keys():
            self.protocol = kwargs["protocol"]
        else:
            self.protocol = "http"
        colorama.init()

    def create_dictobj(self, filename):
        with open(filename, "r") as read_obj:
            reader = DictReader(read_obj)
            dictobj = list(reader)
            return dictobj

    def unqlist(self, mydict, ignore_field):
        return [
            dict(data)
            for data in sorted(
                set(
                    tuple(
                        (key, value)
                        for key, value in row.items()
                        if key != ignore_field
                    )
                    for row in mydict
                )
            )
        ]

    def gen_dxtools_csv_file(self, protocol="http"):
        if protocol == "https":
            port = 443
        else:
            port = 80
        f = open(globals.dxtools_file_csv, "w")
        f.write(
            "{},{},{},{},{},{},{}\n".format(
                "protocol",
                "ip_address",
                "password",
                "port",
                "username",
                "default",
                "hostname",
            )
        )
        engine_list = self.create_dictobj(self.enginelistfile)
        for engine in engine_list:
            f.write(
                "{},{},{},{},{},{},{}\n".format(
                    protocol,
                    engine["ip_address"],
                    "delphix",
                    port,
                    "admin",
                    "true",
                    engine["ip_address"],
                )
            )
        f.close()
        return

    def gen_dxtools_conf(self):
        protocol = self.protocol
        # Write csv conf file
        self.gen_dxtools_csv_file(protocol)
        # Generate json conf file
        csvfile = open(globals.dxtools_file_csv, "r")
        reader = csv.DictReader(csvfile)
        fieldnames = (
            "protocol",
            "ip_address",
            "password",
            "port",
            "username",
            "default",
            "hostname",
        )
        output = []
        for each in reader:
            row = {}
            for field in fieldnames:
                row[field] = each[field]
            output.append(row)

        outputdict = {"data": output}
        with open(globals.dxtools_file, "w") as outfile:
            json.dump(
                outputdict,
                outfile,
                sort_keys=True,
                indent=4,
                ensure_ascii=False,
            )
        outfile.close()
        print("{} file generated successfully".format(globals.dxtools_file))

    def get_jobreqlist(self, mydictname, myjobname, myenvname):
        filtereddatafinal1 = filter(
            lambda row: (
                myjobname == row["jobname"]
                and myenvname == row["environmentname"]
            ),
            mydictname,
        )
        filtereddataQ = filtereddatafinal1
        return list(filtereddataQ)

    def join_dict1(self, dict1, dict2, fieldname):
        answer = {}
        for item in dict2:
            answer[item[fieldname]] = item
        for item in dict1:
            key = item[fieldname]
            if key in answer.keys():
                del item[fieldname]
                answer[key].update(item)
        return answer.values()

    def join_dict(self, dict1, dict2, fieldname, emptyfield):
        mergedictlist = []
        emptymem = collections.OrderedDict([("totalusedmemory", "0")])
        emptycpu = collections.OrderedDict([("cpu", "0")])
        for item1 in dict1:
            key = item1[fieldname]
            i = 0
            for item2 in dict2:
                if fieldname in item2.keys():
                    if key == item2[fieldname]:
                        res = {**item1, **item2}
                        mergedictlist.append(res)
                        i = i + 1

            if i == 0:
                if emptyfield == "cpu":
                    res = {**item1, **emptycpu}
                    mergedictlist.append(res)
                elif emptyfield == "memcpu":
                    restmp = {**item1, **emptymem}
                    res = {**restmp, **emptycpu}
                    mergedictlist.append(res)
        return mergedictlist

    def get_unqualified_qualified_engines(self, dict1):
        qualified_engines = []
        unqualified_engines = []
        for item in dict1:
            if int(item["availablemb"]) > 0:
                qualified_engines.append(item)
            else:
                unqualified_engines.append(item)
        print_debug("qualified_engines:{}".format(qualified_engines))
        print_debug("unqualified_engines:{}".format(unqualified_engines))
        return qualified_engines, unqualified_engines

    def get_jobpool_qualified_engines(self, dict1):
        poolqualified_engines = []
        poolunqualified_engines = []
        print_debug("poolname = {}".format(self.poolname))
        for item in dict1:
            if item["poolname"] == self.poolname:
                poolqualified_engines.append(item)
                print_debug(
                    "Pool matched for {}. requested pool :{}, engine pool:{}".format(
                        item["ip_address"], self.poolname, item["poolname"]
                    )
                )
            else:
                poolunqualified_engines.append(item)
                print_debug(
                    "Pool did not match for {}. requested pool :{}, engine pool:{}".format(
                        item["ip_address"], self.poolname, item["poolname"]
                    )
                )
        print_debug(
            "jobpool qualified_engines:{}".format(poolqualified_engines)
        )
        print_debug(
            "jobpool unqualified_engines:{}".format(poolunqualified_engines)
        )
        return poolqualified_engines

    def get_jobpool_unqualified_engines(self, dict1):
        upoolqualified_engines = []
        upoolunqualified_engines = []
        for item in dict1:
            if item["poolname"] == self.poolname:
                upoolqualified_engines.append(item)
                print_debug(
                    "Pool matched for {}. requested pool :{}, engine pool:{}".format(
                        item["ip_address"], self.poolname, item["poolname"]
                    )
                )
            else:
                upoolunqualified_engines.append(item)
                print_debug(
                    "Pool did not match for {}. requested pool :{}, engine pool:{}".format(
                        item["ip_address"], self.poolname, item["poolname"]
                    )
                )
        print_debug(
            "jobpool unqualified_qualified_engines:{}".format(
                upoolqualified_engines
            )
        )
        print_debug(
            "jobpool unqualified_unqualified_engines:{}".format(
                upoolunqualified_engines
            )
        )
        return upoolqualified_engines

    def get_max_free_mem_engine(self, dict1):
        freemem = 0
        winner_engine = {}
        for item in dict1:
            if int(item["availablemb"]) > freemem:
                winner_engine = item
                freemem = int(item["availablemb"])
        return winner_engine

    def group_job_mem_usage(self, key, sumcol, mydictname):
        try:
            aggregate_list = []
            c = Counter()
            for v in mydictname:
                if v["jobstatus"] == "RUNNING":
                    c[v[key]] += int(v[sumcol])

            aggregate_list = [
                {key: key1, "totalusedmemory": sumcol1}
                for key1, sumcol1 in c.items()
            ]
            if aggregate_list is None:
                print_debug("Returned None for aggregate job usage data")
                return None
            elif aggregate_list == []:
                print_debug("Returned [] for aggregate job usage data")
                return None
            else:
                return aggregate_list
        except Exception as e:
            print_debug("ERROR : Unable to aggregate job usage data")
            print_debug(e)
            return None

    def convert_ordered_dict_to_dict(self, ordered_dict):
        simple_dict = {}
        for key, value in ordered_dict.items():
            if isinstance(value, collections.OrderedDict):
                simple_dict[key] = self.convert_dict_to_ordereddict(value)
            else:
                simple_dict[key] = value
        return simple_dict

    def convert_dict_to_ordereddict(self, mydict):
        ordered_dict = {}
        for key, value in mydict.items():
            if isinstance(value, dict):
                ordered_dict[key] = self.convert_ordered_dict_to_dict(value)
            else:
                ordered_dict[key] = value
        return ordered_dict

    def read_data_from_file(self, filename):
        rc = []
        with open(filename) as f:
            records = csv.DictReader(f)
            for row in records:
                rc.append(row)
        return rc

    def print_debug_banner(self, txtmsg):
        bannertext = banner()
        mybannero = bannertext.banner_sl_box_open(text=" ")
        mybannera = bannertext.banner_sl_box_addline(txtmsg)
        mybannerc = bannertext.banner_sl_box_close()
        print_debug(" ")
        print_debug(mybannero)
        print_debug(mybannera)
        print_debug(mybannerc)
        print_debug(" ")

    def add_engine(self):
        # import pdb
        # pdb.set_trace()
        print_debug("self.enginelistfile = {}".format(self.enginelistfile))
        try:
            if os.path.exists(self.enginelistfile):
                engine_list = self.create_dictobj(self.enginelistfile)
                print_debug(engine_list)
                for engine in engine_list:
                    if self.mskengname == engine["ip_address"]:
                        print(
                            "Engine {} already exists in pool".format(
                                self.mskengname
                            )
                        )
                        print("Please use del-engine and add-engine module")
                        exit()
                f = open(self.enginelistfile, "a")
                f.write(
                    "{},{},{},{}\n".format(
                        self.mskengname,
                        self.totalgb,
                        self.systemgb,
                        self.poolname,
                    )
                )
                f.close()
            else:
                print_debug("poolname={}".format(self.poolname))
                f = open(self.enginelistfile, "w")
                f.write(
                    "{},{},{},{}\n".format(
                        "ip_address", "totalgb", "systemgb", "poolname"
                    )
                )
                f.write(
                    "{},{},{},{}\n".format(
                        self.mskengname,
                        self.totalgb,
                        self.systemgb,
                        self.poolname,
                    )
                )
                f.close()
            print(
                "Engine {} successfully added to pool".format(self.mskengname)
            )
        except Exception as e:
            print_debug(str(e))
            raise Exception("ERROR: Error adding engine {} to file {}".format(self.mskengname, self.enginelistfile))

    def list_engine(self):
        error_condition = 0
        try:
            if os.path.exists(self.enginelistfile):
                engine_list = self.create_dictobj(self.enginelistfile)
                print(
                    "{0:>1}{1:<35}{2:>20}{3:>20}{4:>20}".format(
                        " ",
                        "EngineName",
                        "Total Memory(GB)",
                        "System Memory(GB)",
                        "Pool Name",
                    )
                )
                for engine in engine_list:
                    print(
                        "{0:>1}{1:<35}{2:>20}{3:>20}{4:>20}".format(
                            " ",
                            engine["ip_address"],
                            engine["totalgb"],
                            engine["systemgb"],
                            engine["poolname"],
                        )
                    )
                print(" ")
            else:
                error_condition = 1
                raise Exception ("ERROR: No Engine found in pool")

        except Exception as e:
            print_debug(str(e))
            if error_condition == 1:
                raise Exception("ERROR: No Engine found in pool")
            else:
                raise Exception("ERROR: Not able to open file {}".format(self.enginelistfile))

    def del_engine(self):
        newenginelist = []
        try:
            i = 0
            if os.path.exists(self.enginelistfile):
                engine_list = self.create_dictobj(self.enginelistfile)
                for engine in engine_list:
                    if self.mskengname != engine["ip_address"]:
                        newenginelist.append(engine)
                    else:
                        i = 1
                        print(
                            "Engine {} deleted from pool".format(
                                self.mskengname
                            )
                        )

                if i == 1:
                    f = open(self.enginelistfile, "w")
                    f.write(
                        "{},{},{},{}\n".format(
                            "ip_address", "totalgb", "systemgb", "poolname"
                        )
                    )
                    f.close()
                    f = open(self.enginelistfile, "a")
                    for engine in newenginelist:
                        f.write(
                            "{},{},{},{}\n".format(
                                engine["ip_address"],
                                engine["totalgb"],
                                engine["systemgb"],
                                engine["poolname"],
                            )
                        )
                    f.close()
                else:
                    print(
                        "Engine {} does not exists in pool".format(
                            self.mskengname
                        )
                    )
            else:
                raise Exception("ERROR: File {} does not exists".format(self.enginelistfile))
        except Exception as e:
            print_debug(str(e))
            raise Exception("ERROR: Error deleting engine {} from file {}".format(self.mskengname, self.enginelistfile))

    def get_auth_key(self, ip_address, port=80):
        protocol = self.protocol
        if protocol == "https":
            port = 443
        api_url_base = "{}://{}:{}/masking/api/".format(
            protocol, ip_address, port
        )
        headers = {"Content-Type": "application/json"}
        api_url = "{0}login".format(api_url_base)
        print_debug("api_url = {}".format(api_url))
        credentials = {"username": self.username, "password": self.password}
        # print_debug('{},{},{},{},{},{}'.format(ip_address,port,api_url_base,headers,api_url,credentials))
        try:
            response = requests.post(
                api_url, headers=headers, json=credentials, verify=False
            )
            if response.status_code == 200:
                data = json.loads(response.content.decode("utf-8"))
                # print_debug (data['Authorization'])
                return data["Authorization"]
            else:
                print_debug("Error generating key {}".format(ip_address))
                print_debug(
                    "Error response {}".format(
                        response.content.decode("utf-8")
                    )
                )
                # sys.exit()
                return None
        except:
            print_debug("Error connecting engine {}".format(ip_address))
            return None

    def get_api_response(self, ip_address, api_token, apicall, port=80):
        protocol = self.protocol
        if protocol == "https":
            port = 443
        api_url_base = "{}://{}:{}/masking/api/".format(
            protocol, ip_address, port
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": "{0}".format(api_token),
        }
        api_url = "{0}{1}".format(api_url_base, apicall)
        response = requests.get(api_url, headers=headers, verify=False)
        if response.status_code == 200:
            data = json.loads(response.content.decode("utf-8"))
            return data
        else:
            print_debug(response.content.decode("utf-8"))
            outputstring = response.content.decode("utf-8")
            if "errorMessage" in outputstring:
                print(outputstring, file=sys.stderr)
            return None

    def del_api_response(self, ip_address, api_token, apicall, port=80):
        protocol = self.protocol
        if protocol == "https":
            port = 443
        api_url_base = "{}://{}:{}/masking/api/".format(
            protocol, ip_address, port
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": "{0}".format(api_token),
        }
        api_url = "{0}{1}".format(api_url_base, apicall)
        response = requests.delete(api_url, headers=headers, verify=False)
        if response.status_code == 200:
            data = response.content.decode("utf-8")
            return data
        else:
            print_debug(response.content.decode("utf-8"))
            print(response.content.decode("utf-8"))
            return None

    def post_api_response(self, ip_address, api_token, apicall, body, port=80):
        protocol = self.protocol
        if protocol == "https":
            port = 443
        api_url_base = "{}://{}:{}/masking/api/".format(
            protocol, ip_address, port
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": "{0}".format(api_token),
        }
        api_url = "{0}{1}".format(api_url_base, apicall)
        response = requests.post(
            api_url, headers=headers, json=body, verify=False
        )
        # print(response)
        # data = json.loads(response.content.decode('utf-8'))
        # print(data)
        # print("=====")
        if response.status_code == 200:
            data = json.loads(response.content.decode("utf-8"))
            return data
        else:
            print_debug(response.content.decode("utf-8"))
            outputstring = response.content.decode("utf-8")
            if "errorMessage" in outputstring:
                print(outputstring, file=sys.stderr)
            return None

    def put_api_response(self, ip_address, api_token, apicall, body, port=80):
        protocol = self.protocol
        if protocol == "https":
            port = 443
        api_url_base = "{}://{}:{}/masking/api/".format(
            protocol, ip_address, port
        )

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "{0}".format(api_token),
        }
        api_url = "{0}{1}".format(api_url_base, apicall)
        print_debug("api_url: {}".format(api_url))
        response = requests.put(
            api_url, headers=headers, json=body, verify=False
        )
        # print(response)
        # data = json.loads(response.content.decode('utf-8'))
        if response.status_code == 200:
            data = json.loads(response.content.decode("utf-8"))
            return data
        elif response.status_code == 409:
            data = json.loads(response.content.decode("utf-8"))
            return data
        else:
            print_debug(" >>>>> Erroring api_url: {}".format(api_url))
            print_debug(" >>>>> Erroring body   : {}".format(body))
            print(" {}".format(response.content.decode("utf-8")))
            return None

    def post_api_response1(
        self, ip_address, api_token, apicall, body, port=80
    ):
        protocol = self.protocol
        if protocol == "https":
            port = 443
        api_url_base = "{}://{}:{}/masking/api/".format(
            protocol, ip_address, port
        )

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "{0}".format(api_token),
        }
        api_url = "{0}{1}".format(api_url_base, apicall)
        print_debug("api_url: {}".format(api_url))
        response = requests.post(
            api_url, headers=headers, json=body, verify=False
        )
        # print(response)
        # data = json.loads(response.content.decode('utf-8'))
        if response.status_code == 200:
            data = json.loads(response.content.decode("utf-8"))
            return data
        elif response.status_code == 409:
            data = json.loads(response.content.decode("utf-8"))
            return data
        else:
            print(" {}".format(response.content.decode("utf-8")))
            print_debug(response.content.decode("utf-8"))
            outputstring = response.content.decode("utf-8")
            if "errorMessage" in outputstring:
                print(outputstring, file=sys.stderr)
            return None

    def exec_job(self, ip_address, api_token, jobid):
        jobpayload = {"jobId": jobid}
        data = self.post_api_response(
            ip_address, api_token, "executions", jobpayload
        )
        return data

    def chk_job_running(self):
        envname = self.envname
        jobname = self.jobname
        filepath = self.jobexeclistfile
        reqjobspec = "{},{}".format(envname, jobname)
        r = 0
        with open(filepath) as fp:
            line = fp.readline()
            cnt = 1
            while line:
                print_debug("Line {}: {}".format(cnt, line.strip()))
                env_job = []
                env_job = line.strip().split(",")
                filejobspec = "{},{}".format(env_job[5], env_job[1])
                if filejobspec == reqjobspec:
                    #r = 1
                    r = env_job[6]
                    return r
                    break
                line = fp.readline()
                cnt += 1
        return r

    def add_debugspace(self):
        print_debug(" ")
        print_debug(" ")

    # @track
    def run_job(self):
        if self.config.debug:
            print_debug("Parameter List:")
            print_debug("  jobname = {}".format(self.jobname))
            print_debug("  envname = {}".format(self.envname))
            print_debug("  run     = {}".format(self.run))
        # print_debug("  password= {}".format(self.password))
        # on windows
        # os.system('color')

        if not self.mock:
            # Run this if its not mock run for demos
            self.pull_jobexeclist()
        job_list = self.create_dictobj(self.joblistfile)
        jobexec_list = self.create_dictobj(self.jobexeclistfile)
        enginecpu_list = self.create_dictobj(self.enginecpulistfile)
        engine_list = self.create_dictobj(self.enginelistfile)
        print_debug("engine_list:\n{}".format(engine_list))

        self.add_debugspace()
        enginecpu_namelist = []
        if not enginecpu_list:
            print_debug("enginecpu_list is empty")
        else:
            for ecpuname in enginecpu_list:
                enginecpu_namelist.append(ecpuname["ip_address"])

        print_debug("enginecpu_list:{}".format(enginecpu_list))
        print_debug("enginecpu_namelist:{}".format(enginecpu_namelist))
        self.add_debugspace()

        enginelist = []
        nonreach_enginelist = []
        for engine in engine_list:
            engine_list_dict = collections.OrderedDict(
                ip_address=engine["ip_address"],
                totalmb=int(engine["totalgb"]) * 1024,
                systemmb=int(engine["systemgb"]) * 1024,
                poolname=engine["poolname"],
            )
            apikey = self.get_auth_key(engine["ip_address"])
            if apikey is not None:
                enginelist.append(engine_list_dict)
                if engine["ip_address"] not in enginecpu_namelist:
                    tmpengip = {
                        "ip_address": engine["ip_address"],
                        "cpu": "20",
                    }
                    print_debug(
                        "Engine not found in enginecpu_namelist. Assigning default 20% CPU usage"
                    )
                    enginecpu_list.append(tmpengip)
            else:
                nonreach_enginelist.append(engine_list_dict)

        if not enginelist:
            raise Exception("ERROR: Unable to reach any engines. Please check connections to engine in pool")

        print_debug("engine_list:\n{}".format(engine_list))
        print_debug("enginelist :\n{}".format(enginelist))
        engine_list = enginelist

        self.add_debugspace()
        print_debug("enginecpu_list:{}".format(enginecpu_list))

        joblistunq = self.unqlist(job_list, "ip_address")
        print_debug("joblistunq:{}".format(joblistunq))
        jobreqlist = self.get_jobreqlist(
            joblistunq, self.jobname, self.envname
        )
        print_debug("jobreqlist:{}".format(jobreqlist))
        if len(jobreqlist) == 0:
            print_red_on_white = lambda x: cprint(x, "red", "on_white")
            print_red_on_white(
                "Job : {} in Environment: {} does not exists on any masking server. Please recheck job name / environment and resubmit.".format(
                    self.jobname, self.envname
                )
            )
            raise Exception("ERROR: Job : {} in Environment: {} does not exists on any masking server. Please recheck job name / environment and resubmit.".format(self.jobname, self.envname))
        engine_pool_for_job = self.get_jobreqlist(
            job_list, self.jobname, self.envname
        )
        print_debug("engine_pool_for_job:\n{}\n".format(engine_pool_for_job))
        for job in engine_pool_for_job:
            print_debug(job)

        bannertext = banner()
        print(" ")
        print(
            (colored(bannertext.banner_sl_box(text="Requirements:"), "yellow"))
        )
        print(" Jobname   = {}".format(self.jobname))
        print(" Env       = {}".format(self.envname))
        print(" MaxMB     = {} MB".format(jobreqlist[0]["jobmaxmemory"]))
        print(" ReserveMB = {} MB".format(jobreqlist[0]["reservememory"]))
        print(
            " Total     = {} MB".format(
                int(jobreqlist[0]["jobmaxmemory"])
                + int(jobreqlist[0]["reservememory"])
            )
        )

        if self.config.verbose or self.config.debug:
            print(
                (
                    colored(
                        bannertext.banner_sl_box(
                            text="Job available on following Engines:"
                        ),
                        "yellow",
                    )
                )
            )
            print(
                "{0:>1}{1:<35}{2:>20}{3:>20}".format(
                    "", "Engine Name", "Job ID", "Env Name"
                )
            )

        if self.config.verbose or self.config.debug:
            for row in engine_pool_for_job:
                print(
                    "{0:>1}{1:<35}{2:>20}{3:>20}".format(
                        " ",
                        row["ip_address"],
                        row["jobid"],
                        row["environmentname"],
                    )
                )

        if self.config.verbose or self.config.debug:
            print(
                (
                    colored(
                        bannertext.banner_sl_box(
                            text="Available Engine Pool:"
                        ),
                        "yellow",
                    )
                )
            )
            print(
                "{0:>1}{1:<35}{2:>20}{3:>20}{4:>20}".format(
                    "",
                    "Engine Name",
                    "Total Memory(MB)",
                    "System Memory(MB)",
                    "Pool Name",
                )
            )
            for ind in engine_list:
                print(
                    "{0:>1}{1:<35}{2:>20}{3:>20}{4:>20}".format(
                        " ",
                        ind["ip_address"],
                        ind["totalmb"],
                        ind["systemmb"],
                        ind["poolname"],
                    )
                )

        if nonreach_enginelist:
            if self.config.verbose or self.config.debug:
                print(
                    (
                        colored(
                            bannertext.banner_sl_box(
                                text="Unreachable Engine Pool:"
                            ),
                            "yellow",
                        )
                    )
                )
                print(
                    "{0:>1}{1:<35}{2:>20}{3:>20}{4:>20}".format(
                        "",
                        "Engine Name",
                        "Total Memory(MB)",
                        "System Memory(MB)",
                        "Pool Name",
                    )
                )
                for ind in nonreach_enginelist:
                    print(
                        "{0:>1}{1:<35}{2:>20}{3:>20}{4:>20}".format(
                            " ",
                            ind["ip_address"],
                            ind["totalmb"],
                            ind["systemmb"],
                            ind["poolname"],
                        )
                    )

        # if self.config.verbose or self.config.debug:
        if self.config.debug:
            print(
                (
                    colored(
                        bannertext.banner_sl_box(text="CPU Usage:"), "yellow"
                    )
                )
            )
            print(
                "{0:>1}{1:<35}{2:>20}".format("", "Engine Name", "Used CPU(%)")
            )
            for ind in enginecpu_list:
                print(
                    "{0:>1}{1:<35}{2:>20}".format(
                        " ", ind["ip_address"], ind["cpu"]
                    )
                )

        print_debug("jobexec_list = \n{}".format(jobexec_list))
        engineusage = self.group_job_mem_usage(
            "ip_address", "jobmaxmemory", jobexec_list
        )
        print_debug("engineusage = \n{}".format(engineusage))
        if engineusage is None:
            print_debug("Creating empty list.")
            engineusage_od = []
            temporddict = {}
            for ind in engine_list:
                temporddict = collections.OrderedDict(
                    ip_address=ind["ip_address"], totalusedmemory=0
                )
                engineusage_od.append(temporddict)
            print_debug(engineusage_od)
        else:
            engineusage_od = []
            temporddict = {}
            for row in engineusage:
                engineusage_od.append(collections.OrderedDict(row))

            # Add empty list for remaining engines [ not in jobexeclist ]
            print_debug("engine_list = \n{}".format(engine_list))
            for ind in engine_list:
                i = 0
                for ind1 in engineusage:
                    if ind["ip_address"] == ind1["ip_address"]:
                        i = 1
                if i == 0:
                    temporddict = collections.OrderedDict(
                        ip_address=ind["ip_address"], totalusedmemory=0
                    )
                    engineusage_od.append(temporddict)

        print_debug("engineusage_od = \n{}".format(engineusage_od))

        # if self.config.verbose or self.config.debug:
        if self.config.debug:
            print(
                (
                    colored(
                        bannertext.banner_sl_box(text="Memory Usage:"),
                        "yellow",
                    )
                )
            )
            print(
                "{0:>1}{1:<35}{2:>20}".format(
                    "", "Engine Name", "Used Memory(MB)"
                )
            )
            for ind in engineusage_od:
                print(
                    "{0:>1}{1:<35}{2:>20}".format(
                        " ", ind["ip_address"], ind["totalusedmemory"]
                    )
                )

        if self.config.verbose or self.config.debug:
            print(
                (
                    colored(
                        bannertext.banner_sl_box(text="Engine Current Usage:"),
                        "yellow",
                    )
                )
            )
            print(
                "{0:>1}{1:<35}{2:>20}{3:>20}".format(
                    "", "Engine Name", "Used Memory(MB)", "Used CPU(%)"
                )
            )

        if len(enginecpu_list) != 0:
            engineusage = self.join_dict(
                engineusage_od, enginecpu_list, "ip_address", "cpu"
            )
            self.add_debugspace()
            print_debug("engineusage:{}".format(engineusage))
            self.add_debugspace()
            if self.config.verbose or self.config.debug:
                for ind in engineusage:
                    print(
                        "{0:>1}{1:<35}{2:>20}{3:>20}".format(
                            " ",
                            ind["ip_address"],
                            ind["totalusedmemory"],
                            ind["cpu"],
                        )
                    )
        else:
            print("Handle this situation")

        self.add_debugspace()
        print_debug("enginecpu_list:{}".format(enginecpu_list))
        self.add_debugspace()
        print_debug("engineusage_od = \n{}\n".format(engineusage_od))
        print_debug("enginecpu_list = \n{}\n".format(enginecpu_list))
        print_debug("engineusage = \n{}\n".format(engineusage))

        # if self.config.verbose or self.config.debug:
        #     print((colored(bannertext.banner_sl_box(text="Job available on following engines:"), 'yellow')))
        #     print('{0:>1}{1:<35}{2:>20}{3:>20}'.format("", "Engine Name", "Job ID", "Env Name"))
        #
        # if self.config.verbose or self.config.debug:
        #     for row in engine_pool_for_job:
        #         print(
        #             '{0:>1}{1:<35}{2:>20}{3:>20}'.format(" ", row['ip_address'], row['jobid'], row['environmentname']))

        jpd1 = self.join_dict(
            engine_pool_for_job, engine_list, "ip_address", "dummy"
        )
        print_debug("jpd1 = \n{}\n".format(jpd1))
        jpd2 = self.join_dict(
            jpd1, engineusage, "ip_address", "totalusedmemory"
        )
        # jpd2 = self.join_dict(jpd1, engineusage, 'ip_address', 'dummy')
        print_debug("jpd2 = \n{}\n".format(jpd2))

        tempjpd = []
        for jpd in jpd2:
            availablemb = (
                int(jpd["totalmb"])
                - int(jpd["systemmb"])
                - int(jpd["totalusedmemory"])
                - int(jobreqlist[0]["jobmaxmemory"])
                - int(jobreqlist[0]["reservememory"])
            )
            jpd["availablemb"] = availablemb
            tempjpd.append(jpd)

        jpd2 = tempjpd
        print_debug("jpd2:".format(jpd2))
        self.add_debugspace()
        (
            qualified_engines,
            unqualified_engines,
        ) = self.get_unqualified_qualified_engines(jpd2)
        print_debug("qualified_engines = \n{}\n".format(qualified_engines))
        print_debug("unqualified_engines = \n{}\n".format(unqualified_engines))
        self.add_debugspace()
        jobpool_qualified_engines = self.get_jobpool_qualified_engines(
            qualified_engines
        )
        jobpool_unqualified_engines = self.get_jobpool_unqualified_engines(
            unqualified_engines
        )
        qualified_engines = jobpool_qualified_engines
        unqualified_engines = jobpool_unqualified_engines
        print_debug(
            "POOL:qualified_engines = \n{}\n".format(qualified_engines)
        )
        print_debug(
            "POOL:unqualified_engines = \n{}\n".format(unqualified_engines)
        )
        self.add_debugspace()

        if len(qualified_engines) == 0:
            redcandidate = []
            for item in unqualified_engines:
                item.update(
                    {
                        "maxavailablememory": (
                            float(item["availablemb"])
                            + float(jobreqlist[0]["jobmaxmemory"])
                            + float(jobreqlist[0]["reservememory"])
                        )
                    }
                )
                redcandidate.append(item)

            if self.config.verbose or self.config.debug:
                print(
                    (
                        colored(
                            bannertext.banner_sl_box(text="Red Engines:"),
                            "yellow",
                        )
                    )
                )
                print(
                    "{0:>1}{1:<35}{2:>20}{3:>20}".format(
                        "",
                        "Engine Name",
                        "Available Memory(MB)",
                        "Used CPU(%)",
                    )
                )
                for ind in redcandidate:
                    print(
                        colored(
                            "{0:>1}{1:<35}{2:>20}{3:>20}".format(
                                " ",
                                ind["ip_address"],
                                round(int(ind["maxavailablememory"])),
                                ind["cpu"],
                            ),
                            "red",
                        )
                    )
            print(" ")
            # Sort by max available memory
            sorted_redcandidate = sorted(
                redcandidate,
                key=lambda k: k["maxavailablememory"],
                reverse=True,
            )
            print_debug("Printing - sorted by memory")
            for ind in sorted_redcandidate:
                print_debug(
                    colored(
                        "{0:>1}{1:<35}{2:>20}{3:>20}".format(
                            " ",
                            ind["ip_address"],
                            round(int(ind["maxavailablememory"])),
                            ind["cpu"],
                        ),
                        "red",
                    )
                )
            queue_enabled_eng_found = False
            for ind in sorted_redcandidate:
                engine_name = ind["ip_address"]
                apikey = self.get_auth_key(engine_name)
                engine_version = self.find_engine_version(engine_name, apikey)
                print_debug(
                    "engine_name = {}, engine_version = {}".format(
                        engine_name, engine_version
                    )
                )
                is_queue_enabled = self.chk_eng_queue_enabled(engine_version)
                print_debug("is_queue_enabled = {}".format(is_queue_enabled))
                # is_queue_enabled = True
                # print_debug("is_queue_enabled = {}".format(is_queue_enabled))
                if is_queue_enabled:
                    queue_enabled_eng_found = True
                    if self.run:
                        jobid = self.find_job_id(
                            self.jobname, self.envname, engine_name, apikey
                        )
                        chk_status = self.chk_job_running()
                        if chk_status == 0:
                            job_exec_response = self.exec_job(
                                engine_name, apikey, jobid
                            )
                            if job_exec_response is not None:
                                if job_exec_response["status"] == "RUNNING":
                                    executionId = job_exec_response[
                                        "executionId"
                                    ]
                                    print_green_on_white = lambda x: cprint(
                                        x, "blue", "on_white"
                                    )
                                    print_green_on_white(
                                        " Execution of Masking job# {} with execution ID {} on Engine {} is in progress".format(
                                            jobid, executionId, engine_name
                                        )
                                    )
                                else:
                                    curr_job_status = job_exec_response[
                                        "status"
                                    ]
                                    print_red_on_white = lambda x: cprint(
                                        x, "red", "on_white"
                                    )
                                    print_red_on_white(
                                        " Execution status of Masking job# {} on Engine {} : {}. Queued job will start as soon as slots are free.".format(
                                            jobid, engine_name, curr_job_status
                                        )
                                    )
                            else:
                                print_red_on_white = lambda x: cprint(
                                    x, "red", "on_white"
                                )
                                print_red_on_white(
                                    " Execution of Masking job# {} on Engine {} failed".format(
                                        jobid, engine_name
                                    )
                                )
                                raise Exception(
                                    "ERROR: Execution of Masking job# {} on Engine {} failed".format(
                                        jobid, engine_name))
                        else:
                            print_red_on_white = lambda x: cprint(
                                x, "red", "on_white"
                            )
                            print_red_on_white(
                                " Job {} on Env {} is already running on engine {} - Check Status {}. Please retry later".format(
                                    self.jobname,
                                    self.envname,
                                    engine_name,
                                    chk_status,
                                )
                            )
                            raise Exception(
                                "ERROR: Job {} on Env {} is already running on engine {} - Check Status {}. Please retry later".format(
                                    self.jobname,
                                    self.envname,
                                    engine_name,
                                    chk_status,))
                        break
                    else:
                        print_green_on_white = lambda x: cprint(
                            x, "blue", "on_white"
                        )
                        print_green_on_white(
                            " Engine {} selected as probable candidate for execution of Masking job# {} [ Job not submitted ]".format(
                                engine_name,
                                self.jobname,
                            )
                        )
                    break
                else:
                    queue_enabled_eng_found = False
                    print_debug(
                        "Engine {}. Queue not supported. Proceed with next red engine".format(
                            engine_name
                        )
                    )

            print_debug(
                "queue_enabled_eng_found = {}".format(queue_enabled_eng_found)
            )
            if not queue_enabled_eng_found:
                print(
                    " All engines are busy. Running job {} of environment {} may cause issues.".format(
                        self.jobname, self.envname
                    )
                )
                print(
                    " Existing jobs may complete after sometime and create additional capacity to execute new job."
                )
                print(" Please retry later.")
                print(" ")
                print(
                    "",
                    colored(
                        "Recommendation: 1",
                        color="green",
                        attrs=["reverse", "blink", "bold"],
                    ),
                )
                print(" Please retry later.")
                print(" ")
                print(
                    "",
                    colored(
                        "Recommendation: 2",
                        color="green",
                        attrs=["reverse", "blink", "bold"],
                    ),
                )
                print(
                    " Add job to following engines using sync_eng/sync_env/sync_job module"
                )
                print(" ./msksidekick.py sync-eng")
                print(" OR")
                print(" ./msksidekick.py sync-env")
                print(" ")
                print(" Job can be added to following engines")
                idx = 0
                for engine in engine_list:
                    i = 0
                    for red in redcandidate:
                        if engine["ip_address"] == red["ip_address"]:
                            i = 1
                    if i == 0:
                        idx = idx + 1
                        print(" {}) {}".format(idx, engine["ip_address"]))
                print(" ")
                raise Exception(
                    "ERROR: All engines are busy. Running job {} of environment {} may cause issues.".format(
                        self.jobname, self.envname))
        else:
            redcandidate = []
            for item in unqualified_engines:
                item.update(
                    {
                        "maxavailablememory": (
                            float(item["availablemb"])
                            + float(jobreqlist[0]["jobmaxmemory"])
                            + float(jobreqlist[0]["reservememory"])
                        )
                    }
                )
                redcandidate.append(item)

            if self.config.verbose or self.config.debug:
                print(
                    (
                        colored(
                            bannertext.banner_sl_box(text="Red Engines:"),
                            "yellow",
                        )
                    )
                )
                print(
                    "{0:>1}{1:<35}{2:>20}{3:>20}".format(
                        "",
                        "Engine Name",
                        "Available Memory(MB)",
                        "Used CPU(%)",
                    )
                )
                for ind in redcandidate:
                    print(
                        colored(
                            "{0:>1}{1:<35}{2:>20}{3:>20}".format(
                                " ",
                                ind["ip_address"],
                                round(int(ind["maxavailablememory"])),
                                ind["cpu"],
                            ),
                            "red",
                        )
                    )

            bestcandidatedetails = []
            for item in qualified_engines:
                item.update(
                    {
                        "maxavailablememory": (
                            float(item["availablemb"])
                            + float(jobreqlist[0]["jobmaxmemory"])
                            + float(jobreqlist[0]["reservememory"])
                        )
                    }
                )
                bestcandidatedetails.append(item)
            # print(qualified_engines)
            # print(bestcandidatedetails)
            if self.config.verbose or self.config.debug:
                print(
                    (
                        colored(
                            bannertext.banner_sl_box(text="Green Engines:"),
                            "yellow",
                        )
                    )
                )
                print(
                    "{0:>1}{1:<35}{2:>20}{3:>20}".format(
                        "",
                        "Engine Name",
                        "Available Memory(MB)",
                        "Used CPU(%)",
                    )
                )
                for ind in bestcandidatedetails:
                    print(
                        colored(
                            "{0:>1}{1:<35}{2:>20}{3:>20}".format(
                                " ",
                                ind["ip_address"],
                                round(int(ind["maxavailablememory"])),
                                ind["cpu"],
                            ),
                            "green",
                        )
                    )

            print(
                (
                    colored(
                        bannertext.banner_sl_box(text="Best Candidate:"),
                        "yellow",
                    )
                )
            )
            print(" ")
            winner_engine = self.get_max_free_mem_engine(bestcandidatedetails)
            engine_name = winner_engine["ip_address"]
            engine_mem = winner_engine["maxavailablememory"]
            engine_cpu = winner_engine["cpu"]
            print(
                colored(
                    " Engine : {} , Available Memory : {} MB ,  Available CPU : {}% ".format(
                        engine_name, engine_mem, (100 - float(engine_cpu))
                    ),
                    color="green",
                    attrs=["reverse", "blink", "bold"],
                )
            )

            if self.run:
                apikey = self.get_auth_key(engine_name)
                # print(apikey)
                jobid = self.find_job_id(
                    self.jobname, self.envname, engine_name, apikey
                )
                chk_status = self.chk_job_running()
                if chk_status == 0:
                    job_exec_response = self.exec_job(
                        engine_name, apikey, jobid
                    )
                    if job_exec_response is not None:
                        if job_exec_response["status"] == "RUNNING":
                            executionId = job_exec_response["executionId"]
                            print_green_on_white = lambda x: cprint(
                                x, "blue", "on_white"
                            )
                            print_green_on_white(
                                " Execution of Masking job# {} with execution ID {} on Engine {} is in progress".format(
                                    jobid, executionId, engine_name
                                )
                            )
                        else:
                            print_red_on_white = lambda x: cprint(
                                x, "red", "on_white"
                            )
                            print_red_on_white(
                                " Execution of Masking job# {} on Engine {} failed".format(
                                    jobid, engine_name
                                )
                            )
                            raise Exception(
                                "ERROR: Execution of Masking job# {} on Engine {} failed.".format(
                                    jobid, engine_name))
                    else:
                        print_red_on_white = lambda x: cprint(
                            x, "red", "on_white"
                        )
                        print_red_on_white(
                            " Execution of Masking job# {} on Engine {} failed".format(
                                jobid, engine_name
                            )
                        )
                        raise Exception(
                            "ERROR: Execution of Masking job# {} on Engine {} failed.".format(
                                jobid, engine_name))
                else:
                    print_red_on_white = lambda x: cprint(x, "red", "on_white")
                    print_red_on_white(
                        " Job {} on Env {} is already running on engine {} - Check Status {}. Please retry later".format(
                            self.jobname, self.envname, engine_name, chk_status
                        )
                    )
            print(" ")

    def pull_joblist(self):
        if self.mskengname == "all":

            try:
                if os.path.exists(self.joblistfile):
                    os.remove(self.joblistfile)
                    f = open(self.joblistfile, "w")
                    f.write(
                        "{},{},{},{},{},{},{}\n".format(
                            "jobid",
                            "jobname",
                            "jobmaxmemory",
                            "reservememory",
                            "environmentid",
                            "environmentname",
                            "ip_address",
                        )
                    )
                    f.close()
                else:
                    f = open(self.joblistfile, "w")
                    f.write(
                        "{},{},{},{},{},{},{}\n".format(
                            "jobid",
                            "jobname",
                            "jobmaxmemory",
                            "reservememory",
                            "environmentid",
                            "environmentname",
                            "ip_address",
                        )
                    )
                    f.close()
            except:
                print_debug("Error deleting file ", self.joblistfile)

            engine_list = self.create_dictobj(self.enginelistfile)
            for engine in engine_list:
                engine_name = engine["ip_address"]
                apikey = self.get_auth_key(engine_name)
                # print("apikey:{}".format(apikey))
                if apikey is not None:
                    apicall = "environments?page_number=1&page_size=999"
                    envlist_response = self.get_api_response(
                        engine_name, apikey, apicall
                    )

                    f = open(self.joblistfile, "a")

                    for envname in envlist_response["responseList"]:
                        jobapicall = "masking-jobs?page_number=1&page_size=999&environment_id={}".format(
                            envname["environmentId"]
                        )
                        joblist_response = self.get_api_response(
                            engine_name, apikey, jobapicall
                        )
                        joblist_responselist = joblist_response["responseList"]
                        for joblist in joblist_responselist:
                            f.write(
                                "{},{},{},{},{},{},{}\n".format(
                                    joblist["maskingJobId"],
                                    joblist["jobName"],
                                    joblist["maxMemory"],
                                    "0",
                                    envname["environmentId"],
                                    envname["environmentName"],
                                    engine_name,
                                )
                            )
                    f.close()
                    print(
                        "File {} successfully updated with jobs from {}".format(
                            self.joblistfile, engine_name
                        )
                    )

        else:
            # Delete existing jobs for particular engine
            newjoblist = []
            try:
                i = 0
                if os.path.exists(self.joblistfile):
                    job_list = self.create_dictobj(self.joblistfile)
                    for job in job_list:
                        if self.mskengname != job["ip_address"]:
                            newjoblist.append(job)
                        else:
                            i = 1
                            print(
                                "Existing Job {} deleted for engine {}".format(
                                    job["jobname"], self.mskengname
                                )
                            )

                    if i == 1:

                        try:
                            if os.path.exists(self.joblistfile):
                                os.remove(self.joblistfile)
                                f = open(self.joblistfile, "w")
                                f.write(
                                    "{},{},{},{},{},{},{}\n".format(
                                        "jobid",
                                        "jobname",
                                        "jobmaxmemory",
                                        "reservememory",
                                        "environmentid",
                                        "environmentname",
                                        "ip_address",
                                    )
                                )
                                f.close()
                        except:
                            print_debug(
                                "Error deleting file ", self.joblistfile
                            )

                        f = open(self.joblistfile, "a")
                        for job in newjoblist:
                            f.write(
                                "{},{},{},{},{},{},{}\n".format(
                                    job["jobid"],
                                    job["jobname"],
                                    job["jobmaxmemory"],
                                    job["reservememory"],
                                    job["environmentid"],
                                    job["environmentname"],
                                    job["ip_address"],
                                )
                            )
                        f.close()
                    else:
                        print(
                            "No existing jobs found for Engine {} in pool".format(
                                self.mskengname
                            )
                        )
                else:
                    print(
                        "File {} does not exists. Creating it".format(
                            self.joblistfile
                        )
                    )
                    f = open(self.joblistfile, "w")
                    f.write(
                        "{},{},{},{},{},{},{}\n".format(
                            "jobid",
                            "jobname",
                            "jobmaxmemory",
                            "reservememory",
                            "environmentid",
                            "environmentname",
                            "ip_address",
                        )
                    )
                    f.close()
            except Exception as e:
                print_debug(str(e))
                print_debug(
                    "Error deleting jobs for engine {} in file {}".format(
                        self.mskengname, self.joblistfile
                    )
                )

            # Pull New List
            engine_name = self.mskengname
            apikey = self.get_auth_key(engine_name)
            if apikey is not None:
                apicall = "environments?page_number=1&page_size=999"
                envlist_response = self.get_api_response(
                    engine_name, apikey, apicall
                )
                f = open(self.joblistfile, "a")
                for envname in envlist_response["responseList"]:
                    jobapicall = "masking-jobs?page_number=1&page_size=999&environment_id={}".format(
                        envname["environmentId"]
                    )
                    joblist_response = self.get_api_response(
                        engine_name, apikey, jobapicall
                    )
                    joblist_responselist = joblist_response["responseList"]
                    for joblist in joblist_responselist:
                        f.write(
                            "{},{},{},{},{},{},{}\n".format(
                                joblist["maskingJobId"],
                                joblist["jobName"],
                                joblist["maxMemory"],
                                "0",
                                envname["environmentId"],
                                envname["environmentName"],
                                engine_name,
                            )
                        )
                f.close()
                print(
                    "Job list for engine {} successfully generated in file {}".format(
                        self.mskengname, self.joblistfile
                    )
                )

    @dump_func_name
    def pull_eng_jobexeclist(self, engine, testconn_eng_list):
        print_debug(
            "Engine : {}".format(json.dumps(engine, indent=4, sort_keys=True))
        )
        engine_name = engine["ip_address"]
        apikey = self.get_auth_key(engine_name)
        print_debug("apikey : {}".format(apikey))
        if apikey is not None:
            testconn_eng_list.append(engine_name)
            apicall = "environments?page_number=1&page_size=999"
            envlist_response = self.get_api_response(
                engine_name, apikey, apicall
            )
            for envname in envlist_response["responseList"]:
                print_debug("envname : {}".format(envname))
                jobapicall = "masking-jobs?page_number=1&page_size=999&environment_id={}".format(
                    envname["environmentId"]
                )
                joblist_response = self.get_api_response(
                    engine_name, apikey, jobapicall
                )
                joblist_responselist = joblist_response["responseList"]
                for joblist in joblist_responselist:
                    print_debug("joblist : {}".format(joblist))
                    fe = open(self.jobexeclistfile, "a")
                    jobexecapicall = "executions?job_id={}&page_number=1&page_size=999".format(
                        joblist["maskingJobId"]
                    )
                    jobexeclist_response = self.get_api_response(
                        engine_name, apikey, jobexecapicall
                    )
                    jobexeclist_responselist = jobexeclist_response[
                        "responseList"
                    ]
                    if jobexeclist_responselist != []:
                        latestexecid = max(
                            jobexeclist_responselist,
                            key=lambda ev: ev["executionId"],
                        )
                        print_debug(
                            "latestexecid-status = {}".format(
                                latestexecid["status"]
                            )
                        )
                        if latestexecid["status"] == "RUNNING":
                            fe.write(
                                "{},{},{},{},{},{},{},{}\n".format(
                                    joblist["maskingJobId"],
                                    joblist["jobName"],
                                    joblist["maxMemory"],
                                    "0",
                                    envname["environmentId"],
                                    envname["environmentName"],
                                    engine_name,
                                    latestexecid["status"],
                                )
                            )
                    fe.close()

    def pull_jobexeclist(self):
        t = time.time()
        threadlist = {}
        try:
            if os.path.exists(self.jobexeclistfile):
                os.remove(self.jobexeclistfile)
                fe = open(self.jobexeclistfile, "w")
                fe.write(
                    "{},{},{},{},{},{},{},{}\n".format(
                        "jobid",
                        "jobname",
                        "jobmaxmemory",
                        "reservememory",
                        "environmentid",
                        "environmentname",
                        "ip_address",
                        "jobstatus",
                    )
                )
                fe.close()
            else:
                fe = open(self.jobexeclistfile, "w")
                fe.write(
                    "{},{},{},{},{},{},{},{}\n".format(
                        "jobid",
                        "jobname",
                        "jobmaxmemory",
                        "reservememory",
                        "environmentid",
                        "environmentname",
                        "ip_address",
                        "jobstatus",
                    )
                )
                fe.close()
        except:
            print_debug("Error while deleting file ", self.jobexeclistfile)

        engine_list = self.create_dictobj(self.enginelistfile)
        testconn_eng_list = []
        self.print_debug_banner("Pull engine jobexec data")
        i = 0
        for engine in engine_list:
            print_debug("jobexec Engine : {}".format(engine))
            threadlist[i] = threading.Thread(
                target=self.pull_eng_jobexeclist,
                args=(
                    engine,
                    testconn_eng_list,
                ),
            )
            print_debug("threadlist: {}".format(threadlist))
            threadlist[i].start()
            # time.sleep(1)
            i = i + 1

        for threadkeys in threadlist.keys():
            print_debug("threadkey = {}".format(threadkeys))
            threadlist[threadkeys].join()

        if not testconn_eng_list:
            bannertext = banner()
            if self.config.verbose or self.config.debug:
                print(
                    (
                        colored(
                            bannertext.banner_sl_box(
                                text="Available Engine Pool:"
                            ),
                            "yellow",
                        )
                    )
                )
                print(
                    "{0:>1}{1:<35}{2:>20}".format(
                        "", "Engine Name", "Pool Name"
                    )
                )
                for ind in engine_list:
                    print(
                        "{0:>1}{1:<35}{2:>20}".format(
                            " ", ind["ip_address"], ind["poolname"]
                        )
                    )
            print("ERROR: Unable to connect any engine in engine pool")
            raise Exception(
                "ERROR: Unable to connect any engine in engine pool"
            )
        else:
            print_debug(
                "File {} successfully generated".format(self.jobexeclistfile)
            )
            print_debug(
                "jobexeclist data collection done in {0} Minutes".format(
                    (time.time() - t) / 60
                )
            )

    def pull_currjoblist(self):
        connection_success = 0
        processid = os.getpid()
        bannertext = banner()
        self.jobexeclistfile = "{}.{}".format(self.jobexeclistfile, processid)
        try:
            if os.path.exists(self.jobexeclistfile):
                os.remove(self.jobexeclistfile)
            fe = open(self.jobexeclistfile, "w")
            fe.write(
                "{},{},{},{},{},{},{},{},{},{},{},{}\n".format(
                    "jobid",
                    "jobname",
                    "jobmaxmemory",
                    "reservememory",
                    "environmentid",
                    "environmentname",
                    "ip_address",
                    "jobstatus",
                    "rowsMasked",
                    "rowsTotal",
                    "startTime",
                    "poolname",
                )
            )
            fe.close()
        except:
            print_debug("Error while deleting file ", self.jobexeclistfile)

        engine_list = self.create_dictobj(self.enginelistfile)
        # print(engine_list)
        for engine in engine_list:
            # print_debug("Engine : {}".format(engine))
            print_debug(
                "Engine : {}, Poolname: {}".format(engine, engine["poolname"])
            )
            if engine["poolname"] == self.poolname:
                # print("Engine : {}, Poolname: {}".format(engine, engine['poolname']))
                engine_name = engine["ip_address"]
                apikey = self.get_auth_key(engine_name)
                print_debug("apikey : {}".format(apikey))
                if apikey is not None:
                    connection_success = connection_success + 1
                    apicall = "environments?page_number=1&page_size=999"
                    envlist_response = self.get_api_response(
                        engine_name, apikey, apicall
                    )
                    for envname in envlist_response["responseList"]:
                        print_debug("envname : {}".format(envname))
                        jobapicall = "masking-jobs?page_number=1&page_size=999&environment_id={}".format(
                            envname["environmentId"]
                        )
                        joblist_response = self.get_api_response(
                            engine_name, apikey, jobapicall
                        )
                        joblist_responselist = joblist_response["responseList"]
                        for joblist in joblist_responselist:
                            print_debug("joblist : {}".format(joblist))
                            #fe = open(self.jobexeclistfile, "a")
                            jobexecapicall = "executions?job_id={}&page_number=1&page_size=999".format(
                                joblist["maskingJobId"]
                            )
                            jobexeclist_response = self.get_api_response(
                                engine_name, apikey, jobexecapicall
                            )
                            jobexeclist_responselist = jobexeclist_response[
                                "responseList"
                            ]
                            if jobexeclist_responselist != []:
                                latestexecid = max(
                                    jobexeclist_responselist,
                                    key=lambda ev: ev["executionId"],
                                )
                                print_debug(
                                    "latestexecid = {}".format(latestexecid)
                                )

                                if self.jobname and self.envname:
                                    print_debug("By Job")
                                    if (
                                        self.jobname == joblist["jobName"]
                                        and self.envname
                                        == envname["environmentName"]
                                    ):
                                        fe = open(self.jobexeclistfile, "a")
                                        fe.write(
                                            "{},{},{},{},{},{},{},{},{},{},{},{}\n".format(
                                                joblist["maskingJobId"],
                                                joblist["jobName"],
                                                joblist["maxMemory"],
                                                "0",
                                                envname["environmentId"],
                                                envname["environmentName"],
                                                engine_name,
                                                latestexecid["status"],
                                                "-"
                                                if latestexecid["status"]
                                                == "QUEUED"
                                                else latestexecid["rowsMasked"]
                                                if "rowsMasked"
                                                in latestexecid.keys()
                                                else "0",
                                                "-"
                                                if latestexecid["status"]
                                                == "QUEUED"
                                                else latestexecid["rowsTotal"]
                                                if "rowsTotal"
                                                in latestexecid.keys()
                                                else "0",
                                                self.extract_start_or_submit_datetime(
                                                    latestexecid
                                                ),
                                                engine["poolname"],
                                            )
                                        )
                                        fe.close()
                                else:
                                    print_debug("All Jobs")
                                    print_debug(latestexecid)
                                    # Customer requested to list all status
                                    # if latestexecid['status'] == "RUNNING" or latestexecid['status'] == "QUEUED" or latestexecid['status'] == "SUCCEEDED":
                                    if (
                                        latestexecid["status"]
                                        == latestexecid["status"]
                                    ):
                                        fe = open(self.jobexeclistfile, "a")
                                        fe.write(
                                            "{},{},{},{},{},{},{},{},{},{},{},{}\n".format(
                                                joblist["maskingJobId"],
                                                joblist["jobName"],
                                                joblist["maxMemory"],
                                                "0",
                                                envname["environmentId"],
                                                envname["environmentName"],
                                                engine_name,
                                                latestexecid["status"],
                                                "-"
                                                if latestexecid["status"]
                                                == "QUEUED"
                                                else latestexecid["rowsMasked"]
                                                if "rowsMasked"
                                                in latestexecid.keys()
                                                else "0",
                                                "-"
                                                if latestexecid["status"]
                                                == "QUEUED"
                                                else latestexecid["rowsTotal"]
                                                if "rowsTotal"
                                                in latestexecid.keys()
                                                else "0",
                                                self.extract_start_or_submit_datetime(
                                                    latestexecid
                                                ),
                                                engine["poolname"],
                                            )
                                        )
                                        fe.close()
            else:
                print_debug(
                    "Engine not from requested pool : {}, Poolname: {}".format(
                        engine, engine["poolname"]
                    )
                )

        if connection_success > 0:
            print_debug(
                "File {} successfully generated".format(self.jobexeclistfile)
            )
        else:
            print("Unable to connect any engines")
            raise Exception(
                "ERROR: Unable to connect any engines")
        jobexec_list = self.create_dictobj(self.jobexeclistfile)
        print(
            (
                colored(
                    bannertext.banner_sl_box(text="JOB POOL EXECUTION LIST:"),
                    "yellow",
                )
            )
        )
        print(
            "{0:>1}{1:<35}{2:<7}{3:25}{4:<25}{5:<12}{6:>11}{7:>11}{8:>32}{9:>20}".format(
                " ",
                "Engine name",
                "Job Id",
                "Job Name",
                "Env Name",
                "Job Status",
                "rowsMasked",
                "rowsTotal",
                "startTime/submitTime/endTime",
                "PoolName",
            )
        )

        jobexec_list = self.create_dictobj(self.jobexeclistfile)
        for row in jobexec_list:
            print(
                "{0:>1}{1:<35}{2:<7}{3:25}{4:<25}{5:<12}{6:>11}{7:>11}{8:>32}{9:>20}".format(
                    " ",
                    row["ip_address"],
                    row["jobid"],
                    row["jobname"],
                    row["environmentname"],
                    row["jobstatus"],
                    row["rowsMasked"],
                    row["rowsTotal"],
                    row["startTime"],
                    row["poolname"],
                )
            )

        try:
            os.rename(self.jobexeclistfile, os.path.join(self.jobexeclistfile, ".tmp"))
            os.rename(os.path.join(self.jobexeclistfile, ".tmp"), self.jobexeclistfile)
            os.remove(self.jobexeclistfile)
        except OSError as e:
            print_debug('{} File is still open. error is {}'.format(self.jobexeclistfile, str(e)))
            os.remove(self.jobexeclistfile)

    def sync_globalobj(self):
        self.sync_syncable_objects("GLOBAL_OBJECT")
        self.sync_syncable_objects("FILE_FORMAT")
        self.sync_syncable_objects("MOUNT_INFORMATION")

    def sync_globalfileformats(self):
        src_engine_name = self.srcmskengname
        tgt_engine_name = self.tgtmskengname
        globalfileformats = True
        i = None
        srcapikey = self.get_auth_key(src_engine_name)
        if srcapikey is not None:
            if globalfileformats:
                syncobjapicall = "syncable-objects?page_number=1&page_size=999&object_type=FILE_FORMAT"
                syncobjapicallresponse = self.get_api_response(
                    src_engine_name, srcapikey, syncobjapicall
                )
                for globalfileobj in syncobjapicallresponse["responseList"]:
                    i = 1
                    globalfileobjdef = []
                    globalfileobjdef.append(globalfileobj)
                    srcapicall = "export"
                    srcapiresponse = self.post_api_response1(
                        src_engine_name,
                        srcapikey,
                        srcapicall,
                        globalfileobjdef,
                        port=80,
                    )

                    tgtapikey = self.get_auth_key(tgt_engine_name)
                    tgtapicall = "import?force_overwrite=true"
                    tgtapiresponse = self.post_api_response1(
                        tgt_engine_name,
                        tgtapikey,
                        tgtapicall,
                        srcapiresponse,
                        port=80,
                    )
                    if tgtapiresponse is None:
                        print(" File Format synced failed.")
                    else:
                        print(" File Format synced successfully.")
                if i == 1:
                    print(" ")
        else:
            print(" Error connecting source engine {}".format(src_engine_name))

    def sync_globalmountfs(self):
        src_engine_name = self.srcmskengname
        tgt_engine_name = self.tgtmskengname
        globalmountfs = True
        i = None
        srcapikey = self.get_auth_key(src_engine_name)
        if srcapikey is not None:
            if globalmountfs:
                syncobjapicall = "syncable-objects?page_number=1&page_size=999&object_type=MOUNT_INFORMATION"
                syncobjapicallresponse = self.get_api_response(
                    src_engine_name, srcapikey, syncobjapicall
                )
                for globalmountfs in syncobjapicallresponse["responseList"]:
                    i = 1
                    globalmountfsdef = []
                    globalmountfsdef.append(globalmountfs)
                    srcapicall = "export"
                    srcapiresponse = self.post_api_response1(
                        src_engine_name,
                        srcapikey,
                        srcapicall,
                        globalmountfsdef,
                        port=80,
                    )

                    tgtapikey = self.get_auth_key(tgt_engine_name)
                    tgtapicall = "import?force_overwrite=true"
                    tgtapiresponse = self.post_api_response1(
                        tgt_engine_name,
                        tgtapikey,
                        tgtapicall,
                        srcapiresponse,
                        port=80,
                    )
                    if tgtapiresponse is None:
                        print(" Mount FS synced failed.")
                    else:
                        print(" Mount FS synced successfully.")
                if i == 1:
                    print(" ")
        else:
            print(" Error connecting source engine {}".format(src_engine_name))

    def sync_syncable_objects(self, syncable_object_type):
        src_engine_name = self.srcmskengname
        tgt_engine_name = self.tgtmskengname
        i = None
        srcapikey = self.get_auth_key(src_engine_name)
        if srcapikey is not None:
            syncobjapicall = "syncable-objects?page_number=1&page_size=999&object_type={}".format(
                syncable_object_type
            )
            syncobjapicallresponse = self.get_api_response(
                src_engine_name, srcapikey, syncobjapicall
            )
            for syncable_object_type_elem in syncobjapicallresponse[
                "responseList"
            ]:
                i = 1
                syncable_object_type_def = []
                syncable_object_type_def.append(syncable_object_type_elem)
                srcapicall = "export"
                srcapiresponse = self.post_api_response1(
                    src_engine_name,
                    srcapikey,
                    srcapicall,
                    syncable_object_type_def,
                    port=80,
                )

                tgtapikey = self.get_auth_key(tgt_engine_name)
                tgtapicall = "import?force_overwrite=true"
                tgtapiresponse = self.post_api_response1(
                    tgt_engine_name,
                    tgtapikey,
                    tgtapicall,
                    srcapiresponse,
                    port=80,
                )
                if tgtapiresponse is None:
                    print(
                        " Syncable Object {} sync failed.".format(
                            syncable_object_type
                        )
                    )
                else:
                    print(
                        " Syncable Object {} synced successfully.".format(
                            syncable_object_type
                        )
                    )
            if i == 1:
                print(" ")
        else:
            print(" Error connecting source engine {}".format(src_engine_name))

    def process_sync_job(
        self,
        src_engine_name,
        tgt_engine_name,
        globalobjsync,
        src_env_name,
        tgt_env_name,
        jobname,
    ):

        srcapikey = self.get_auth_key(src_engine_name)
        print_debug("srcapikey={}".format(srcapikey))

        tgtapikey = self.get_auth_key(tgt_engine_name)
        print_debug("tgtapikey={}".format(tgtapikey))

        if srcapikey is not None and tgtapikey is not None:
            src_job_id = self.find_job_id(
                jobname, src_env_name, src_engine_name, srcapikey
            )

            if globalobjsync:
                self.sync_globalobj()

            # Create dummy app to handle on the fly masking job/env
            cr_app_response = self.create_application(
                tgt_engine_name, self.src_dummy_conn_app, tgtapikey
            )
            src_dummy_conn_app_id = cr_app_response["applicationId"]

            # Create dummy env to handle on the fly masking job/env
            cr_env_response = self.create_environment(
                tgt_engine_name,
                src_dummy_conn_app_id,
                self.src_dummy_conn_env,
                "MASK",
                tgtapikey,
            )
            src_dummy_conn_env_id = cr_env_response["environmentId"]

            print_debug(
                "Source Env name = {}, Source Env purpose = {}, Source App name = {}, Source Env Id = {}, Source App Id = {}".format(
                    self.src_dummy_conn_env,
                    "MASK",
                    self.src_dummy_conn_app,
                    src_dummy_conn_env_id,
                    src_dummy_conn_app_id,
                )
            )
            print(" ")
            #

            syncobjapicall = "syncable-objects?page_number=1&page_size=999&object_type=MASKING_JOB"
            syncobjapicallresponse = self.get_api_response(
                src_engine_name, srcapikey, syncobjapicall
            )
            for jobobj in syncobjapicallresponse["responseList"]:
                curr_job_id = jobobj["objectIdentifier"]["id"]
                if curr_job_id == src_job_id:
                    jobdef = []
                    jobdef.append(jobobj)
                    print_debug("jobobj: {}".format(jobobj))
                    src_env_id = self.find_env_id(
                        src_env_name, src_engine_name, srcapikey
                    )
                    src_env_purpose = self.find_env_purpose(
                        src_env_id, src_engine_name, srcapikey
                    )
                    src_app_id = self.find_appid_of_envid(
                        src_env_id, src_engine_name, srcapikey
                    )
                    src_app_name = self.find_app_name(
                        src_app_id, src_engine_name, srcapikey
                    )
                    print_debug(
                        "Source Env name = {}, Source Env purpose = {}, Source App name = {}, Source Env Id = {}, Source App Id = {}".format(
                            src_env_name,
                            src_env_purpose,
                            src_app_name,
                            src_env_id,
                            src_app_id,
                        )
                    )
                    srcapicall = "export"
                    srcapiresponse = self.post_api_response1(
                        src_engine_name, srcapikey, srcapicall, jobdef, port=80
                    )

                    tgt_env_id = self.find_env_id(
                        tgt_env_name, tgt_engine_name, tgtapikey
                    )
                    tgtapicall = "import?force_overwrite=true&environment_id={}&source_environment_id={}".format(
                        tgt_env_id, src_dummy_conn_env_id
                    )
                    tgtapiresponse = self.post_api_response1(
                        tgt_engine_name,
                        tgtapikey,
                        tgtapicall,
                        srcapiresponse,
                        port=80,
                    )
                    if tgtapiresponse is None:
                        print(" Job {} sync failed.".format(jobname))
                    else:
                        print(
                            " Job {} synced successfully. Please update password for connectors in this environment using GUI / API".format(
                                jobname
                            )
                        )
                    print(" ")
            # print(" ")

        else:
            print(" Error connecting source engine {}".format(src_engine_name))

    def process_sync_env(
        self,
        src_engine_name,
        tgt_engine_name,
        globalobjsync,
        src_env_name,
        tgt_env_name,
        sync_scope,
        srcapikey=None,
        tgtapikey=None,
    ):

        if srcapikey is None:
            srcapikey = self.get_auth_key(src_engine_name)
        print_debug("srcapikey={}".format(srcapikey))

        if tgtapikey is None:
            tgtapikey = self.get_auth_key(tgt_engine_name)
        print_debug("tgtapikey={}".format(tgtapikey))

        tgt_env_not_exists = False

        if srcapikey is not None and tgtapikey is not None:
            if globalobjsync:
                self.sync_globalobj()

            if sync_scope == "ENV":
                try:
                    src_env_id = self.find_env_id(
                        src_env_name, src_engine_name, srcapikey
                    )
                except:
                    raise Exception(
                        "ERROR: Unable to pull source env id for environment {}. Please check engine and environment name".format(
                            src_env_name
                        )
                    )

                try:
                    tgt_env_id = self.find_env_id(
                        tgt_env_name, tgt_engine_name, tgtapikey
                    )
                except:
                    tgt_env_not_exists = True
                    print(
                        "Warning: Unable to pull target env id for environment {}. Assuming environment does not exists".format(
                            tgt_env_name
                        )
                    )
                if tgt_env_id is None:
                    tgt_env_not_exists = True
                    print(
                        " Agent will create new environment {}".format(
                            tgt_env_name
                        )
                    )
                    print(" ")

            # Create dummy app to handle on the fly masking job/env
            cr_app_response = self.create_application(
                tgt_engine_name, self.src_dummy_conn_app, tgtapikey
            )
            src_dummy_conn_app_id = cr_app_response["applicationId"]

            # Create dummy env to handle on the fly masking job/env
            cr_env_response = self.create_environment(
                tgt_engine_name,
                src_dummy_conn_app_id,
                self.src_dummy_conn_env,
                "MASK",
                tgtapikey,
            )
            src_dummy_conn_env_id = cr_env_response["environmentId"]

            print_debug(
                "Source Common OTF Env Id = {}, Source Common OTF App Id = {}".format(
                    src_dummy_conn_env_id, src_dummy_conn_app_id
                )
            )
            print(" ")
            #

            syncobjapicall = "syncable-objects?page_number=1&page_size=999&object_type=ENVIRONMENT"
            syncobjapicallresponse = self.get_api_response(
                src_engine_name, srcapikey, syncobjapicall
            )
            for envobj in syncobjapicallresponse["responseList"]:
                curr_env_id = envobj["objectIdentifier"]["id"]
                if sync_scope == "ENGINE":
                    src_env_id = curr_env_id

                if curr_env_id == src_env_id:
                    envdef = []
                    envdef.append(envobj)
                    print_debug("envobj: {}".format(envobj))
                    # src_env_id = envobj['objectIdentifier']['id']
                    src_env_name = self.find_env_name(
                        src_env_id, src_engine_name, srcapikey
                    )
                    src_env_purpose = self.find_env_purpose(
                        src_env_id, src_engine_name, srcapikey
                    )
                    src_app_id = self.find_appid_of_envid(
                        src_env_id, src_engine_name, srcapikey
                    )
                    src_app_name = self.find_app_name(
                        src_app_id, src_engine_name, srcapikey
                    )
                    print_debug(
                        "Source Env name = {}, Source Env purpose = {}, Source App name = {}, Source Env Id = {}, Source App Id = {}".format(
                            src_env_name,
                            src_env_purpose,
                            src_app_name,
                            src_env_id,
                            src_app_id,
                        )
                    )
                    srcapicall = "export"
                    # print_debug(src_engine_name, srcapikey, srcapicall, envdef, port=80)
                    srcapiresponse = self.post_api_response1(
                        src_engine_name, srcapikey, srcapicall, envdef, port=80
                    )
                    # print_debug("srcapiresponse={}".format(srcapiresponse))

                    if sync_scope == "ENV":
                        if tgt_env_not_exists:
                            print_debug(
                                "In if tgt_env_not_exists : {}".format(
                                    tgt_env_not_exists
                                )
                            )
                            cr_app_response = self.create_application(
                                tgt_engine_name, src_app_name, tgtapikey
                            )
                            tgt_app_id = cr_app_response["applicationId"]
                        else:
                            print_debug(
                                "In else tgt_env_not_exists : {}".format(
                                    tgt_env_not_exists
                                )
                            )
                            tgt_env_id = self.find_env_id(
                                tgt_env_name, tgt_engine_name, tgtapikey
                            )
                            tgt_app_id = self.find_appid_of_envid(
                                tgt_env_id, tgt_engine_name, tgtapikey
                            )
                    elif sync_scope == "ENGINE":
                        cr_app_response = self.create_application(
                            tgt_engine_name, src_app_name, tgtapikey
                        )
                        tgt_app_id = cr_app_response["applicationId"]
                        tgt_env_name = src_env_name
                    else:
                        cr_app_response = self.create_application(
                            tgt_engine_name, src_app_name, tgtapikey
                        )
                        tgt_app_id = cr_app_response["applicationId"]

                    if sync_scope == "ENV":
                        cr_env_response = self.create_environment(
                            tgt_engine_name,
                            tgt_app_id,
                            tgt_env_name,
                            src_env_purpose,
                            tgtapikey,
                        )
                        tgt_env_id = cr_env_response["environmentId"]
                    else:
                        cr_env_response = self.create_environment(
                            tgt_engine_name,
                            tgt_app_id,
                            tgt_env_name,
                            src_env_purpose,
                            tgtapikey,
                        )
                        tgt_env_id = cr_env_response["environmentId"]

                    print_debug(
                        "Target Env Id = {}, Target App Id = {}".format(
                            tgt_env_id, tgt_app_id
                        )
                    )

                    tgtapicall = "import?force_overwrite=true&environment_id={}&source_environment_id={}".format(
                        tgt_env_id, src_dummy_conn_env_id
                    )
                    tgtapiresponse = self.post_api_response1(
                        tgt_engine_name,
                        tgtapikey,
                        tgtapicall,
                        srcapiresponse,
                        port=80,
                    )

                    if tgtapiresponse is None:
                        print(
                            " Environment {} sync failed.".format(tgt_env_name)
                        )
                    else:
                        print(
                            " Environment {} synced successfully. Please update password for connectors in this environment using GUI / API".format(
                                tgt_env_name
                            )
                        )
                    print(" ")

                    if sync_scope == "ENV":
                        break
            # print(" ")
        else:
            print(" Error connecting source engine {}".format(src_engine_name))

    def sync_env(self):
        src_engine_name = self.srcmskengname
        tgt_engine_name = self.tgtmskengname
        globalobjsync = self.globalobjsync
        src_env_name = self.srcenvname
        tgt_env_name = self.tgtenvname
        sync_scope = "ENV"

        srcapikey = self.validate_msk_eng_connection(src_engine_name)
        tgtapikey = self.validate_msk_eng_connection(tgt_engine_name)

        self.process_sync_env(
            src_engine_name,
            tgt_engine_name,
            globalobjsync,
            src_env_name,
            tgt_env_name,
            sync_scope,
            srcapikey,
            tgtapikey,
        )

        print(" Adjust Source Connector for OTF jobs(if any)")
        print_debug(
            " {},{},{},{}".format(
                src_engine_name, tgt_engine_name, src_env_name, tgt_env_name
            )
        )
        del_tmp_env = self.upd_all_otf_jobs_src_connectors(
            src_engine_name,
            tgt_engine_name,
            src_env_name,
            tgt_env_name,
            sync_scope,
        )
        print_debug(" del_tmp_env = {}".format(del_tmp_env))
        print(" ")

        if del_tmp_env == 0:
            print(
                " Delete temporary environment {} created for OTF jobs".format(
                    self.src_dummy_conn_env
                )
            )
            dummy_conn_env_id = self.find_env_id(
                self.src_dummy_conn_env, tgt_engine_name, tgtapikey
            )
            self.del_env_byid(tgt_engine_name, dummy_conn_env_id, tgtapikey)

            print(" ")
            print(
                " Delete temporary application {} created for OTF jobs".format(
                    self.src_dummy_conn_app
                )
            )
            dummy_conn_app_id = self.find_app_id(
                self.src_dummy_conn_app, tgt_engine_name, tgtapikey
            )
            self.del_app_byid(tgt_engine_name, dummy_conn_app_id, tgtapikey)
            print(" ")

        # Commented as it takes time. It can be tested separately
        # conn_type_list = ["database", "file", "mainframe-dataset"]
        # for conn_type in conn_type_list:
        #     self.test_connectors(tgt_engine_name, conn_type, sync_scope, tgt_env_name)

    def validate_msk_eng_connection(self, msk_engine_name):
        mskapikey = self.get_auth_key(msk_engine_name)
        print_debug("mskapikey={}".format(mskapikey))

        if mskapikey is None:
            print(
                " Unable to connect Source engine {}. Please check username, user, password and protocol".format(
                    msk_engine_name
                )
            )
            raise Exception(
                "ERROR: Unable to connect Source engine {}. Please check username, user, password and protocol".format(
                    msk_engine_name
                )
            )
        else:
            return mskapikey

    def sync_eng(self):
        src_engine_name = self.srcmskengname
        tgt_engine_name = self.tgtmskengname
        globalobjsync = self.globalobjsync
        globalobjsync = True
        sync_scope = "ENGINE"

        srcapikey = self.validate_msk_eng_connection(src_engine_name)
        tgtapikey = self.validate_msk_eng_connection(tgt_engine_name)

        self.process_sync_env(
            src_engine_name,
            tgt_engine_name,
            globalobjsync,
            None,
            None,
            sync_scope,
            srcapikey,
            tgtapikey,
        )

        self.add_debugspace()
        self.add_debugspace()
        print(" Adjust Source Connector for OTF jobs(if any)")
        src_env_name = None
        tgt_env_name = None
        print_debug(
            " {},{},{},{}".format(
                src_engine_name, tgt_engine_name, src_env_name, tgt_env_name
            )
        )
        del_tmp_env = self.upd_all_otf_jobs_src_connectors(
            src_engine_name,
            tgt_engine_name,
            src_env_name,
            tgt_env_name,
            sync_scope,
            None,
        )
        print_debug(" del_tmp_env = {}".format(del_tmp_env))
        print(" ")

        if del_tmp_env == 0:
            print(
                " Delete temporary environment {} created for OTF jobs".format(
                    self.src_dummy_conn_env
                )
            )
            dummy_conn_env_id = self.find_env_id(
                self.src_dummy_conn_env, tgt_engine_name, tgtapikey
            )
            self.del_env_byid(tgt_engine_name, dummy_conn_env_id, tgtapikey)

            print(" ")
            print(
                " Delete temporary application {} created for OTF jobs".format(
                    self.src_dummy_conn_app
                )
            )
            dummy_conn_app_id = self.find_app_id(
                self.src_dummy_conn_app, tgt_engine_name, tgtapikey
            )
            self.del_app_byid(tgt_engine_name, dummy_conn_app_id, tgtapikey)
            print(" ")

        # Sync Roles
        self.sync_roles(src_engine_name, tgt_engine_name)

        print(" ")
        # Sync Users
        self.sync_users(src_engine_name, tgt_engine_name)

        if self.delextra:
            self.delete_extra_objects()

        # Commeneted this functionality as it takes time. It can be tested separately
        # conn_type_list = ["database", "file", "mainframe-dataset"]
        # for conn_type in conn_type_list:
        #     self.test_connectors(tgt_engine_name, conn_type, sync_scope, None)

    def test_all_connectors(self):
        tgt_engine_name = self.mskengname
        sync_scope = "ENGINE"
        # srcapikey = self.get_auth_key(tgt_engine_name)
        # print_debug("srcapikey={}".format(srcapikey))
        conn_type_list = ["database", "file", "mainframe-dataset"]
        for conn_type in conn_type_list:
            self.test_connectors(
                tgt_engine_name, conn_type, sync_scope, None, None
            )

    def sync_job(self):
        src_engine_name = self.srcmskengname
        tgt_engine_name = self.tgtmskengname
        src_env_name = self.srcenvname
        tgt_env_name = self.tgtenvname
        src_job_name = self.srcjobname
        globalobjsync = self.globalobjsync
        sync_scope = "JOB"

        srcapikey = self.validate_msk_eng_connection(src_engine_name)
        tgtapikey = self.validate_msk_eng_connection(tgt_engine_name)

        self.process_sync_job(
            src_engine_name,
            tgt_engine_name,
            globalobjsync,
            src_env_name,
            tgt_env_name,
            src_job_name,
        )

        print(" Adjust Source Connector for OTF jobs(if any)")
        print_debug(
            " {},{},{},{}".format(
                src_engine_name, tgt_engine_name, src_env_name, tgt_env_name
            )
        )
        del_tmp_env = self.upd_all_otf_jobs_src_connectors(
            src_engine_name,
            tgt_engine_name,
            src_env_name,
            tgt_env_name,
            sync_scope,
            src_job_name,
        )
        print(" ")

        if del_tmp_env == 0:
            print(
                " Delete temporary environment {} created for OTF jobs".format(
                    self.src_dummy_conn_env
                )
            )
            dummy_conn_env_id = self.find_env_id(
                self.src_dummy_conn_env, tgt_engine_name, tgtapikey
            )
            self.del_env_byid(tgt_engine_name, dummy_conn_env_id, tgtapikey)

            print(" ")
            print(
                " Delete temporary application {} created for OTF jobs".format(
                    self.src_dummy_conn_app
                )
            )
            dummy_conn_app_id = self.find_app_id(
                self.src_dummy_conn_app, tgt_engine_name, tgtapikey
            )
            self.del_app_byid(tgt_engine_name, dummy_conn_app_id, tgtapikey)
            print(" ")

        # Commented as it takes time. It can be tested separately
        # conn_type_list = ["database", "file", "mainframe-dataset"]
        # for conn_type in conn_type_list:
        #     self.test_connectors(tgt_engine_name, conn_type, sync_scope, tgt_env_name)

    def delete_extra_objects(self):
        src_engine_name = self.srcmskengname
        tgt_engine_name = self.tgtmskengname
        srcapikey = self.get_auth_key(src_engine_name)
        print_debug("srcapikey={}".format(srcapikey))
        tgtapikey = self.get_auth_key(tgt_engine_name)
        print_debug("tgtapikey={}".format(tgtapikey))
        print(" Cleanup Extra Environments/Applications")
        if srcapikey is not None:
            src_env_name_list = []
            src_app_name_list = []

            syncobjapicall = "environments?page_number=1&page_size=999"
            syncobjapicallresponse = self.get_api_response(
                src_engine_name, srcapikey, syncobjapicall
            )
            for envobj in syncobjapicallresponse["responseList"]:
                src_env_name = envobj["environmentName"]
                src_env_name_list.append(src_env_name)

            syncobjapicall = "applications?page_number=1&page_size=999"
            syncobjapicallresponse = self.get_api_response(
                src_engine_name, srcapikey, syncobjapicall
            )
            for appobj in syncobjapicallresponse["responseList"]:
                src_app_name = appobj["applicationName"]
                src_app_name_list.append(src_app_name)

        if tgtapikey is not None:
            tgt_env_name_list = []
            tgt_app_name_list = []

            syncobjapicall = "environments?page_number=1&page_size=999"
            syncobjapicallresponse = self.get_api_response(
                tgt_engine_name, tgtapikey, syncobjapicall
            )
            for envobj in syncobjapicallresponse["responseList"]:
                tgt_env_name = envobj["environmentName"]
                tgt_env_name_list.append(tgt_env_name)

            syncobjapicall = "applications?page_number=1&page_size=999"
            syncobjapicallresponse = self.get_api_response(
                tgt_engine_name, tgtapikey, syncobjapicall
            )
            for appobj in syncobjapicallresponse["responseList"]:
                tgt_app_name = appobj["applicationName"]
                tgt_app_name_list.append(tgt_app_name)

        extra_env_name_list = list(
            (
                Counter(tgt_env_name_list) - Counter(src_env_name_list)
            ).elements()
        )
        extra_app_name_list = list(
            (
                Counter(tgt_app_name_list) - Counter(src_app_name_list)
            ).elements()
        )

        for env_name in extra_env_name_list:
            envid = self.find_env_id(env_name, tgt_engine_name, tgtapikey)
            delapicall = "environments/{}".format(envid)
            delapiresponse = self.del_api_response(
                tgt_engine_name, tgtapikey, delapicall
            )
            if delapiresponse is None:
                # May require To Handle dependents especially on-the-fly-masking interdependent env in future version
                print(" Unable to delete Environment {}.".format(env_name))
            else:
                print(" Environment {} deleted successfully.".format(env_name))
        print(" ")
        for app_name in extra_app_name_list:
            appid = self.find_app_id(app_name, tgt_engine_name, tgtapikey)
            delapicall = "applications/{}".format(appid)
            delapiresponse = self.del_api_response(
                tgt_engine_name, tgtapikey, delapicall
            )
            if delapiresponse is None:
                # May require To Handle dependents especially on-the-fly-masking interdependent env in future version
                print(" Unable to delete Application {}.".format(app_name))
            else:
                print(" Application {} deleted successfully.".format(app_name))
        print(" ")

    def upd_all_otf_jobs_src_connectors(
        self,
        src_engine_name,
        tgt_engine_name,
        src_env_name,
        tgt_env_name,
        sync_scope,
        jobname=None,
    ):
        delete_tmp_env = 0
        is_otf_job = 0
        srcapikey = self.get_auth_key(src_engine_name)
        print_debug("srcapikey={}".format(srcapikey))

        tgtapikey = self.get_auth_key(tgt_engine_name)
        print_debug("tgtapikey={}".format(tgtapikey))

        if sync_scope == "ENV" or sync_scope == "JOB":
            try:
                src_env_id = self.find_env_id(
                    src_env_name, src_engine_name, srcapikey
                )
            except:
                raise Exception(
                    "ERROR: Unable to pull source env id for environment {}. Please check engine and environment name".format(
                        src_env_name
                    )
                )

            try:
                tgt_env_id = self.find_env_id(
                    tgt_env_name, tgt_engine_name, tgtapikey
                )
            except:
                print(
                    "Error: Unable to pull target env id for environment {}. Please check engine and environment name".format(
                        tgt_env_name
                    )
                )

        if srcapikey is not None and tgtapikey is not None:
            syncobjapicall = "environments?page_number=1&page_size=999"
            syncobjapicallresponse = self.get_api_response(
                src_engine_name, srcapikey, syncobjapicall
            )
            print_debug(" ")
            print_debug(" ")
            print_debug(" ")
            for envobj in syncobjapicallresponse["responseList"]:
                print_debug(" ")
                print_debug(" ")
                print_debug("ENV")
                print_debug(
                    "++++++++++++++++++++++++++++++++++++++++++++++++++"
                )
                curr_env_id = envobj["environmentId"]
                curr_env_name = envobj["environmentName"]

                if sync_scope == "ENGINE":
                    src_env_id = curr_env_id
                    src_env_name = curr_env_name
                    tgt_env_name = curr_env_name

                print_debug(
                    "upd_all_otf_jobs_src_connectors - src_env_id={},curr_env_id={}".format(
                        src_env_id, curr_env_id
                    )
                )

                if curr_env_id == src_env_id:
                    print_debug(
                        "Before otf_src_job_mappings - jobname = {}".format(
                            jobname
                        )
                    )
                    otf_src_job_mappings = self.gen_otf_job_mappings(
                        src_engine_name, src_env_name, sync_scope, jobname
                    )
                    otf_tgt_job_mappings = self.gen_otf_job_mappings(
                        tgt_engine_name, tgt_env_name, sync_scope, jobname
                    )
                    print_debug(
                        " otf_src_job_mappings : {}".format(
                            otf_src_job_mappings
                        )
                    )
                    print_debug(
                        " otf_tgt_job_mappings : {}".format(
                            otf_tgt_job_mappings
                        )
                    )

                    # print(" ")
                    for i in otf_tgt_job_mappings:
                        is_otf_job = 1
                        upd_job_name = i["jobname"]
                        print(
                            " Updating Job {} on Environment {} for source connector".format(
                                upd_job_name, tgt_env_name
                            )
                        )
                        src_record = self.find_conn_details(
                            otf_src_job_mappings, upd_job_name, src_env_name
                        )
                        tgt_record = self.find_conn_details(
                            otf_tgt_job_mappings, upd_job_name, tgt_env_name
                        )

                        print_debug(" src:{}".format(src_record))
                        print_debug(" tgt:{}".format(tgt_record))

                        maskingJobId = tgt_record["maskingJobId"]
                        srcconnectorName = src_record["srcconnectorName"]
                        srcconnectorType = src_record["srcconnectorType"]
                        srcconnectorEnvName = src_record["srcconnectorEnvName"]
                        srcconnectorEnvappname = src_record[
                            "srcconnectorEnvappname"
                        ]
                        tgtenvironmentId = tgt_record["environmentId"]

                        print_debug(
                            " {},{},{},{},{},{},{}".format(
                                maskingJobId,
                                srcconnectorName,
                                srcconnectorType,
                                srcconnectorEnvName,
                                tgt_engine_name,
                                tgt_env_name,
                                srcconnectorEnvappname,
                            )
                        )
                        return_status = self.upd_job_connector(
                            maskingJobId,
                            srcconnectorName,
                            srcconnectorType,
                            srcconnectorEnvName,
                            tgt_engine_name,
                            tgt_env_name,
                            srcconnectorEnvappname,
                            tgtapikey,
                        )
                        if return_status == 1:
                            delete_tmp_env = 1
                    if sync_scope == "ENV":
                        if is_otf_job == 0:
                            delete_tmp_env = 1
                        elif is_otf_job == 1 and delete_tmp_env == 1:
                            delete_tmp_env = 1
                        elif is_otf_job == 1 and delete_tmp_env == 0:
                            delete_tmp_env = 0
                        break
        return delete_tmp_env

    def cr_dir(self, dirname):
        if not os.path.exists(dirname):
            try:
                os.makedirs(dirname)
            except:
                raise Exception(
                    "ERROR: Unable to create directory {}. Please check permissions".format(
                        dirname
                    )
                )

    def cr_backup_dirs(self):
        backup_dir = self.backup_dir
        x = datetime.datetime.now()
        x_dateformat = x.strftime("%m%d%Y_%H%M%S")

        bkp_main_dir = os.path.join(backup_dir, x_dateformat)
        self.cr_dir(bkp_main_dir)

        globalobjects_dir = os.path.join(bkp_main_dir, "globalobjects")
        self.cr_dir(globalobjects_dir)

        roleobjects_dir = os.path.join(bkp_main_dir, "roleobjects")
        self.cr_dir(roleobjects_dir)

        userobjects_dir = os.path.join(bkp_main_dir, "userobjects")
        self.cr_dir(userobjects_dir)

        environments_dir = os.path.join(bkp_main_dir, "environments")
        self.cr_dir(environments_dir)

        applications_dir = os.path.join(bkp_main_dir, "applications")
        self.cr_dir(applications_dir)

        mappings_dir = os.path.join(bkp_main_dir, "mappings")
        self.cr_dir(mappings_dir)

        print("Created directory structure for backups")

        return bkp_main_dir

    def bkp_syncable_objects(
        self, syncable_object_type, bkp_main_dir, srcapikey=None
    ):
        src_engine_name = self.mskengname
        if srcapikey is None:
            srcapikey = self.get_auth_key(src_engine_name)
        if srcapikey is not None:
            syncobjapicall = "syncable-objects?page_number=1&page_size=999&object_type={}".format(
                syncable_object_type
            )
            syncobjapicallresponse = self.get_api_response(
                src_engine_name, srcapikey, syncobjapicall
            )
            for syncable_object_type_elem in syncobjapicallresponse[
                "responseList"
            ]:
                syncable_object_type_def = []
                syncable_object_type_def.append(syncable_object_type_elem)
                srcapicall = "export"
                srcapiresponse = self.post_api_response1(
                    src_engine_name,
                    srcapikey,
                    srcapicall,
                    syncable_object_type_def,
                    port=80,
                )

                syncobj_bkp_dict = {
                    "syncable_object_type": syncable_object_type,
                    "srcapiresponse": srcapiresponse,
                }
                syncobj_bkp_file = "{}/globalobjects/backup_{}.dat".format(
                    bkp_main_dir, syncable_object_type
                )
                with open(syncobj_bkp_file, "wb") as fh:
                    pickle.dump(syncobj_bkp_dict, fh)
                print(
                    "Created backup of syncable_object_type {}".format(
                        syncable_object_type
                    )
                )
        else:
            #print("ERROR: Error connecting source engine {}".format(src_engine_name))
            raise Exception("ERROR: Error connecting source engine {}".format(src_engine_name))


    def bkp_roles(self, bkp_main_dir, srcapikey=None):
        role_mapping = {}
        src_engine_name = self.mskengname
        i = None
        if srcapikey is None:
            srcapikey = self.get_auth_key(src_engine_name)
        if srcapikey is not None:
            roleobjapicall = "roles?page_number=1&page_size=999"
            roleobjapicallresponse = self.get_api_response(
                src_engine_name, srcapikey, roleobjapicall
            )
            for role_rec in roleobjapicallresponse["responseList"]:
                i = 1
                roleId = role_rec["roleId"]
                roleName = role_rec["roleName"]
                role_mapping[roleId] = roleName
                roleNameNoSpace = roleName.replace(" ", "_")
                role_bkp_dict = {
                    "roleId": roleId,
                    "roleName": roleName,
                    "srcapiresponse": role_rec,
                }
                roleobj_bkp_file = "{}/roleobjects/backup_{}.dat".format(
                    bkp_main_dir, roleNameNoSpace
                )
                with open(roleobj_bkp_file, "wb") as fh:
                    pickle.dump(role_bkp_dict, fh)
                print("Created backup of role {}".format(roleName))

            role_mapping_file = "{}/mappings/backup_role_mapping.dat".format(
                bkp_main_dir
            )
            with open(role_mapping_file, "wb") as fh:
                pickle.dump(role_mapping, fh)
            print("Created mapping file for roles")
            print(" ")
        else:
            raise Exception("ERROR: Error connecting source engine {}".format(src_engine_name))

    def bkp_users(self, bkp_main_dir, srcapikey):
        src_engine_name = self.mskengname
        i = None
        if srcapikey is None:
            srcapikey = self.get_auth_key(src_engine_name)
        if srcapikey is not None:
            userobjapicall = "users?page_number=1&page_size=999"
            userobjapicallresponse = self.get_api_response(
                src_engine_name, srcapikey, userobjapicall
            )
            for user_rec in userobjapicallresponse["responseList"]:
                i = 1
                userId = user_rec["userId"]
                userName = user_rec["userName"]
                userNameNoSpace = userName.replace(" ", "_")
                user_rec["password"] = "Delphix-123"
                user_bkp_dict = {
                    "userId": userId,
                    "userName": userName,
                    "srcapiresponse": user_rec,
                }
                userobj_bkp_file = "{}/userobjects/backup_{}.dat".format(
                    bkp_main_dir, userNameNoSpace
                )
                with open(userobj_bkp_file, "wb") as fh:
                    pickle.dump(user_bkp_dict, fh)
                print("Created backup of user {}".format(userName))
        else:
            raise Exception("ERROR: Error connecting source engine {}".format(src_engine_name))

    def bkp_globalobj(self, bkp_main_dir, srcapikey=None):
        self.bkp_syncable_objects("GLOBAL_OBJECT", bkp_main_dir, srcapikey)
        self.bkp_syncable_objects("FILE_FORMAT", bkp_main_dir, srcapikey)
        self.bkp_syncable_objects("MOUNT_INFORMATION", bkp_main_dir, srcapikey)

    def bkp_otf_job_mappings(self, bkp_main_dir, srcapikey=None):
        src_engine_name = self.mskengname
        otf_job_mapping_list = []

        if srcapikey is None:
            srcapikey = self.get_auth_key(src_engine_name)
        print_debug("srcapikey={}".format(srcapikey))

        if srcapikey is not None:
            syncobjapicall = "environments?page_number=1&page_size=999"
            syncobjapicallresponse = self.get_api_response(
                src_engine_name, srcapikey, syncobjapicall
            )

            for envobj in syncobjapicallresponse["responseList"]:
                src_env_id = envobj["environmentId"]
                src_env_name = envobj["environmentName"]

                jobobjapicall = "masking-jobs?page_number=1&page_size=999&environment_id={}".format(
                    src_env_id
                )
                jobobjapicallresponse = self.get_api_response(
                    src_engine_name, srcapikey, jobobjapicall
                )

                for jobobj in jobobjapicallresponse["responseList"]:
                    otf_job_dict = {}
                    print_debug(
                        "{},{},{},{}".format(
                            jobobj["maskingJobId"],
                            jobobj["jobName"],
                            src_env_name,
                            jobobj["onTheFlyMasking"],
                        )
                    )
                    if jobobj["onTheFlyMasking"]:
                        otf_jobid = jobobj["maskingJobId"]
                        otf_jobname = jobobj["jobName"]
                        srcconnectorId = jobobj["onTheFlyMaskingSource"][
                            "connectorId"
                        ]
                        srcconnectortype = jobobj["onTheFlyMaskingSource"][
                            "connectorType"
                        ].lower()

                        srcconnectorName = self.find_conn_name_by_conn_id(
                            srcconnectorId,
                            srcconnectortype,
                            src_engine_name,
                            srcapikey,
                        )
                        srcconnectorenvId = self.find_env_id_by_conn_id(
                            srcconnectorId,
                            srcconnectortype,
                            src_engine_name,
                            srcapikey,
                        )
                        srcconnectorEnvname = self.find_env_name(
                            srcconnectorenvId, src_engine_name, srcapikey
                        )

                        print_debug(
                            "params = {},{},{},{}".format(
                                srcconnectorId,
                                srcconnectortype,
                                src_engine_name,
                                srcapikey,
                            )
                        )

                        otf_job_dict["otf_jobid"] = otf_jobid
                        otf_job_dict["otf_jobname"] = otf_jobname
                        otf_job_dict["srcconnectorId"] = srcconnectorId
                        otf_job_dict["srcconnectortype"] = srcconnectortype
                        otf_job_dict["srcconnectorName"] = srcconnectorName
                        otf_job_dict[
                            "srcconnectorEnvname"
                        ] = srcconnectorEnvname
                        otf_job_dict["src_env_id"] = src_env_id
                        otf_job_dict["src_env_name"] = src_env_name

                        otf_job_mapping_list.append(otf_job_dict)

            print_debug(" ")
            print_debug("JobMapping: {}".format(otf_job_mapping_list))
            otf_job_mapping_list_file = "{}/mappings/backup_{}.dat".format(
                bkp_main_dir, "otf_job_mapping"
            )
            with open(otf_job_mapping_list_file, "wb") as fh:
                pickle.dump(otf_job_mapping_list, fh)
            print("Created backup of otf_job_mapping")

        else:
            raise Exception("ERROR: Error connecting source engine {}".format(src_engine_name))

    def offline_backup_eng(self):
        env_mapping = {}
        src_engine_name = self.mskengname
        srcapikey = self.get_auth_key(src_engine_name)
        print_debug("srcapikey={}".format(srcapikey))
        if srcapikey is not None:
            bkp_main_dir = self.cr_backup_dirs()
            print(" ")
            self.bkp_globalobj(bkp_main_dir, srcapikey)
            print(" ")
            self.bkp_roles(bkp_main_dir, srcapikey)
            print(" ")
            self.bkp_users(bkp_main_dir, srcapikey)
            print(" ")
            self.bkp_otf_job_mappings(bkp_main_dir, srcapikey)
            print(" ")

            syncobjapicall = "syncable-objects?page_number=1&page_size=999&object_type=ENVIRONMENT"
            syncobjapicallresponse = self.get_api_response(
                src_engine_name, srcapikey, syncobjapicall
            )

            for envobj in syncobjapicallresponse["responseList"]:

                envdef = []
                envdef.append(envobj)
                src_env_id = envobj["objectIdentifier"]["id"]
                src_env_name = self.find_env_name(
                    src_env_id, src_engine_name, srcapikey
                )
                src_env_purpose = self.find_env_purpose(
                    src_env_id, src_engine_name, srcapikey
                )
                src_app_id = self.find_appid_of_envid(
                    src_env_id, src_engine_name, srcapikey
                )
                src_app_name = self.find_app_name(
                    src_app_id, src_engine_name, srcapikey
                )
                print_debug(
                    "Source Env name = {}, Source Env purpose = {}, Source App name = {}, Source Env Id = {}, Source App Id = {}".format(
                        src_env_name,
                        src_env_purpose,
                        src_app_name,
                        src_env_id,
                        src_app_id,
                    )
                )

                env_mapping[src_env_id] = src_env_name

                otf_job_mapping_list_file = "{}/mappings/backup_{}.dat".format(
                    bkp_main_dir, "otf_job_mapping"
                )
                with open(otf_job_mapping_list_file, "rb") as f1:
                    otf_job_mapping_dict = pickle.load(f1)

                # OTF env need to be handled separately due to possibility of DLPX-77471
                otf_env = 0
                for mapping in otf_job_mapping_dict:
                    if otf_env == 1:
                        break
                    else:
                        if mapping['src_env_name'] == src_env_name:
                            otf_env = 1
                            break
                otf_env = 0
                if otf_env == 1:
                    print("{} is OTF job environment so cannot backup at this time".format(src_env_name));
                else:
                    srcapicall = "export"
                    srcapiresponse = self.post_api_response1(
                        src_engine_name, srcapikey, srcapicall, envdef, port=80
                    )
                    env_bkp_dict = {
                        "src_app_id": src_app_id,
                        "src_app_name": src_app_name,
                        "src_env_id": src_env_id,
                        "src_env_name": src_env_name,
                        "src_env_purpose": src_env_purpose,
                        "srcapiresponse": srcapiresponse,
                    }
                    env_bkp_file = "{}/environments/backup_env_{}.dat".format(
                        bkp_main_dir, src_env_id
                    )
                    with open(env_bkp_file, "wb") as fh:
                        pickle.dump(env_bkp_dict, fh)
                    print("Created backup of environment {}".format(src_env_name))

            env_mapping_file = "{}/mappings/backup_env_mapping.dat".format(
                bkp_main_dir
            )
            with open(env_mapping_file, "wb") as fh:
                pickle.dump(env_mapping, fh)
            print("Created mapping file for environment")
            print(" ")

            print(
                "Created backup of masking engine at {}".format(bkp_main_dir)
            )
            print(" ")

        else:
            print("srcapikey={}".format(srcapikey))
            raise Exception("ERROR: Error connecting source engine {}".format(src_engine_name))

    def restore_globalobj(
        self,
        syncable_object_type,
        tgtapikey,
        tgt_engine_name,
        srcapiresponse,
    ):
        tgtapicall = "import?force_overwrite=true"
        tgtapiresponse = self.post_api_response1(
            tgt_engine_name, tgtapikey, tgtapicall, srcapiresponse, port=80
        )
        if tgtapiresponse is None:
            raise Exception("ERROR: Failed to restore Syncable Object {}".format(syncable_object_type))
        else:
            print(
                " Restored syncable_object_type: {}".format(
                    syncable_object_type
                )
            )

    def restore_roleobj(
        self,
        roleName,
        tgtapikey,
        tgt_engine_name,
        srcapiresponse,
        bkp_main_dir,
    ):
        tgtapicall = "roles"
        tgtapiresponse = self.post_api_response1(
            tgt_engine_name, tgtapikey, tgtapicall, srcapiresponse, port=80
        )
        if tgtapiresponse is None:
            print(" Failed to restore role {}".format(roleName))
            print_debug(" Failed role payload: {}".format(srcapiresponse))
        else:
            print(" Restored/Synced role: {}".format(roleName))

    def restore_userobj(
        self,
        userName,
        tgtapikey,
        tgt_engine_name,
        srcapiresponse,
        bkp_main_dir,
    ):
        tgtapicall = "users"
        tgtapiresponse = self.post_api_response1(
            tgt_engine_name, tgtapikey, tgtapicall, srcapiresponse, port=80
        )
        if tgtapiresponse is None:
            print(" Failed to restore user {}".format(userName))
            print_debug(" Failed user payload: {}".format(srcapiresponse))
        else:
            print_debug(" tgtapiresponse: {}".format(tgtapiresponse))
            if "errorMessage" in tgtapiresponse.keys():
                if "User already exists" in tgtapiresponse["errorMessage"]:
                    print_debug("User already exists")
                    userid = self.find_user_id(
                        userName, tgt_engine_name, tgtapikey
                    )
                    print_debug("userid = {}".format(userid))
                    updtgtapicall = "users/{}".format(userid)
                    tgtapiresponse = self.put_api_response(
                        tgt_engine_name,
                        tgtapikey,
                        updtgtapicall,
                        srcapiresponse,
                        port=80,
                    )
                    print_debug(
                        "put tgtapiresponse = {}".format(tgtapiresponse)
                    )
                    print(" Restored user: {}".format(userName))
                else:
                    print("Unable to create user: {}".format(userName))
            else:
                print(" Restored user: {}".format(userName))

    def sync_roles(self, src_engine_name, tgt_engine_name):
        self.add_debugspace()
        self.add_debugspace()
        i = None
        srcapikey = self.get_auth_key(src_engine_name)
        tgtapikey = self.get_auth_key(tgt_engine_name)
        if srcapikey is not None and tgtapikey is not None:
            roleobjapicall = "roles?page_number=1&page_size=999"
            roleobjapicallresponse = self.get_api_response(
                src_engine_name, srcapikey, roleobjapicall
            )
            for role_rec in roleobjapicallresponse["responseList"]:
                i = 1
                roleId = role_rec["roleId"]
                roleName = role_rec["roleName"]
                roleNameNoSpace = roleName.replace(" ", "_")
                print_debug("Role: {}".format(roleName))
                if roleName != "All Privileges":
                    print_debug(" Syncing role {}".format(roleName))
                    self.restore_roleobj(
                        roleName, tgtapikey, tgt_engine_name, role_rec, None
                    )
        else:
            print(
                " Error connecting source/target engine {}".format(
                    src_engine_name, tgt_engine_name
                )
            )
        self.add_debugspace()
        self.add_debugspace()

    def sync_users(self, src_engine_name, tgt_engine_name):
        i = None
        srcapikey = self.get_auth_key(src_engine_name)
        tgtapikey = self.get_auth_key(tgt_engine_name)
        if srcapikey is not None and tgtapikey is not None:
            userobjapicall = "users?page_number=1&page_size=999"
            userobjapicallresponse = self.get_api_response(
                src_engine_name, srcapikey, userobjapicall
            )
            for user_rec in userobjapicallresponse["responseList"]:
                i = 1
                userId = user_rec["userId"]
                userName = user_rec["userName"]
                userNameNoSpace = userName.replace(" ", "_")

                if userName != "admin" and userName != self.username:
                    isAdmin = user_rec["isAdmin"]
                    user_rec["password"] = "Delphix-123"
                    print_debug("User payload: {}".format(user_rec))
                else:
                    print(
                        " Username is : {}. Default admin OR self user are ignored in sync operation".format(
                            userName
                        )
                    )

                if userName != "admin" and userName != self.username:
                    print_debug("User {}".format(userName))
                    if isAdmin:
                        print_debug("User role : Admin")
                        self.restore_userobj(
                            userName,
                            tgtapikey,
                            tgt_engine_name,
                            user_rec,
                            None,
                        )
                    else:
                        if self.excludenonadmin == "N":
                            print_debug("User role : Non-Admin")
                            userRoleId = user_rec["nonAdminProperties"][
                                "roleId"
                            ]
                            userRoleName = self.find_role_name(
                                userRoleId, src_engine_name, srcapikey
                            )
                            tgtuserRoleId = self.find_role_id(
                                userRoleName, tgt_engine_name, tgtapikey
                            )
                            user_rec["nonAdminProperties"][
                                "roleId"
                            ] = tgtuserRoleId

                            tgtenvlist = []
                            envlist = user_rec["nonAdminProperties"][
                                "environmentIds"
                            ]
                            for envid in envlist:
                                envName = self.find_env_name(
                                    envid, src_engine_name, srcapikey
                                )
                                tgtenvid = self.find_env_id(
                                    envName, tgt_engine_name, tgtapikey
                                )
                                tgtenvlist.append(tgtenvid)
                            user_rec["nonAdminProperties"][
                                "environmentIds"
                            ] = tgtenvlist
                            self.restore_userobj(
                                userName,
                                tgtapikey,
                                tgt_engine_name,
                                user_rec,
                                None,
                            )
                        else:
                            print_debug(
                                "Excluding non-admin user {}".format(userName)
                            )
        else:
            print(" Error connecting source engine {}".format(src_engine_name))

    def offline_restore_eng(self):
        tgt_engine_name = self.mskengname
        tgtapikey = self.get_auth_key(tgt_engine_name)

        print_debug("tgtapikey={}".format(tgtapikey))
        if tgtapikey is not None:
            backup_dir = self.backup_dir
            print_debug("backup_dir: {}".format(backup_dir))

            globalobj_bkp_dict_file_fullpath = "{}/{}/{}".format(
                backup_dir, "globalobjects", "backup_GLOBAL_OBJECT.dat"
            )
            with open(globalobj_bkp_dict_file_fullpath, "rb") as f1:
                globalobj_bkp_dict = pickle.load(f1)
                syncable_object_type = globalobj_bkp_dict[
                    "syncable_object_type"
                ]
                srcapiresponse = globalobj_bkp_dict["srcapiresponse"]
                self.restore_globalobj(
                    syncable_object_type,
                    tgtapikey,
                    tgt_engine_name,
                    srcapiresponse,
                )
                print(" ")

            syncobj_bkp_dict_file_arr = os.listdir(
                "{}/globalobjects".format(backup_dir)
            )
            print_debug(
                "syncobj_bkp_dict_file_arr: {}".format(
                    syncobj_bkp_dict_file_arr
                )
            )
            for syncobj_bkp_dict_file in syncobj_bkp_dict_file_arr:
                if syncobj_bkp_dict_file != "backup_GLOBAL_OBJECT.dat":
                    # Global Object is already done so skipped. Looking for mount, fileformat etc
                    print_debug(
                        "syncobj_bkp_dict_file: {}".format(
                            syncobj_bkp_dict_file
                        )
                    )
                    syncobj_bkp_dict_file_fullpath = "{}/{}/{}".format(
                        backup_dir, "globalobjects", syncobj_bkp_dict_file
                    )
                    print_debug(
                        "syncobj_bkp_dict_file_fullpath: {}".format(
                            syncobj_bkp_dict_file_fullpath
                        )
                    )
                    with open(syncobj_bkp_dict_file_fullpath, "rb") as f1:
                        syncobj_bkp_dict = pickle.load(f1)
                    # print_debug(syncobj_bkp_dict) # It will be huge
                    syncable_object_type = syncobj_bkp_dict[
                        "syncable_object_type"
                    ]
                    srcapiresponse = syncobj_bkp_dict["srcapiresponse"]
                    self.restore_globalobj(
                        syncable_object_type,
                        tgtapikey,
                        tgt_engine_name,
                        srcapiresponse,
                    )
                    print(" ")

            # Create dummy app to handle on the fly masking job/env
            cr_app_response = self.create_application(
                tgt_engine_name, self.src_dummy_conn_app, tgtapikey
            )
            src_dummy_conn_app_id = cr_app_response["applicationId"]

            # Create dummy env to handle on the fly masking job/env
            cr_env_response = self.create_environment(
                tgt_engine_name,
                src_dummy_conn_app_id,
                self.src_dummy_conn_env,
                "MASK",
                tgtapikey,
            )
            src_dummy_conn_env_id = cr_env_response["environmentId"]

            print_debug(
                "Target Env Id = {}, Target App Id = {}".format(
                    src_dummy_conn_app_id, src_dummy_conn_env_id
                )
            )

            env_bkp_dict_file_arr = os.listdir(
                "{}/environments".format(backup_dir)
            )
            print_debug(
                "env_bkp_dict_file_arr: {}".format(env_bkp_dict_file_arr)
            )
            for env_bkp_dict_file in env_bkp_dict_file_arr:
                print_debug("env_bkp_dict_file: {}".format(env_bkp_dict_file))
                env_bkp_dict_file_fullpath = "{}/{}/{}".format(
                    backup_dir, "environments", env_bkp_dict_file
                )
                print_debug(
                    "env_bkp_dict_file_fullpath: {}".format(
                        env_bkp_dict_file_fullpath
                    )
                )
                with open(env_bkp_dict_file_fullpath, "rb") as f1:
                    env_bkp_dict = pickle.load(f1)
                print_debug(env_bkp_dict)

                src_app_id = env_bkp_dict["src_app_id"]
                src_app_name = env_bkp_dict["src_app_name"]
                src_env_id = env_bkp_dict["src_env_id"]
                src_env_name = env_bkp_dict["src_env_name"]
                src_env_purpose = env_bkp_dict["src_env_purpose"]
                srcapiresponse = env_bkp_dict["srcapiresponse"]

                if src_env_name == self.src_dummy_conn_env:
                    tgt_app_id = src_dummy_conn_app_id
                    tgt_env_id = src_dummy_conn_env_id
                else:
                    cr_app_response = self.create_application(
                        tgt_engine_name, src_app_name, tgtapikey
                    )
                    tgt_app_id = cr_app_response["applicationId"]

                    cr_env_response = self.create_environment(
                        tgt_engine_name,
                        tgt_app_id,
                        src_env_name,
                        src_env_purpose,
                        tgtapikey,
                    )
                    tgt_env_id = cr_env_response["environmentId"]

                print_debug(
                    "Target Env Id = {}, Target App Id = {}".format(
                        tgt_env_id, tgt_app_id
                    )
                )

                if src_env_name == self.src_dummy_conn_env:
                    # Handle eror : {"errorMessage":"Source environment cannot be the same as environment"}
                    tgtapicall = (
                        "import?force_overwrite=true&environment_id={}".format(
                            tgt_env_id
                        )
                    )
                else:
                    tgtapicall = "import?force_overwrite=true&environment_id={}&source_environment_id={}".format(
                        tgt_env_id, src_dummy_conn_env_id
                    )

                tgtapiresponse = self.post_api_response1(
                    tgt_engine_name,
                    tgtapikey,
                    tgtapicall,
                    srcapiresponse,
                    port=80,
                )
                if tgtapiresponse is None:
                    raise Exception("ERROR: Environment {} restore failed.".format(src_env_name))
                else:
                    print(
                        " Environment {} restored successfully. Please update password for connectors in this environment using GUI / API".format(
                            src_env_name
                        )
                    )

                print(
                    " Restored environment {}".format(
                        env_bkp_dict["src_env_name"]
                    )
                )
                print(" ")

            # Restore OTF_JOB_MAPPING
            otf_job_mapping_file = (
                "{}/mappings/backup_otf_job_mapping.dat".format(backup_dir)
            )
            with open(otf_job_mapping_file, "rb") as otf1:
                otf_job_mapping = pickle.load(otf1)
            print_debug(" Job Env Mapping :{}".format(otf_job_mapping))

            for otf_job in otf_job_mapping:
                print_debug(otf_job)
                jobname = otf_job["otf_jobname"]
                src_env_name = otf_job["src_env_name"]
                srcconn_name = otf_job["srcconnectorName"]
                conn_type = otf_job["srcconnectortype"]
                srcconnectorEnvname = otf_job["srcconnectorEnvname"]
                jobid = self.find_job_id(
                    jobname, src_env_name, tgt_engine_name, tgtapikey
                )
                print_debug(
                    "Before upd_job_connector : {},{},{},{},{}".format(
                        jobid,
                        srcconn_name,
                        conn_type,
                        srcconnectorEnvname,
                        tgt_engine_name,
                    )
                )
                self.upd_job_connector(
                    jobid,
                    srcconn_name,
                    conn_type,
                    srcconnectorEnvname,
                    tgt_engine_name,
                    srcconnectorEnvname,
                    None,
                    tgtapikey,
                )
            print(" ")

            # Restore Roles
            roleobj_bkp_dict_file_arr = os.listdir(
                "{}/roleobjects".format(backup_dir)
            )
            print_debug(
                "roleobj_bkp_dict_file_arr: {}".format(
                    roleobj_bkp_dict_file_arr
                )
            )
            for roleobj_bkp_dict_file in roleobj_bkp_dict_file_arr:
                if roleobj_bkp_dict_file != "backup_All_Privileges.dat":
                    # All Privileges Role is default out of the box
                    print_debug(
                        "roleobj_bkp_dict_file: {}".format(
                            roleobj_bkp_dict_file
                        )
                    )
                    roleobj_bkp_dict_file_fullpath = "{}/{}/{}".format(
                        backup_dir, "roleobjects", roleobj_bkp_dict_file
                    )
                    print_debug(
                        "roleobj_bkp_dict_file_fullpath: {}".format(
                            roleobj_bkp_dict_file_fullpath
                        )
                    )
                    with open(roleobj_bkp_dict_file_fullpath, "rb") as f1:
                        roleobj_bkp_dict = pickle.load(f1)
                    # print_debug(roleobj_bkp_dict) # It will be huge
                    roleId = roleobj_bkp_dict["roleId"]
                    roleName = roleobj_bkp_dict["roleName"]
                    srcapiresponse = roleobj_bkp_dict["srcapiresponse"]

                    self.restore_roleobj(
                        roleName,
                        tgtapikey,
                        tgt_engine_name,
                        srcapiresponse,
                        backup_dir,
                    )
                    # print(" Restored Role {}".format(roleName))
            print(" ")

            # Restore Users
            env_mapping_file = "{}/mappings/backup_env_mapping.dat".format(
                backup_dir
            )
            with open(env_mapping_file, "rb") as m1:
                env_mapping = pickle.load(m1)
            print_debug(" Source Env Mapping :{}".format(env_mapping))

            role_mapping_file = "{}/mappings/backup_role_mapping.dat".format(
                backup_dir
            )
            with open(role_mapping_file, "rb") as m1:
                role_mapping = pickle.load(m1)
            print_debug(" Source Role Mapping :{}".format(role_mapping))

            userobj_bkp_dict_file_arr = os.listdir(
                "{}/userobjects".format(backup_dir)
            )
            print_debug(
                "userobj_bkp_dict_file_arr: {}".format(
                    userobj_bkp_dict_file_arr
                )
            )
            for userobj_bkp_dict_file in userobj_bkp_dict_file_arr:
                if userobj_bkp_dict_file != "backup_admin.dat":
                    srcenvlist = []
                    tgtenvlist = []
                    # All Privileges user is default out of the box
                    print_debug(
                        "userobj_bkp_dict_file: {}".format(
                            userobj_bkp_dict_file
                        )
                    )
                    userobj_bkp_dict_file_fullpath = "{}/{}/{}".format(
                        backup_dir, "userobjects", userobj_bkp_dict_file
                    )
                    print_debug(
                        "userobj_bkp_dict_file_fullpath: {}".format(
                            userobj_bkp_dict_file_fullpath
                        )
                    )
                    with open(userobj_bkp_dict_file_fullpath, "rb") as f1:
                        userobj_bkp_dict = pickle.load(f1)

                    # print_debug(userobj_bkp_dict) # It will be huge

                    userId = userobj_bkp_dict["userId"]
                    userName = userobj_bkp_dict["userName"]
                    srcapiresponse = userobj_bkp_dict["srcapiresponse"]
                    print_debug(
                        " Is Admin:{}".format(srcapiresponse["isAdmin"])
                    )
                    if not srcapiresponse["isAdmin"]:
                        print_debug(
                            " srcnonAdminProperties = {}".format(
                                srcapiresponse["nonAdminProperties"]
                            )
                        )

                        if (
                            "roleId"
                            in srcapiresponse["nonAdminProperties"].keys()
                        ):
                            srcroleId = srcapiresponse["nonAdminProperties"][
                                "roleId"
                            ]
                            tmprolename = role_mapping[srcroleId]
                            tgtroleid = self.find_role_id(
                                tmprolename, tgt_engine_name, tgtapikey
                            )
                            srcapiresponse["nonAdminProperties"][
                                "roleId"
                            ] = tgtroleid
                            print_debug(
                                " Before srcroleId = {}, After tgtroleid = {}".format(
                                    srcroleId, tgtroleid
                                )
                            )

                        srcenvlist = srcapiresponse["nonAdminProperties"][
                            "environmentIds"
                        ]
                        print_debug(
                            " srcenvlist = {}".format(
                                srcapiresponse["nonAdminProperties"][
                                    "environmentIds"
                                ]
                            )
                        )
                        if len(srcenvlist) != 0:
                            for envid in srcenvlist:
                                tmpenvname = env_mapping[envid]
                                tgtenvid = self.find_env_id(
                                    tmpenvname, tgt_engine_name, tgtapikey
                                )
                                print_debug(" tgtenvid = {}".format(tgtenvid))
                                tgtenvlist.append(tgtenvid)
                        else:
                            tgtenvlist = []
                        print_debug(" tgtenvlist = {}".format(tgtenvlist))
                        print_debug(
                            " Before : srcenvlist = {}".format(
                                srcapiresponse["nonAdminProperties"][
                                    "environmentIds"
                                ]
                            )
                        )
                        srcapiresponse["nonAdminProperties"][
                            "environmentIds"
                        ] = tgtenvlist
                        print_debug(
                            " After  : srcenvlist = {}".format(
                                srcapiresponse["nonAdminProperties"][
                                    "environmentIds"
                                ]
                            )
                        )

                    self.restore_userobj(
                        userName,
                        tgtapikey,
                        tgt_engine_name,
                        srcapiresponse,
                        backup_dir,
                    )
                    # print(" Restored user {}".format(userName))
            print(" ")

            del_tmp_env = 0
            if del_tmp_env == 0:
                print(
                    " Delete temporary environment {} created for OTF jobs".format(
                        self.src_dummy_conn_env
                    )
                )
                dummy_conn_env_id = self.find_env_id(
                    self.src_dummy_conn_env, tgt_engine_name, tgtapikey
                )
                self.del_env_byid(
                    tgt_engine_name, dummy_conn_env_id, tgtapikey
                )

                print(" ")
                print(
                    " Delete temporary application {} created for OTF jobs".format(
                        self.src_dummy_conn_app
                    )
                )
                dummy_conn_app_id = self.find_app_id(
                    self.src_dummy_conn_app, tgt_engine_name, tgtapikey
                )
                self.del_app_byid(
                    tgt_engine_name, dummy_conn_app_id, tgtapikey
                )
                print(" ")

            sync_scope = "ENGINE"
            # Commented as it takes time. It can be tested separately
            # conn_type_list = ["database", "file", "mainframe-dataset"]
            # for conn_type in conn_type_list:
            #     self.test_connectors(tgt_engine_name, conn_type, sync_scope, None)

            print(" Restore Engine {} - complete".format(tgt_engine_name))
            print(" ")
        else:
            raise Exception("ERROR: Error connecting source engine {}".format(tgt_engine_name))


    def offline_restore_env(self):
        tgt_engine_name = self.mskengname
        tgtapikey = self.get_auth_key(tgt_engine_name)

        print_debug("tgtapikey={}".format(tgtapikey))
        if tgtapikey is not None:
            backup_dir = self.backup_dir
            print_debug("backup_dir: {}".format(backup_dir))

            globalobj_bkp_dict_file_fullpath = "{}/{}/{}".format(
                backup_dir, "globalobjects", "backup_GLOBAL_OBJECT.dat"
            )
            with open(globalobj_bkp_dict_file_fullpath, "rb") as f1:
                globalobj_bkp_dict = pickle.load(f1)
                syncable_object_type = globalobj_bkp_dict[
                    "syncable_object_type"
                ]
                srcapiresponse = globalobj_bkp_dict["srcapiresponse"]
                self.restore_globalobj(
                    syncable_object_type,
                    tgtapikey,
                    tgt_engine_name,
                    srcapiresponse,
                )
                print(" ")

            syncobj_bkp_dict_file_arr = os.listdir(
                "{}/globalobjects".format(backup_dir)
            )
            print_debug(
                "syncobj_bkp_dict_file_arr: {}".format(
                    syncobj_bkp_dict_file_arr
                )
            )
            for syncobj_bkp_dict_file in syncobj_bkp_dict_file_arr:
                if syncobj_bkp_dict_file != "backup_GLOBAL_OBJECT.dat":
                    # Global Object is already done so skipped. Looking for mount, fileformat etc
                    print_debug(
                        "syncobj_bkp_dict_file: {}".format(
                            syncobj_bkp_dict_file
                        )
                    )
                    syncobj_bkp_dict_file_fullpath = "{}/{}/{}".format(
                        backup_dir, "globalobjects", syncobj_bkp_dict_file
                    )
                    print_debug(
                        "syncobj_bkp_dict_file_fullpath: {}".format(
                            syncobj_bkp_dict_file_fullpath
                        )
                    )
                    with open(syncobj_bkp_dict_file_fullpath, "rb") as f1:
                        syncobj_bkp_dict = pickle.load(f1)
                    # print_debug(syncobj_bkp_dict) # It will be huge
                    syncable_object_type = syncobj_bkp_dict[
                        "syncable_object_type"
                    ]
                    srcapiresponse = syncobj_bkp_dict["srcapiresponse"]
                    self.restore_globalobj(
                        syncable_object_type,
                        tgtapikey,
                        tgt_engine_name,
                        srcapiresponse,
                    )
                    print(" ")

            # Create dummy app to handle on the fly masking job/env
            cr_app_response = self.create_application(
                tgt_engine_name, self.src_dummy_conn_app, tgtapikey
            )
            src_dummy_conn_app_id = cr_app_response["applicationId"]

            # Create dummy env to handle on the fly masking job/env
            cr_env_response = self.create_environment(
                tgt_engine_name,
                src_dummy_conn_app_id,
                self.src_dummy_conn_env,
                "MASK",
                tgtapikey,
            )
            src_dummy_conn_env_id = cr_env_response["environmentId"]

            print_debug(
                "Target Env Id = {}, Target App Id = {}".format(
                    src_dummy_conn_app_id, src_dummy_conn_env_id
                )
            )

            env_bkp_dict_file_arr = os.listdir(
                "{}/environments".format(backup_dir)
            )
            print_debug(
                "env_bkp_dict_file_arr: {}".format(env_bkp_dict_file_arr)
            )
            for env_bkp_dict_file in env_bkp_dict_file_arr:
                print_debug("env_bkp_dict_file: {}".format(env_bkp_dict_file))
                env_bkp_dict_file_fullpath = "{}/{}/{}".format(
                    backup_dir, "environments", env_bkp_dict_file
                )
                print_debug(
                    "env_bkp_dict_file_fullpath: {}".format(
                        env_bkp_dict_file_fullpath
                    )
                )
                with open(env_bkp_dict_file_fullpath, "rb") as f1:
                    env_bkp_dict = pickle.load(f1)
                print_debug(env_bkp_dict)

                src_app_id = env_bkp_dict["src_app_id"]
                src_app_name = env_bkp_dict["src_app_name"]
                src_env_id = env_bkp_dict["src_env_id"]
                src_env_name = env_bkp_dict["src_env_name"]
                src_env_purpose = env_bkp_dict["src_env_purpose"]
                srcapiresponse = env_bkp_dict["srcapiresponse"]

                if src_env_name == self.envname:
                    if src_env_name == self.src_dummy_conn_env:
                        tgt_app_id = src_dummy_conn_app_id
                        tgt_env_id = src_dummy_conn_env_id
                    else:
                        cr_app_response = self.create_application(
                            tgt_engine_name, src_app_name, tgtapikey
                        )
                        tgt_app_id = cr_app_response["applicationId"]

                        cr_env_response = self.create_environment(
                            tgt_engine_name,
                            tgt_app_id,
                            src_env_name,
                            src_env_purpose,
                            tgtapikey,
                        )
                        tgt_env_id = cr_env_response["environmentId"]

                    print_debug(
                        "Target Env Id = {}, Target App Id = {}".format(
                            tgt_env_id, tgt_app_id
                        )
                    )

                    if src_env_name == self.src_dummy_conn_env:
                        # Handle eror : {"errorMessage":"Source environment cannot be the same as environment"}
                        tgtapicall = "import?force_overwrite=true&environment_id={}".format(
                            tgt_env_id
                        )
                    else:
                        tgtapicall = "import?force_overwrite=true&environment_id={}&source_environment_id={}".format(
                            tgt_env_id, src_dummy_conn_env_id
                        )

                    tgtapiresponse = self.post_api_response1(
                        tgt_engine_name,
                        tgtapikey,
                        tgtapicall,
                        srcapiresponse,
                        port=80,
                    )
                    if tgtapiresponse is None:
                        raise Exception("ERROR: Environment {} restore failed.".format(src_env_name))

                    else:
                        print(
                            " Environment {} restored successfully. Please update password for connectors in this environment using GUI / API".format(
                                src_env_name
                            )
                        )

                    print(
                        " Restored environment {}".format(
                            env_bkp_dict["src_env_name"]
                        )
                    )
                    print(" ")

            # Restore OTF_JOB_MAPPING
            otf_job_mapping_file = (
                "{}/mappings/backup_otf_job_mapping.dat".format(backup_dir)
            )
            with open(otf_job_mapping_file, "rb") as otf1:
                otf_job_mapping = pickle.load(otf1)
            print_debug(" Job Env Mapping :{}".format(otf_job_mapping))

            for otf_job in otf_job_mapping:
                print_debug(otf_job)
                jobname = otf_job["otf_jobname"]
                src_env_name = otf_job["src_env_name"]
                srcconn_name = otf_job["srcconnectorName"]
                conn_type = otf_job["srcconnectortype"]
                srcconnectorEnvname = otf_job["srcconnectorEnvname"]

                if src_env_name == self.envname:
                    jobid = self.find_job_id(
                        jobname, src_env_name, tgt_engine_name, tgtapikey
                    )
                    print_debug(
                        "Before upd_job_connector : {},{},{},{},{}".format(
                            jobid,
                            srcconn_name,
                            conn_type,
                            srcconnectorEnvname,
                            tgt_engine_name,
                        )
                    )
                    self.upd_job_connector(
                        jobid,
                        srcconn_name,
                        conn_type,
                        srcconnectorEnvname,
                        tgt_engine_name,
                        srcconnectorEnvname,
                        None,
                        tgtapikey,
                    )
            print(" ")

            del_tmp_env = 0
            if del_tmp_env == 0:
                print(
                    " Delete temporary environment {} created for OTF jobs".format(
                        self.src_dummy_conn_env
                    )
                )
                dummy_conn_env_id = self.find_env_id(
                    self.src_dummy_conn_env, tgt_engine_name, tgtapikey
                )
                self.del_env_byid(
                    tgt_engine_name, dummy_conn_env_id, tgtapikey
                )

                print(" ")
                print(
                    " Delete temporary application {} created for OTF jobs".format(
                        self.src_dummy_conn_app
                    )
                )
                dummy_conn_app_id = self.find_app_id(
                    self.src_dummy_conn_app, tgt_engine_name, tgtapikey
                )
                self.del_app_byid(
                    tgt_engine_name, dummy_conn_app_id, tgtapikey
                )
                print(" ")

            sync_scope = "ENV"
            # Commented as it takes time. It can be tested separately
            # conn_type_list = ["database", "file", "mainframe-dataset"]
            # for conn_type in conn_type_list:
            #     self.test_connectors(tgt_engine_name, conn_type, sync_scope, self.envname)

            print(" Restore Environment {} - complete".format(tgt_engine_name))
            print(" ")
        else:
            print(" Error connecting source engine {}".format(tgt_engine_name))

    def cleanup_eng(self):
        src_engine_name = self.mskengname
        srcapikey = self.get_auth_key(src_engine_name)
        print_debug("srcapikey={}".format(srcapikey))
        i = 0
        if srcapikey is not None:

            mskobjapicall = "masking-jobs?page_number=1&page_size=999"
            mskobjapicallresponse = self.get_api_response(
                src_engine_name, srcapikey, mskobjapicall
            )
            for mskobj in mskobjapicallresponse["responseList"]:
                mskjobid = mskobj["maskingJobId"]
                mskjobname = mskobj["jobName"]

                delapicall = "masking-jobs/{}".format(mskjobid)
                delapiresponse = self.del_api_response(
                    src_engine_name, srcapikey, delapicall
                )
                if delapiresponse is None:
                    # To Handle dependents especially on-the-fly-masking interdependent env
                    print(
                        " Unable to delete masking job {} with jobid {}. Will be retried.".format(
                            mskjobname, mskjobid
                        )
                    )
                else:
                    print(
                        " Masking job {} with jobid {} deleted successfully.".format(
                            mskjobname, mskjobid
                        )
                    )
                    # print(" ")

            rerun_env_id_list = []
            syncobjapicall = "environments?page_number=1&page_size=999"
            syncobjapicallresponse = self.get_api_response(
                src_engine_name, srcapikey, syncobjapicall
            )

            for envobj in syncobjapicallresponse["responseList"]:
                src_env_id = envobj["environmentId"]
                src_env_name = envobj["environmentName"]
                print_debug("srcenv = {},{}".format(src_env_id, src_env_name))

                mskobjapicall = "masking-jobs?page_number=1&page_size=999&environment_id={}".format(
                    src_env_id
                )
                mskobjapicallresponse = self.get_api_response(
                    src_engine_name, srcapikey, mskobjapicall
                )
                for mskobj in mskobjapicallresponse["responseList"]:
                    mskjobid = mskobj["maskingJobId"]
                    mskjobname = mskobj["jobName"]

                    delapicall = "masking-jobs/{}".format(mskjobid)
                    delapiresponse = self.del_api_response(
                        src_engine_name, srcapikey, delapicall
                    )
                    if delapiresponse is None:
                        # To Handle dependents especially on-the-fly-masking interdependent env
                        print(
                            " Unable to delete masking job {} with jobid {}. Will be retried.".format(
                                mskjobname, mskjobid
                            )
                        )
                    else:
                        print(
                            " Masking job {} with jobid {} deleted successfully.".format(
                                mskjobname, mskjobid
                            )
                        )
                        # print(" ")

                delapicall = "environments/{}".format(src_env_id)
                delapiresponse = self.del_api_response(
                    src_engine_name, srcapikey, delapicall
                )
                if delapiresponse is None:
                    # To Handle dependents especially on-the-fly-masking interdependent env
                    print(
                        " Unable to delete Environment {}. Added to retry queue.".format(
                            src_env_name
                        )
                    )
                    rerun_env_id_list.append(
                        {
                            "src_env_id": src_env_id,
                            "src_env_name": src_env_name,
                        }
                    )
                else:
                    print(
                        " Environment {} deleted successfully.".format(
                            src_env_name
                        )
                    )
                    # print(" ")

            if len(rerun_env_id_list) != 0:
                for rerun_env_id_rec in rerun_env_id_list:
                    src_env_id = rerun_env_id_rec["src_env_id"]
                    src_env_name = rerun_env_id_rec["src_env_name"]
                    delapicall = "environments/{}".format(src_env_id)
                    delapiresponse = self.del_api_response(
                        src_engine_name, srcapikey, delapicall
                    )
                    if delapiresponse is None:
                        print(
                            " Unable to delete environment {}.".format(
                                src_env_name
                            )
                        )
                        i = 1
                    else:
                        print(
                            " Environment {} deleted successfully.".format(
                                src_env_name
                            )
                        )
                    # print(" ")

            syncobjapicall = "applications?page_number=1&page_size=999"
            syncobjapicallresponse = self.get_api_response(
                src_engine_name, srcapikey, syncobjapicall
            )
            for appobj in syncobjapicallresponse["responseList"]:
                src_app_id = appobj["applicationId"]
                src_app_name = appobj["applicationName"]
                print_debug("srcapp = {},{}".format(src_app_id, src_app_name))

                delapicall = "applications/{}".format(src_app_id)
                delapiresponse = self.del_api_response(
                    src_engine_name, srcapikey, delapicall
                )
                if delapiresponse is None:
                    print(
                        " Unable to delete Application {}.".format(
                            src_app_name
                        )
                    )
                    i = 1
                else:
                    print(
                        " Application {} deleted successfully.".format(
                            src_app_name
                        )
                    )
                    # print(" ")

            print(" ")
            print(" Deleting users")
            self.del_users(src_engine_name, srcapikey)
            print(" ")
            print(" Deleting roles")
            self.del_roles(src_engine_name, srcapikey)
            print(" ")
            print(" Deleting Domains")
            self.del_domains(src_engine_name, srcapikey)
            print(" ")
            print(" Deleting Algorithms")
            self.del_algorithms(src_engine_name, srcapikey)
            print(" ")
            print(" Deleting Fileformats")
            self.del_fileFormats(src_engine_name, srcapikey)
            print(" Deleting Algorithms")
            self.del_algorithms(src_engine_name, srcapikey)
            print(" ")

            if i == 0:
                print(" Engine {} cleanup completed.".format(src_engine_name))
            else:
                print(" Engine {} cleanup failed.".format(src_engine_name))
            print(" ")

        else:
            raise Exception("ERROR: Error connecting source engine {}".format(src_engine_name))

    def duplicate_connectors(self):
        src_engine_name = self.mskengname
        srcapikey = self.get_auth_key(src_engine_name)
        print_debug("srcapikey={}".format(srcapikey))
        i = 0
        if srcapikey is not None:

            apicall = "environments?page_number=1&page_size=999"
            connectorlist = []
            duplicateconnlist = []

            envresponse = self.get_api_response(src_engine_name, srcapikey, apicall)
            if envresponse is None:
                raise Exception("ERROR: Unable to pull environment details of engine {}".format(src_engine_name))
            else:
                for env in envresponse['responseList']:
                    for conntype in ["database-connectors","file-connectors","mainframe-dataset-connectors"]:
                        apicall = "{}?page_number=1&page_size=999&environment_id={}".format(conntype,
                            env['environmentId'])
                        connresponse = self.get_api_response(src_engine_name, srcapikey, apicall)
                        if connresponse is None:
                            raise Exception("ERROR: Unable to pull connector details for connector type : {}".format(conntype))
                        else:
                            for connector in connresponse['responseList']:
                                if conntype == "database-connectors":
                                    connidparam = "databaseConnectorId"
                                elif conntype == "file-connectors":
                                    connidparam = "fileConnectorId"
                                elif conntype == "mainframe-dataset-connectors":
                                    connidparam = "mainframeDatasetConnectorId"

                                connectordict = {'environmentId': env['environmentId'],
                                                 'environmentName': env['environmentName'],
                                                 'connectorId': connector[connidparam],
                                                 'connectorName': connector['connectorName'],
                                                 'connectorType': conntype}
                                connectorlist.append(connectordict)

                duplicate_conn_names = (
                [connectorName for connectorName, count in Counter(x['connectorName'] for x in connectorlist).items() if
                 count > 1])
                for rec in connectorlist:
                    if rec['connectorName'] in duplicate_conn_names:
                        duplicateconnlist.append(rec)
                sortedduplicateconnlist = sorted(duplicateconnlist, key=lambda k: k['connectorName'])

                if len(sortedduplicateconnlist) > 0:
                    if self.action == "list":
                        print("{},{},{},{},{}".format("connectorId", "connectorName", "environmentId", "environmenNamed",
                                                      "connectorType"))

                prevname = None
                newname = None
                for conn in sortedduplicateconnlist:
                    conntype =  conn['connectorType']
                    if conntype == "database-connectors":
                        connidparam = "databaseConnectorId"
                    elif conntype == "file-connectors":
                        connidparam = "fileConnectorId"
                    elif conntype == "mainframe-dataset-connectors":
                        connidparam = "mainframeDatasetConnectorId"

                    newname = conn['connectorName']
                    if newname != prevname:
                        if i != 0:
                            if self.action == "list":
                                print(" ")
                        else:
                            i = i + 1
                    prevname = newname
                    if self.action == "list":
                        print(
                            "{},{},{},{},{}".format(conn['connectorId'], conn['connectorName'], conn['environmentId'],
                                                 conn['environmentName'],conn['connectorType']))

                    if self.action == "resolve":
                        apicall = "{}/{}".format(conn['connectorType'],conn['connectorId'])
                        connresponse = self.get_api_response(src_engine_name, srcapikey, apicall)
                        if connresponse is None:
                            raise Exception("ERROR: Unable to pull details for connector {} - {} - {}".format(
                                conn['connectorType'],conn['connectorId'],conn['connectorName']))
                        else:
                            originalConnectorName = connresponse['connectorName']
                            renamedConnectorName = "{}{}{}".format(connresponse['connectorName'],
                                                                              connresponse[connidparam],
                                                                              connresponse['environmentId'])
                            connresponse['connectorName'] = renamedConnectorName
                            putconnresponse = self.put_api_response(src_engine_name, srcapikey, apicall, connresponse)
                            if putconnresponse is None:
                                print(
                                    "ERROR: Renaming connector with Id:{} and Name:{} to {} failed.".format(connresponse[connidparam],
                                                                                     originalConnectorName,
                                                                                     connresponse['connectorName']))
                            else:
                                print(
                                    "Success: Renamed connector with Id:{} and Name:{} to {}".format(connresponse[connidparam],
                                                                                      originalConnectorName,
                                                                                      connresponse['connectorName']))
            # if i == 0:
            if i == 0:
                print("No duplicate connector names found.")
            print(" ")

        else:
            raise Exception("ERROR: Error connecting masking engine {}".format(src_engine_name))

    def gen_otf_job_mappings(
        self, src_engine_name, src_env_name, sync_scope=None, jobname=None
    ):
        otf_job_mapping_list = []

        srcapikey = self.get_auth_key(src_engine_name)
        print_debug("srcapikey={}".format(srcapikey))
        if srcapikey is not None:

            envid = self.find_env_id(src_env_name, src_engine_name, srcapikey)
            syncobjapicall = "environments?page_number=1&page_size=999"
            syncobjapicallresponse = self.get_api_response(
                src_engine_name, srcapikey, syncobjapicall
            )

            for envobj in syncobjapicallresponse["responseList"]:
                # otf_job_dict = {}
                src_env_id = envobj["environmentId"]
                src_env_name = envobj["environmentName"]
                src_env_purpose = envobj["purpose"]

                if envid == src_env_id:
                    jobobjapicall = "masking-jobs?page_number=1&page_size=999&environment_id={}".format(
                        src_env_id
                    )
                    jobobjapicallresponse = self.get_api_response(
                        src_engine_name, srcapikey, jobobjapicall
                    )

                    for jobobj in jobobjapicallresponse["responseList"]:
                        print_debug(" ")
                        otf_job_dict = {}
                        print_debug(
                            "{},{},{},{}".format(
                                jobobj["maskingJobId"],
                                jobobj["jobName"],
                                src_env_name,
                                jobobj["onTheFlyMasking"],
                            )
                        )
                        if jobobj["onTheFlyMasking"]:
                            otf_jobid = jobobj["maskingJobId"]
                            otf_jobname = jobobj["jobName"]
                            if sync_scope != "JOB":
                                jobname = otf_jobname
                            print_debug(
                                "otf_jobname={},jobname={},sync_scope={}".format(
                                    otf_jobname, jobname, sync_scope
                                )
                            )
                            if otf_jobname == jobname:
                                print_debug(
                                    "Matched : otf_jobname={},jobname={},sync_scope={}".format(
                                        otf_jobname, jobname, sync_scope
                                    )
                                )
                                # otf_job_dict = {}

                                srcconnectorId = jobobj[
                                    "onTheFlyMaskingSource"
                                ]["connectorId"]
                                srcconnectortype = jobobj[
                                    "onTheFlyMaskingSource"
                                ]["connectorType"]
                                srcconnectorenvId = (
                                    self.find_env_id_by_conn_id(
                                        srcconnectorId,
                                        srcconnectortype,
                                        src_engine_name,
                                        srcapikey,
                                    )
                                )
                                srcconnectorName = (
                                    self.find_conn_name_by_conn_id(
                                        srcconnectorId,
                                        srcconnectortype,
                                        src_engine_name,
                                        srcapikey,
                                    )
                                )
                                srcconnectorEnvname = self.find_env_name(
                                    srcconnectorenvId,
                                    src_engine_name,
                                    srcapikey,
                                )
                                srcconnectorEnvappid = (
                                    self.find_appid_of_envid(
                                        srcconnectorenvId,
                                        src_engine_name,
                                        srcapikey,
                                    )
                                )
                                srcconnectorEnvappname = self.find_app_name(
                                    srcconnectorEnvappid,
                                    src_engine_name,
                                    srcapikey,
                                )

                                otf_job_details_dict = {}
                                otf_job_details_dict["maskingJobId"] = jobobj[
                                    "maskingJobId"
                                ]
                                otf_job_details_dict[
                                    "environmentId"
                                ] = src_env_id
                                otf_job_details_dict["envname"] = src_env_name
                                # otf_job_details_dict['purpose'] = src_env_purpose
                                otf_job_details_dict[
                                    "srcconnectorId"
                                ] = srcconnectorId
                                otf_job_details_dict[
                                    "srcconnectorName"
                                ] = srcconnectorName
                                otf_job_details_dict[
                                    "srcconnectorType"
                                ] = jobobj["onTheFlyMaskingSource"][
                                    "connectorType"
                                ].lower()
                                otf_job_details_dict[
                                    "srcconnectorEnvId"
                                ] = srcconnectorenvId
                                otf_job_details_dict[
                                    "srcconnectorEnvName"
                                ] = srcconnectorEnvname
                                otf_job_details_dict[
                                    "srcconnectorEnvappname"
                                ] = srcconnectorEnvappname
                                print_debug(
                                    "otf_job_details_dict = {}".format(
                                        otf_job_details_dict
                                    )
                                )
                                print_debug(" ")

                                otf_jobenv_mapping_dict = {}
                                otf_jobenv_mapping_dict[
                                    src_env_name
                                ] = otf_job_details_dict
                                print_debug(
                                    "otf_jobenv_mapping_dict = {}".format(
                                        otf_jobenv_mapping_dict
                                    )
                                )
                                print_debug(" ")

                                otf_job_dict[otf_jobid] = otf_jobname
                                otf_job_dict[
                                    otf_jobname
                                ] = otf_jobenv_mapping_dict
                                otf_job_dict["jobname"] = otf_jobname

                                print_debug(
                                    "otf_job_dict = {}".format(otf_job_dict)
                                )
                                print_debug(" ")

                                otf_job_mapping_list.append(otf_job_dict)
                                print_debug(
                                    "otf_job_mapping_list = {}".format(
                                        otf_job_mapping_list
                                    )
                                )
                                print_debug(
                                    "=========================================================="
                                )
                                print_debug(" ")

            print_debug(" ")
            print_debug(" ")
            print_debug("JobMapping: {}".format(otf_job_mapping_list))
            return otf_job_mapping_list
        else:
            print(" Error connecting source engine {}".format(src_engine_name))

    def create_application(self, engine_name, app_name, apikey=None):
        if apikey is None:
            apikey = self.get_auth_key(engine_name)
        apicall = "applications"
        payload = {"applicationName": "{}".format(app_name)}
        apiresponse = self.post_api_response1(
            engine_name, apikey, apicall, payload, port=80
        )
        if "errorMessage" in apiresponse.keys():
            print(" Application {} already exists".format(app_name))
            app_id = self.find_app_id(app_name, engine_name, apikey)
            apiresponse = {"applicationId": "{}".format(app_id)}
        else:
            print(" Application {} Created Successfully".format(app_name))
        return apiresponse

    def create_environment(
        self, engine_name, app_id, env_name, env_purpose, apikey=None
    ):
        if apikey is None:
            apikey = self.get_auth_key(engine_name)
        apicall = "environments"
        payload = {
            "environmentName": "{}".format(env_name),
            "applicationId": "{}".format(app_id),
            "purpose": "{}".format(env_purpose),
        }
        apiresponse = self.post_api_response1(
            engine_name, apikey, apicall, payload, port=80
        )
        if "errorMessage" in apiresponse.keys():
            print(" Environment {} already exists".format(env_name))
            env_id = self.find_env_id(env_name, engine_name, apikey)
            apiresponse = {"environmentId": "{}".format(env_id)}
        else:
            print(" Environment {} Created Successfully".format(env_name))
        return apiresponse

    def find_job_id(self, jobname, paramenvname, engine_name, apikey=None):
        if apikey is None:
            apikey = self.get_auth_key(engine_name)
        i = 0
        if apikey is not None:
            apicall = "environments?page_number=1&page_size=999"
            envlist_response = self.get_api_response(
                engine_name, apikey, apicall
            )
            for envname in envlist_response["responseList"]:
                if envname["environmentName"] == paramenvname:
                    jobapicall = "masking-jobs?page_number=1&page_size=999&environment_id={}".format(
                        envname["environmentId"]
                    )
                    joblist_response = self.get_api_response(
                        engine_name, apikey, jobapicall
                    )
                    joblist_responselist = joblist_response["responseList"]
                    for joblist in joblist_responselist:
                        if joblist["jobName"] == jobname:
                            i = 1
                            print_debug(
                                "Job ID = {}".format(joblist["maskingJobId"])
                            )
                            return joblist["maskingJobId"]
            if i == 0:
                print(
                    "Error unable to find job id for jobname {} and environment {}".format(
                        jobname, paramenvname
                    )
                )
        else:
            print("Error connecting engine {}".format(engine_name))

    def find_env_id(self, paramenvname, engine_name, apikey=None):
        if apikey is None:
            apikey = self.get_auth_key(engine_name)
        i = 0
        if apikey is not None:
            apicall = "environments?page_number=1&page_size=999"
            envlist_response = self.get_api_response(
                engine_name, apikey, apicall
            )
            for envname in envlist_response["responseList"]:
                if envname["environmentName"] == paramenvname:
                    i = 1
                    # print_debug("env id = {}".format(envname['environmentId']))
                    return envname["environmentId"]
                    break

            if i == 0:
                print(
                    " Unable to find env id for environment {}".format(
                        paramenvname
                    )
                )
                return None
        else:
            print("Error connecting engine {}".format(engine_name))

    def find_env_name(self, paramenvnid, engine_name, apikey=None):
        if apikey is None:
            apikey = self.get_auth_key(engine_name)
        if apikey is not None:
            apicall = "environments/{}".format(paramenvnid)
            envlist_response = self.get_api_response(
                engine_name, apikey, apicall
            )
            return envlist_response["environmentName"]
        else:
            print("Error connecting engine {}".format(engine_name))

    def find_role_name(self, paramroleid, engine_name, apikey=None):
        if apikey is None:
            apikey = self.get_auth_key(engine_name)
        if apikey is not None:
            apicall = "roles/{}".format(paramroleid)
            rolelist_response = self.get_api_response(
                engine_name, apikey, apicall
            )
            return rolelist_response["roleName"]
        else:
            print("Error connecting engine {}".format(engine_name))

    def find_role_id(self, paramrolename, engine_name, apikey=None):
        if apikey is None:
            apikey = self.get_auth_key(engine_name)
        i = 0
        if apikey is not None:
            apicall = "roles?page_number=1&page_size=999"
            rolelist_response = self.get_api_response(
                engine_name, apikey, apicall
            )
            for rolerec in rolelist_response["responseList"]:
                if rolerec["roleName"] == paramrolename:
                    i = 1
                    # print_debug("env id = {}".format(envname['environmentId']))
                    return rolerec["roleId"]
            if i == 0:
                print(
                    " Error: unable to find role id for role {}".format(
                        paramrolename
                    )
                )
                return None
        else:
            print("Error connecting engine {}".format(engine_name))

    def find_env_purpose(self, paramenvnid, engine_name, apikey=None):
        if apikey is None:
            apikey = self.get_auth_key(engine_name)
        if apikey is not None:
            apicall = "environments/{}".format(paramenvnid)
            envlist_response = self.get_api_response(
                engine_name, apikey, apicall
            )
            return envlist_response["purpose"]
        else:
            print("Error connecting engine {}".format(engine_name))

    def find_appid_of_envid(self, paramenvnid, engine_name, apikey=None):
        if apikey is None:
            apikey = self.get_auth_key(engine_name)
        i = 0
        if apikey is not None:
            apicall = "environments/{}".format(paramenvnid)
            envlist_response = self.get_api_response(
                engine_name, apikey, apicall
            )
            return envlist_response["applicationId"]
        else:
            print("Error connecting engine {}".format(engine_name))

    def find_app_id(self, paramappname, engine_name, apikey=None):
        if apikey is None:
            apikey = self.get_auth_key(engine_name)
        i = 0
        if apikey is not None:
            apicall = "applications?page_number=1&page_size=999"
            applist_response = self.get_api_response(
                engine_name, apikey, apicall
            )
            for appname in applist_response["responseList"]:
                if appname["applicationName"] == paramappname:
                    i = 1
                    # print_debug("app id = {}".format(appname['applicationId']))
                    return appname["applicationId"]
            if i == 0:
                print(
                    "Error unable to find app id for application {}".format(
                        paramappname
                    )
                )
        else:
            print("Error connecting engine {}".format(engine_name))

    def find_app_name(self, paramappid, engine_name, apikey=None):
        if apikey is None:
            apikey = self.get_auth_key(engine_name)
        i = 0
        if apikey is not None:
            apicall = "applications/{}".format(paramappid)
            applist_response = self.get_api_response(
                engine_name, apikey, apicall
            )
            try:
                return applist_response["applicationName"]
            except:
                return None
        else:
            print("Error connecting engine {}".format(engine_name))

    def find_env_id_by_conn_id(
        self, paramconnid, paramconntype, engine_name, srcapikey
    ):
        print_debug(
            "Parameters: {},{},{},{}".format(
                paramconnid, paramconntype, engine_name, srcapikey
            )
        )
        apikey = srcapikey
        i = 0
        if apikey is not None:
            if paramconntype.lower() == "database":
                apicall = "database-connectors/{}".format(paramconnid)
            elif paramconntype.lower() == "file":
                apicall = "file-connectors/{}".format(paramconnid)
            elif paramconntype.lower() == "vsam":
                apicall = "mainframe-dataset-connectors/{}".format(paramconnid)

            try:
                conn_response = self.get_api_response(
                    engine_name, apikey, apicall
                )
                env_id = conn_response["environmentId"]
                return env_id

            except Exception as e:
                print(
                    " Error unable to find env id for connector id {}".format(
                        paramconnid
                    )
                )
                return None
        else:
            print("Error connecting engine {}".format(engine_name))

    def find_conn_name_by_conn_id(
        self, paramconnid, paramconntype, engine_name, srcapikey
    ):
        apikey = srcapikey
        i = 0
        if apikey is not None:
            if paramconntype.lower() == "database":
                apicall = "database-connectors/{}".format(paramconnid)
            elif paramconntype.lower() == "file":
                apicall = "file-connectors/{}".format(paramconnid)
            elif paramconntype.lower() == "vsam":
                apicall = "mainframe-dataset-connectors/{}".format(paramconnid)

            try:
                conn_response = self.get_api_response(
                    engine_name, apikey, apicall
                )
                conn_name = conn_response["connectorName"]
                return conn_name

            except Exception as e:
                print(
                    " Error unable to find connector Name for connector id {}".format(
                        paramconnid
                    )
                )
                return None
        else:
            print("Error connecting engine {}".format(engine_name))

    def find_connid_by_name(
        self, paramconnname, paramconntype, engine_name, srcapikey, src_env_id
    ):
        print_debug(" ")
        print_debug(" ")
        print_debug(" ")
        print_debug("find_connid_by_name")
        print_debug("===================")
        # print(inspect.stack()[0][3])
        # print(inspect.stack()[1][3])
        apikey = srcapikey
        print_debug(
            "{},{},{},{}".format(
                paramconnname, paramconntype, engine_name, src_env_id
            )
        )
        print_debug("apikey={}".format(apikey))
        try:
            if paramconntype.lower() == "vsam":
                syncobjapicall = "{}-connectors?page_number=1&page_size=999&environment_id={}".format(
                    "mainframe-dataset", src_env_id
                )
            else:
                syncobjapicall = "{}-connectors?page_number=1&page_size=999&environment_id={}".format(
                    paramconntype, src_env_id
                )

            print_debug("syncobjapicall: {}".format(syncobjapicall))
            syncobjapicallresponse = self.get_api_response(
                engine_name, apikey, syncobjapicall
            )
            # print("syncobjapicallresponse: {}".format(syncobjapicallresponse))
            print_debug(syncobjapicallresponse)
            for connobj in syncobjapicallresponse["responseList"]:
                print_debug(connobj)
                if paramconntype.lower() == "vsam":
                    conn_id = connobj[
                        "{}ConnectorId".format("mainframe-dataset")
                    ]
                else:
                    conn_id = connobj["{}ConnectorId".format(paramconntype)]

                conn_name = connobj["connectorName"]
                print_debug(
                    "conn_name:{},paramconnname:{},conn_id:{}".format(
                        conn_name, paramconnname, conn_id
                    )
                )
                if conn_name == paramconnname:
                    print_debug(
                        "conn_id:{},paramconnname:{}".format(
                            conn_id, paramconnname
                        )
                    )
                    return conn_id

        except Exception as e:
            print("   Unable to pull {} connector data".format(paramconntype))
            print_debug(e)
        # print(" ")

    def find_user_id(self, paramusername, engine_name, apikey=None):
        if apikey is None:
            apikey = self.get_auth_key(engine_name)
        if apikey is not None:
            apicall = "users"
            userlist_response = self.get_api_response(
                engine_name, apikey, apicall
            )
            print_debug("userlist_response = {}".format(userlist_response))
            for user_rec in userlist_response["responseList"]:
                print_debug("user_rec = {}".format(user_rec))
                if user_rec["userName"] == paramusername:
                    return user_rec["userId"]
        else:
            print("Error connecting engine {}".format(engine_name))
            return 0

    def find_engine_version(self, engine_name, apikey=None):
        if apikey is None:
            apikey = self.get_auth_key(engine_name)
        if apikey is not None:
            apicall = "system-information"
            systeminfo_response = self.get_api_response(
                engine_name, apikey, apicall
            )
            print_debug("systeminfo_response = {}".format(systeminfo_response))
            return systeminfo_response["version"]
        else:
            print("Error connecting engine {}".format(engine_name))
            return 0

    def chk_eng_queue_enabled(self, engine_version):
        version_arr = engine_version.split(".")
        major_digit = int(version_arr[0])
        minor_digit = int(version_arr[1])
        micro_digit = int(version_arr[2])
        patch_digit = int(version_arr[3])
        print_debug(
            "Major = {}, Minor = {}, Micro = {}, Patch = {}".format(
                major_digit, minor_digit, micro_digit, patch_digit
            )
        )
        queue_enabled_engine = False
        if major_digit < 6:
            queue_enabled_engine = False
        elif major_digit == 6:
            queue_enabled_engine = True if micro_digit > 4 else False
        elif major_digit > 6:
            queue_enabled_engine = True

        return queue_enabled_engine

    def upd_job_connector(
        self,
        jobid,
        srcconn_name,
        conn_type,
        src_env_name,
        engine_name,
        tgt_env_name,
        srcconnectorEnvappname,
        apikey=None,
    ):
        return_status = 1
        if apikey is None:
            apikey = self.get_auth_key(engine_name)
        print_debug("src_env_name = {}".format(src_env_name))
        print_debug("tgt_env_name = {}".format(tgt_env_name))
        src_env_id = self.find_env_id(src_env_name, engine_name, apikey)
        if src_env_id is None:
            print(
                " Source environment {} does not exists on masking engine {}. Please sync {} env for OTF jobs".format(
                    src_env_name, engine_name, src_env_name
                )
            )
            print(
                " Please sync environment {} first for syncing OTF jobs".format(
                    src_env_name
                )
            )
            print(" ")
            return_status = 1
            return return_status

            # Below can create ap and env but connector will still be missing.
            # cr_app_response = self.create_application(engine_name,srcconnectorEnvappname)
            # src_conn_app_id = cr_app_response['applicationId']
            # cr_env_response = self.create_environment(engine_name,src_conn_app_id,src_env_name)
            # src_env_id = cr_env_response['environmentId']

        print_debug("src_env_id on target engine = {}".format(src_env_id))

        newconnid = self.find_connid_by_name(
            srcconn_name, conn_type, engine_name, apikey, src_env_id
        )
        print_debug("newconnid = {}".format(newconnid))
        if apikey is not None:
            apicall = "masking-jobs/{}?page_number=1&page_size=999".format(
                jobid
            )
            print_debug("apicall: {}".format(apicall))
            mskjob_response = self.get_api_response(
                engine_name, apikey, apicall
            )
            print_debug("mskjob_response: {}".format(mskjob_response))
            mskjob_response["onTheFlyMaskingSource"]["connectorId"] = newconnid
            print_debug("mskjob_response: {}".format(mskjob_response))

            res = self.put_api_response(
                engine_name, apikey, apicall, mskjob_response, port=80
            )
            print_debug("res: {}".format(res))
            print(" Job {} - update complete.".format(jobid))
            return_status = 0
            return return_status
        else:
            return_status = 1
            return return_status

    def del_env_byid(self, engine_name, env_id, apikey=None):
        if apikey is None:
            apikey = self.get_auth_key(engine_name)
        env_name = self.find_env_name(env_id, engine_name, apikey)
        delapicall = "environments/{}".format(env_id)
        delapiresponse = self.del_api_response(engine_name, apikey, delapicall)
        if delapiresponse is None:
            print(" Unable to delete environment {}".format(env_name))
        else:
            print(" Environment {} deleted successfully.".format(env_name))

    def del_app_byid(self, engine_name, app_id, apikey=None):
        if apikey is None:
            apikey = self.get_auth_key(engine_name)
        app_name = self.find_app_name(app_id, engine_name, apikey)
        delapicall = "applications/{}".format(app_id)
        delapiresponse = self.del_api_response(engine_name, apikey, delapicall)
        if delapiresponse is None:
            print(" Unable to delete application {}".format(app_name))
        else:
            print(" Application {} deleted successfully.".format(app_name))

    def del_users(self, src_engine_name, srcapikey):
        if srcapikey is None:
            self.get_auth_key(src_engine_name)
        syncobjapicall = "users?page_number=1&page_size=999"
        syncobjapicallresponse = self.get_api_response(
            src_engine_name, srcapikey, syncobjapicall
        )
        for userobj in syncobjapicallresponse["responseList"]:
            src_user_id = userobj["userId"]
            src_user_name = userobj["userName"]
            print_debug("User = {},{}".format(src_user_id, src_user_name))
            if src_user_name != "admin" and src_user_name != self.username:
                print_debug("User Admin = {}".format(userobj["isAdmin"]))
                if userobj["isAdmin"]:
                    if self.includeadmin:
                        print_debug(
                            "self.includeadmin = {}".format(self.includeadmin)
                        )
                        print_debug(
                            "Converting {} to non-admin".format(src_user_name)
                        )
                        userobj["isAdmin"] = False
                        userobj["nonAdminProperties"] = {
                            "roleId": 1,
                            "environmentIds": [],
                        }
                        updapicall = "users/{}".format(src_user_id)
                        updapiresponse = self.put_api_response(
                            src_engine_name, srcapikey, updapicall, userobj
                        )
                        print_debug(
                            "put updapiresponse = {}".format(updapiresponse)
                        )

                        delapicall = "users/{}".format(src_user_id)
                        delapiresponse = self.del_api_response(
                            src_engine_name, srcapikey, delapicall
                        )
                        if delapiresponse is None:
                            print(
                                " Unable to delete User {}.".format(
                                    src_user_name
                                )
                            )
                            i = 1
                        else:
                            print(
                                " User {} deleted successfully.".format(
                                    src_user_name
                                )
                            )
                            # print(" ")
                    else:
                        print_debug(
                            "self.includeadmin = {}".format(self.includeadmin)
                        )
                        print_debug(
                            "Skipping admin user {} as per delete adminflag: {}".format(
                                src_user_name, self.includeadmin
                            )
                        )
                else:
                    delapicall = "users/{}".format(src_user_id)
                    delapiresponse = self.del_api_response(
                        src_engine_name, srcapikey, delapicall
                    )
                    if delapiresponse is None:
                        print(
                            " Unable to delete User {}.".format(src_user_name)
                        )
                        i = 1
                    else:
                        print(
                            " User {} deleted successfully.".format(
                                src_user_name
                            )
                        )
                        # print(" ")
            else:
                print_debug(
                    "UserId = {} , Username = {} - Default user admin OR self user executing cleanup cannot be deleted.".format(
                        src_user_id, src_user_name
                    )
                )

    def del_fileFormats(self, src_engine_name, srcapikey):
        if srcapikey is None:
            self.get_auth_key(src_engine_name)
        syncobjapicall = "file-formats?page_number=1&page_size=999"
        syncobjapicallresponse = self.get_api_response(
            src_engine_name, srcapikey, syncobjapicall
        )
        for fileFormatobj in syncobjapicallresponse["responseList"]:
            src_fileFormat_id = fileFormatobj["fileFormatId"]
            src_fileFormat_name = fileFormatobj["fileFormatName"]
            print_debug(
                "fileFormat = {},{}".format(
                    src_fileFormat_id, src_fileFormat_name
                )
            )
            if src_fileFormat_name != "admin":
                delapicall = "file-formats/{}".format(src_fileFormat_id)
                delapiresponse = self.del_api_response(
                    src_engine_name, srcapikey, delapicall
                )
                if delapiresponse is None:
                    print(
                        " Unable to delete fileFormat {}.".format(
                            src_fileFormat_name
                        )
                    )
                    i = 1
                else:
                    print(
                        " fileFormat {} deleted successfully.".format(
                            src_fileFormat_name
                        )
                    )
                    # print(" ")

        syncobjapicall = (
            "mainframe-dataset-formats?page_number=1&page_size=999"
        )
        syncobjapicallresponse = self.get_api_response(
            src_engine_name, srcapikey, syncobjapicall
        )
        for fileFormatobj in syncobjapicallresponse["responseList"]:
            src_fileFormat_id = fileFormatobj["mainframeDatasetFormatId"]
            src_fileFormat_name = fileFormatobj["mainframeDatasetFormatName"]
            print_debug(
                "fileFormat = {},{}".format(
                    src_fileFormat_id, src_fileFormat_name
                )
            )
            if src_fileFormat_name != "admin":
                delapicall = "mainframe-dataset-formats/{}".format(
                    src_fileFormat_id
                )
                delapiresponse = self.del_api_response(
                    src_engine_name, srcapikey, delapicall
                )
                if delapiresponse is None:
                    print(
                        " Unable to delete fileFormat {}.".format(
                            src_fileFormat_name
                        )
                    )
                    i = 1
                else:
                    print(
                        " fileFormat {} deleted successfully.".format(
                            src_fileFormat_name
                        )
                    )
                    # print(" ")

    def del_roles(self, src_engine_name, srcapikey):
        if srcapikey is None:
            self.get_auth_key(src_engine_name)
        syncobjapicall = "roles?page_number=1&page_size=999"
        syncobjapicallresponse = self.get_api_response(
            src_engine_name, srcapikey, syncobjapicall
        )
        for roleobj in syncobjapicallresponse["responseList"]:
            src_role_id = roleobj["roleId"]
            src_role_name = roleobj["roleName"]
            print_debug("Role = {},{}".format(src_role_id, src_role_name))
            if src_role_name != "All Privileges":
                delapicall = "roles/{}".format(src_role_id)
                delapiresponse = self.del_api_response(
                    src_engine_name, srcapikey, delapicall
                )
                if delapiresponse is None:
                    print(" Unable to delete Role {}.".format(src_role_name))
                    i = 1
                else:
                    print(
                        " Role {} deleted successfully.".format(src_role_name)
                    )
                    # print(" ")

    def del_domains(self, src_engine_name, srcapikey):
        if srcapikey is None:
            self.get_auth_key(src_engine_name)
        syncobjapicall = "domains?page_number=1&page_size=999"
        syncobjapicallresponse = self.get_api_response(
            src_engine_name, srcapikey, syncobjapicall
        )
        for domainobj in syncobjapicallresponse["responseList"]:
            if "createdBy" in domainobj.keys():
                src_domain_name = domainobj["domainName"]
                print_debug("Domain = {}".format(src_domain_name))
                print_debug("domainobj = {}".format(domainobj))
                if src_domain_name not in self.systemdomainlist:
                    delapicall = "domains/{}".format(src_domain_name)
                    delapiresponse = self.del_api_response(
                        src_engine_name, srcapikey, delapicall
                    )
                    if delapiresponse is None:
                        print(
                            " Unable to delete Domain {}.".format(
                                src_domain_name
                            )
                        )
                        i = 1
                    else:
                        print(
                            " Domain {} deleted successfully.".format(
                                src_domain_name
                            )
                        )
                        # print(" ")

    def del_algorithms(self, src_engine_name, srcapikey):
        if srcapikey is None:
            self.get_auth_key(src_engine_name)
        syncobjapicall = "algorithms?page_number=1&page_size=999"
        syncobjapicallresponse = self.get_api_response(
            src_engine_name, srcapikey, syncobjapicall
        )
        for algorithmobj in syncobjapicallresponse["responseList"]:
            if "createdBy" in algorithmobj.keys():
                src_algorithm_name = algorithmobj["algorithmName"]
                print_debug("Algorithm = {}".format(src_algorithm_name))
                print_debug("algorithmobj = {}".format(algorithmobj))
                if src_algorithm_name not in self.systemalgorithmlist:
                    delapicall = "algorithms/{}".format(src_algorithm_name)
                    delapiresponse = self.del_api_response(
                        src_engine_name, srcapikey, delapicall
                    )
                    if delapiresponse is None:
                        print(
                            " Unable to delete Algorithm {}.".format(
                                src_algorithm_name
                            )
                        )
                        i = 1
                    else:
                        print(
                            " Algorithm {} deleted successfully.".format(
                                src_algorithm_name
                            )
                        )
                        # print(" ")

    def find_conn_details(self, otf_job_mappings, job_name, env_name):
        # print(" ")
        print_debug("{} {}".format(job_name, env_name))
        for jobrec in otf_job_mappings:
            if job_name in jobrec.keys():
                env_rec = jobrec[job_name]
                if env_name in env_rec.keys():
                    print_debug("Match found")
                    detail_rec = env_rec[env_name]
                    return detail_rec

    def test_connectors(
        self, engine_name, conn_type, test_scope, envname=None, apikey=None
    ):
        print(" TEST CONNECTORS ON MASKING ENGINE: {}".format(engine_name))
        if apikey is None:
            apikey = self.get_auth_key(engine_name)
        print_debug("apikey={}".format(apikey))
        if test_scope == "ENV":
            envid = self.find_env_id(envname, engine_name, apikey)

        if apikey is not None:
            print(" Test {} Connectors:".format(conn_type))
            try:
                syncobjapicall = (
                    "{}-connectors?page_number=1&page_size=999".format(
                        conn_type
                    )
                )
                syncobjapicallresponse = self.get_api_response(
                    engine_name, apikey, syncobjapicall
                )
                print_debug(syncobjapicallresponse)
                for connobj in syncobjapicallresponse["responseList"]:
                    print_debug(connobj)
                    conn_envid = connobj["environmentId"]
                    if test_scope == "ENGINE":
                        tgt_envid = conn_envid
                    elif test_scope == "ENV":
                        tgt_envid = envid

                    if conn_envid == tgt_envid:
                        conn_id = connobj["{}ConnectorId".format(conn_type)]
                        conn_name = connobj["connectorName"]
                        conn_envname = self.find_env_name(
                            conn_envid, engine_name, apikey
                        )

                        testapicall = "{}-connectors/{}/test".format(
                            conn_type, conn_id
                        )
                        payload = connobj
                        print_debug("payload={}".format(payload))

                        try:
                            apiresponse = self.post_api_response(
                                engine_name,
                                apikey,
                                testapicall,
                                payload,
                                port=80,
                            )
                            print_debug("apiresponse= {}".format(apiresponse))
                            if (
                                apiresponse["response"]
                                == "Connection Succeeded"
                            ):
                                print(
                                    " Env : {:35}, Connector : {:25} --> {}.".format(
                                        conn_envname,
                                        conn_name,
                                        apiresponse["response"],
                                    )
                                )
                            else:
                                print(
                                    " Env : {:35}, Connector : {:25} --> {}.".format(
                                        conn_envname,
                                        conn_name,
                                        "Connection Failed",
                                    )
                                )
                        except Exception as e:
                            print(
                                " Env : {:35}, Connector : {:25} --> {}.".format(
                                    conn_envname,
                                    conn_name,
                                    "Unable to test Connection",
                                )
                            )
                            print_debug(e)
            except Exception as e:
                print_debug(e)
                raise Exception("ERROR: Unable to pull {} connector data".format(conn_type))
            print(" ")

        else:
            print(" Error connecting source engine {}".format(engine_name))

    def extract_start_or_submit_datetime(self, latestexecid):
        returndate = ""
        if latestexecid["status"] == "QUEUED":
            returndate = latestexecid["submitTime"]
        elif latestexecid["status"] == "RUNNING":
            returndate = latestexecid["startTime"]
        elif latestexecid["status"] == "CANCELLED":
            returndate = (
                latestexecid["startTime"]
                if "startTime" in latestexecid.keys()
                else latestexecid["submitTime"]
            )
        else:
            returndate = latestexecid["endTime"]
        return returndate

    # @track
    def list_eng_usage(self):
        if not self.mock:
            # Run this if its not mock run for demos
            self.pull_jobexeclist()
        engine_list = self.create_dictobj(self.enginelistfile)
        jobexec_list = self.create_dictobj(self.jobexeclistfile)
        enginecpu_list = self.create_dictobj(self.enginecpulistfile)

        self.add_debugspace()
        print_debug("enginecpu_list:{}".format(enginecpu_list))
        self.add_debugspace()

        engine_list = self.create_dictobj(self.enginelistfile)
        print_debug("engine_list:{}".format(engine_list))

        enginelist = []
        for engine in engine_list:
            engine_list_dict = collections.OrderedDict(
                ip_address=engine["ip_address"],
                totalmb=int(engine["totalgb"]) * 1024,
                systemmb=int(engine["systemgb"]) * 1024,
            )
            enginelist.append(engine_list_dict)
        print_debug("engine_list:{}".format(engine_list))
        print_debug("enginelist:{}".format(enginelist))
        engine_list = enginelist

        engine_pool_for_job = engine_list
        print_debug("engine_pool_for_job:{}".format(engine_pool_for_job))

        bannertext = banner()

        if self.config.verbose or self.config.debug:
            print(
                (
                    colored(
                        bannertext.banner_sl_box(
                            text="Available Engine Pool:"
                        ),
                        "yellow",
                    )
                )
            )
            print(
                "{0:>1}{1:<35}{2:>20}{3:>20}".format(
                    "", "Engine Name", "Total Memory(MB)", "System Memory(MB)"
                )
            )
            for ind in engine_list:
                print(
                    "{0:>1}{1:<35}{2:>20}{3:>20}".format(
                        " ", ind["ip_address"], ind["totalmb"], ind["systemmb"]
                    )
                )

        if self.config.verbose or self.config.debug:
            print(
                (
                    colored(
                        bannertext.banner_sl_box(text="CPU Usage:"), "yellow"
                    )
                )
            )
            print(
                "{0:>1}{1:<35}{2:>20}".format("", "Engine Name", "Used CPU(%)")
            )
            for ind in enginecpu_list:
                print(
                    "{0:>1}{1:<35}{2:>20}".format(
                        " ", ind["ip_address"], ind["cpu"]
                    )
                )

        print_debug("jobexec_list = {}".format(jobexec_list))
        engineusage = self.group_job_mem_usage(
            "ip_address", "jobmaxmemory", jobexec_list
        )
        print_debug("engineusage = {}".format(engineusage))
        if engineusage is None:
            print_debug("Creating empty list.")
            engineusage_od = []
            temporddict = {}
            for ind in engine_list:
                temporddict = collections.OrderedDict(
                    ip_address=ind["ip_address"], totalusedmemory=0
                )
                engineusage_od.append(temporddict)
            print_debug(engineusage_od)
        else:
            engineusage_od = []
            temporddict = {}
            for row in engineusage:
                engineusage_od.append(collections.OrderedDict(row))

            # Add empty list for remaining engines [ not in jobexeclist ]
            print_debug("engine_list = \n{}".format(engine_list))
            for ind in engine_list:
                i = 0
                for ind1 in engineusage:
                    if ind["ip_address"] == ind1["ip_address"]:
                        i = 1
                if i == 0:
                    temporddict = collections.OrderedDict(
                        ip_address=ind["ip_address"], totalusedmemory=0
                    )
                    engineusage_od.append(temporddict)

        print_debug("engineusage_od = {}".format(engineusage_od))

        if self.config.verbose or self.config.debug:
            print(
                (
                    colored(
                        bannertext.banner_sl_box(text="Memory Usage:"),
                        "yellow",
                    )
                )
            )
            print(
                "{0:>1}{1:<35}{2:>20}".format(
                    "", "Engine Name", "Used Memory(MB)"
                )
            )
            for ind in engineusage_od:
                print(
                    "{0:>1}{1:<35}{2:>20}".format(
                        " ", ind["ip_address"], ind["totalusedmemory"]
                    )
                )

        if self.config.verbose or self.config.debug:
            print(
                (
                    colored(
                        bannertext.banner_sl_box(text="Engine Current Usage:"),
                        "yellow",
                    )
                )
            )
            print(
                "{0:>1}{1:<35}{2:>20}{3:>20}".format(
                    "", "Engine Name", "Used Memory(MB)", "Used CPU(%)"
                )
            )

        if len(enginecpu_list) != 0:
            engineusage = self.join_dict(
                engineusage_od, enginecpu_list, "ip_address", "cpu"
            )
            self.add_debugspace()
            print_debug("engineusage:{}".format(engineusage))
            self.add_debugspace()
            if self.config.verbose or self.config.debug:
                for ind in engineusage:
                    print(
                        "{0:>1}{1:<35}{2:>20}{3:>20}".format(
                            " ",
                            ind["ip_address"],
                            ind["totalusedmemory"],
                            ind["cpu"],
                        )
                    )
        else:
            print("Handle this situation")

        self.add_debugspace()
        print_debug("enginecpu_list:{}".format(enginecpu_list))
        self.add_debugspace()
        print_debug("engineusage_od = \n{}\n".format(engineusage_od))
        print_debug("enginecpu_list = \n{}\n".format(enginecpu_list))
        print_debug("engineusage = \n{}\n".format(engineusage))
