import json
import os
import re
import time
import requests

from csv import DictReader
from datetime import datetime, timedelta
from statistics import mean
from mskpkg.banner import banner

import mskpkg.globals as globals
from mskpkg.DxLogging import print_debug
from mskpkg.veconfig import loadveconfig
import subprocess
import threading


class virtualization:
    def __init__(self, config, **kwargs):
        # self.scriptname = os.path.basename(__file__)
        # self.scriptdir = os.path.dirname(os.path.abspath(__file__))
        self.enginelistfile = globals.enginelistfile
        self.enginecpulistfile = globals.enginecpulistfile
        self.config = config

        if "config_file_path" in kwargs.keys():
            self.config_file_path = kwargs["config_file_path"]
        if "outputdir" in kwargs.keys():
            self.outputdir = kwargs["outputdir"]
        if "protocol" in kwargs.keys():
            self.protocol = kwargs["protocol"]
        if "dxtoolkit_path" in kwargs.keys():
            self.dxtoolkit_path = kwargs["dxtoolkit_path"]

        self.headers = {"Content-Type": "application/json"}

        try:
            os.stat(self.outputdir)
        except:
            os.mkdir(self.outputdir)
            if self.config.debug:
                print_debug("Created directory {}".format(self.outputdir))

    def create_api_session(self, ip_address, port=80):
        protocol = self.protocol
        print_debug("protocol = {}, port ={}".format(protocol, port))
        if protocol == "https":
            port = 443
        print_debug("New protocol = {}, port ={}".format(protocol, port))
        apiversion = {
            "type": "APISession",
            "version": {"type": "APIVersion", "major": 1, "minor": 9, "micro": 3},
        }
        api_url_base = "{}://{}:{}/resources/json/delphix/".format(
            protocol, ip_address, port
        )
        print_debug("api_url_base = {}".format(api_url_base))
        headers = self.headers
        api_url = "{0}session".format(api_url_base)
        try:
            response = requests.post(
                api_url, headers=headers, json=apiversion, verify=False
            )
            if response.status_code == 200:
                data = json.loads(response.content.decode("utf-8"))
                if data["status"] == "OK":
                    cookies = {"JSESSIONID": response.cookies["JSESSIONID"]}
                    return cookies
                else:
                    print_debug(
                        "Engine {} : Error connecting engine".format(ip_address)
                    )
                    return None
            else:
                print_debug("Engine {} : Error connecting engine".format(ip_address))
                return None
        except:
            print_debug("Engine {} : Error connecting engine".format(ip_address))
            return None

    def login_api_session(self, ip_address, cookies, apicall, payload, port=80):
        protocol = self.protocol
        print_debug("protocol = {}, port ={}".format(protocol, port))
        if protocol == "https":
            port = 443
        print_debug("New protocol = {}, port ={}".format(protocol, port))
        api_url_base = "{}://{}:{}/resources/json/delphix/".format(
            protocol, ip_address, port
        )
        headers = self.headers
        api_url = "{0}{1}".format(api_url_base, apicall)
        try:
            response = requests.post(
                api_url, cookies=cookies, headers=headers, json=payload, verify=False
            )
            if response.status_code == 200:
                data = json.loads(response.content.decode("utf-8"))
                if data["status"] == "OK":
                    cookies = {"JSESSIONID": response.cookies["JSESSIONID"]}
                    return cookies
                else:
                    print_debug("Engine {} : Error logging engine".format(ip_address))
                    return None
            else:
                print_debug("Engine {} : Error logging engine".format(ip_address))
                return None
        except:
            print_debug("Engine {} : Error logging engine".format(ip_address))
            return None

    def get_api_response(self, ip_address, cookies, apicall, port=80):
        protocol = self.protocol
        print_debug("protocol = {}, port ={}".format(protocol, port))
        if protocol == "https":
            port = 443
        print_debug("New protocol = {}, port ={}".format(protocol, port))
        api_url_base = "{}://{}:{}/resources/json/delphix/".format(
            protocol, ip_address, port
        )
        headers = self.headers
        api_url = "{0}{1}".format(api_url_base, apicall)
        try:
            response = requests.get(
                api_url, cookies=cookies, headers=headers, verify=False
            )
            if response.status_code == 200:
                data = json.loads(response.content.decode("utf-8"))
                if data["status"] == "OK":
                    return data["result"]
                else:
                    print_debug("Engine {} : Error fetching data".format(ip_address))
                    return None
            else:
                print_debug("Engine {} : Error fetching data".format(ip_address))
                return None
        except:
            print_debug("Engine {} : Error fetching data".format(ip_address))
            return None

    def post_api_response(self, ip_address, cookies, apicall, payload, mrthod, port=80):
        protocol = self.protocol
        print_debug("protocol = {}, port ={}".format(protocol, port))
        if protocol == "https":
            port = 443
        print_debug("New protocol = {}, port ={}".format(protocol, port))
        api_url_base = "{}://{}:{}/resources/json/delphix/".format(
            protocol, ip_address, port
        )
        headers = self.headers
        api_url = "{0}{1}".format(api_url_base, apicall)
        try:
            response = requests.post(
                api_url, cookies=cookies, headers=headers, json=payload, verify=False
            )
            if response.status_code == 200:
                data = json.loads(response.content.decode("utf-8"))
                if data["status"] == "OK":
                    return data["result"]
                else:
                    print_debug("Engine {} : Error fetching data".format(ip_address))
                    return None
            else:
                print_debug("Engine {} : Error fetching data".format(ip_address))
                return None
        except:
            print_debug("Engine {} : Error fetching data".format(ip_address))
            return None

    def create_dictobj(self, filename):
        with open(filename, "r") as read_obj:
            reader = DictReader(read_obj)
            dictobj = list(reader)
            return dictobj

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

    def get_cpu_for_engine(self, config_file_path, engine, dxtoolkit_eng_ip):
        dxtoolkit_path = self.dxtoolkit_path
        try:
            print_debug(
                "dxtoolkit_path: {}, config_file_path:{}, engine: {}".format(
                    dxtoolkit_path + "/dx_get_cpu", config_file_path, engine
                )
            )
            out = subprocess.Popen(
                [
                    dxtoolkit_path + "/dx_get_cpu",
                    "-d",
                    engine,
                    "-configfile",
                    config_file_path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            stdout, stderr = out.communicate()
            print_debug("stdout: {} ,stderr: {}".format(stdout, stderr))

            r1 = re.findall(r"Can't connect", stdout.decode("utf-8"))
            if not r1:
                rs = stdout.split()[0]
                rs = rs.decode("utf-8")
                print_debug("rs: {}".format(rs))
                if rs == "OK:" or "CRITICAL:" or "WARNING:":
                    cpuvalue = stdout.split()[-1:][0]
                    cpuvalue = cpuvalue.decode("utf-8")
                    f = open(self.enginecpulistfile, "a")
                    f.write("{},{}\n".format(dxtoolkit_eng_ip, cpuvalue))
                    f.close()
                    print_debug("Engine {} : pulled cpu data - OK".format(engine))
                else:
                    print("Engine {} : Unable to pull cpu data".format(engine))
                    f = open(self.enginecpulistfile, "a")
                    f.write("{},{}\n".format(engine, "0"))
                    f.close()
            else:
                print(
                    "Engine {} : Unable to connect and pull cpu data. Setting Default Value to 0".format(
                        engine
                    )
                )
                f = open(self.enginecpulistfile, "a")
                f.write("{},{}\n".format(engine, "0"))
                f.close()

        except:
            # print_debug("Engine {} : Error for get_cpu_raw_data".format(engine['ip_address']))
            print_debug("Engine {} : Unable to pull cpu data".format(engine))

    def gen_cpu_file(self):
        t = time.time()
        threadlist = {}
        f = open(self.enginecpulistfile, "w")
        f.write("{},{}\n".format("ip_address", "cpu"))
        f.close()
        dlpxconfig = loadveconfig()
        config_file_path = self.config_file_path

        dlpxconfig.get_config(config_file_path)
        engine_dict = self.create_dictobj(self.enginelistfile)
        eng_list = []
        for eng_rec in engine_dict:
            eng_list.append(eng_rec["ip_address"])
        print_debug(eng_list)
        i = 1

        self.print_debug_banner("Generate CPU Info")
        for engine in dlpxconfig.dlpx_engines:
            print_debug("dxtoolkit Engine : {}".format(engine))
            dxtoolkit_eng_ip = dlpxconfig.dlpx_engines[engine]["ip_address"]
            if dxtoolkit_eng_ip in eng_list:
                print_debug("Found Engine {} in pool".format(dxtoolkit_eng_ip))
                threadlist[i] = threading.Thread(
                    target=self.get_cpu_for_engine,
                    args=(
                        config_file_path,
                        engine,
                        dxtoolkit_eng_ip,
                    ),
                )
                print_debug("threadlist: {}".format(threadlist))
                threadlist[i].start()
                # time.sleep(1)
                i = i + 1
                # self.get_cpu_for_engine(config_file_path,engine)
            else:
                print_debug("Engine {} not in pool. skipping ...".format(engine))

        for threadkeys in threadlist.keys():
            print_debug("threadkey = {}".format(threadkeys))
            threadlist[threadkeys].join()

        # print("CPU data collection done in {0} Minutes".format((time.time() - t) / 60))
        print_debug(
            "CPU data collection done in {0} Minutes".format((time.time() - t) / 60)
        )

    def get_cpu_raw_data(self, engine):
        # engine = {'ip_address' : 'ajaydlpx6pri.dcenter.delphix.com' , 'username' : 'admin' , 'password' : 'delphix'}
        cookies = self.create_api_session(engine["ip_address"], port=80)
        if cookies is not None:
            print_debug("Engine {} : Session created".format(engine["ip_address"]))
            apicall = "login"
            payload = {
                "type": "LoginRequest",
                "username": engine["username"],
                "password": engine["password"],
            }
            logincookies = self.login_api_session(
                engine["ip_address"], cookies, apicall, payload, port=80
            )
            if logincookies is not None:
                print_debug("Engine {} : Login Successful".format(engine["ip_address"]))
                apicall = "analytics"
                analytics_list = self.get_api_response(
                    engine["ip_address"], logincookies, apicall, port=80
                )
                if analytics_list is not None:
                    cpu_data_list = []
                    for slice in analytics_list:
                        if slice["name"] == "default.cpu":
                            five_minute = timedelta(minutes=5)
                            end_date = datetime.utcnow()
                            # end_date = datetime.today()
                            start_date = end_date - five_minute
                            start_date_isostr = "{}T{}.000Z".format(
                                start_date.strftime("%Y-%m-%d"),
                                start_date.strftime("%H:%M:%S"),
                            )
                            end_date_isostr = "{}T{}.000Z".format(
                                end_date.strftime("%Y-%m-%d"),
                                end_date.strftime("%H:%M:%S"),
                            )
                            print_debug(
                                "Engine {} : Parameters ({}, {}, {}, {})".format(
                                    engine["ip_address"],
                                    slice["reference"],
                                    "resolution=1",
                                    start_date_isostr,
                                    end_date_isostr,
                                )
                            )
                            cpu_analytics_list = []
                            try:
                                apicall = "analytics/{}/getData?&resolution={}&numberofDatapoints={}&startTime={}&endTime={}".format(
                                    slice["reference"],
                                    "1",
                                    "10000",
                                    start_date_isostr,
                                    end_date_isostr,
                                )
                                cpu_analytics_data = self.get_api_response(
                                    engine["ip_address"], logincookies, apicall, port=80
                                )
                                if cpu_analytics_data == []:
                                    print_debug(
                                        "Engine {} : No data found for engine".format(
                                            engine["ip_address"]
                                        )
                                    )
                                else:
                                    for row in cpu_analytics_data["datapointStreams"][
                                        0
                                    ]["datapoints"]:
                                        ts = (
                                            row["timestamp"]
                                            .split(".")[0]
                                            .replace("T", " ")
                                        )
                                        idle = 0 if row["idle"] <= 0 else row["idle"]
                                        user = 0 if row["user"] <= 0 else row["user"]
                                        kernel = (
                                            1 if row["kernel"] <= 0 else row["kernel"]
                                        )
                                        ttl_cpu = idle + kernel + user
                                        util = (
                                            0
                                            if (ttl_cpu == 0)
                                            else (((user + kernel) / (ttl_cpu)) * 100)
                                        )
                                        cpu_data_dict = {"ts": ts, "cpu": float(util)}
                                        cpu_data_list.append(cpu_data_dict)

                                    # print_debug(round(mean(k['cpu'] for k in cpu_data_list),2))
                                    cpu_usage = round(
                                        mean(k["cpu"] for k in cpu_data_list), 2
                                    )
                                    f = open(self.enginecpulistfile, "a")
                                    f.write(
                                        "{},{}\n".format(
                                            engine["ip_address"], cpu_usage
                                        )
                                    )
                                    f.close()

                                    print_debug(
                                        "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
                                    )

                            except Exception as e:
                                print_debug(
                                    "Engine {} : Unable to pull cpu_analytics_data".format(
                                        engine["ip_address"]
                                    )
                                )
                                return
                else:
                    print_debug(
                        "Engine {} : Unable to pull data".format(engine["ip_address"])
                    )
            else:
                print_debug("Engine {} : Unable to login".format(engine["ip_address"]))


# GET: http://dlpx-5381-mds-1048-d2b9cd33.dc4.delphix.com:80/resources/json/delphix/service/time
# GET: http://dlpx-5381-mds-1048-d2b9cd33.dc4.delphix.com:80/resources/json/service/configure/currentSystemTime
# GET: http://dlpx-5381-mds-1048-d2b9cd33.dc4.delphix.com:80/resources/json/delphix/analytics/ANALYTICS_STATISTIC_SLICE-1/getData?&resolution=1&numberofDatapoints=10000&startTime=2020-05-21T16%3A49%3A16.000Z
