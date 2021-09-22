import os
debug = None
arguments = {}
script_dir_path = os.path.dirname(os.path.realpath(__file__))
output_dir_path = "{}/../output".format(script_dir_path)
enginelistfile = "{}/enginelist.csv".format(output_dir_path)
joblistfile = "{}/joblist.csv".format(output_dir_path)
jobexeclistfile = "{}/jobexeclist.csv".format(output_dir_path)
qualifiedengineslistfile = "{}/qualifiedengineslist.csv".format(output_dir_path)
enginecpulistfile = "{}/enginecpulist.csv".format(output_dir_path)
dxtools_file_csv = "{}/dxtools.csv".format(output_dir_path)
dxtools_file = "{}/dxtools.conf".format(script_dir_path)
def initialize():     
    global debug
    global arguments
    debug = None
    arguments = {}
