def initialize(pdebug, pverbose, pscript_dir_path):
    global arguments
    global debug
    global verbose
    global script_dir_path
    global output_dir_path
    global enginelistfile
    global joblistfile
    global jobexeclistfile
    global qualifiedengineslistfile
    global enginecpulistfile
    global dxtools_file_csv
    global dxtools_file

    arguments = {}
    debug = pdebug
    verbose = pverbose
    script_dir_path = pscript_dir_path
    output_dir_path = "{}/output".format(script_dir_path)
    enginelistfile = "{}/enginelist.csv".format(output_dir_path)
    joblistfile = "{}/joblist.csv".format(output_dir_path)
    jobexeclistfile = "{}/jobexeclist.csv".format(output_dir_path)
    qualifiedengineslistfile = "{}/qualifiedengineslist.csv".format(output_dir_path)
    enginecpulistfile = "{}/enginecpulist.csv".format(output_dir_path)
    dxtools_file_csv = "{}/dxtools.csv".format(output_dir_path)
    dxtools_file = "{}/dxtools.conf".format(script_dir_path)
