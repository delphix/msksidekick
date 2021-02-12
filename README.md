# Masking Sidekick

Masking Sidekick is a utility built using python 3.x. This utility will help to  

  1. Intelligently load balance masking job across multiple engines
  2. Sync job/environment/global objects/entire engine using source engine
  3. Backup / Restore masking engine metadata to / from file system

This utility relies on opensource [dxtoolkit](https://github.com/delphix/dxtoolkit) to find CPU information. This is required only if using load balancing module i.e. run-job

There are multiple sub modules. List of available modules can be listed as below
##### help
```shell
./msksidekick --help
```
Output
```shell
Usage: msksidekick [OPTIONS] COMMAND [ARGS]...

Options:
  -v, --verbose
  -d, --debug
  --help         Show this message and exit.

Commands:
  version              Script Version
  add-engine           This module will add engine to pool
  list-engine          This module will remove engine from pool
  del-engine           This module will remove engine from pool
  pull-joblist         This module will pull joblist from engine
  gen-dxtools-conf     This module will generate dxtools conf file for...
  sync-job             This module will sync particular job between 2...
  sync-env             This module will sync particular env between 2...
  sync-eng             This module will sync particular env between 2...
  sync-globalobj       This module will sync global objects between 2...
  cleanup-eng          This module will cleanup engine
  run-job              This module will execute masking job on best...
  test-connectors      This module will cleanup engine
  list-eng-usage       This module will find green engines
  offline-backup-eng   This module will offline backup engine
  offline-restore-eng  This module will offline restore engine from backups
```

##### List engines
This command show engines available in pool
```shell
./msksidekick list-engine
```

##### Add engines to pool
This command helps to add engines to the pool
```shell
./msksidekick add-engine -m atmskengine01 -t 64 -s 10
./msksidekick add-engine -m atmskengine02 -t 64 -s 10
./msksidekick add-engine -m atmskengine03 -t 64 -s 10
```

##### List engines
```shell
./msksidekick list-engine

e.g.
 EngineName                             Total Memory(GB)   System Memory(GB)
 atmskengine01                                        64                  10
 atmskengine02                                        64                  10
 atmskengine03                                        64                  10
```

##### Generate dxtools.conf file
```shell
./msksidekick gen-dxtools-conf --protocol http

e.g.
./msksidekick gen-dxtools-conf --protocol http
                            Masking Sidekick - [version]
****************************************************************************************************
./dxtools.conf file generated successfully
```

##### Validate VE
This functionality/settings is needed only for load balancing feature. Not applicable for sync and backup/restore.
```shell
export DXTOOLKIT_PATH=/Users/ajay.thotangare/dxtoolkit2  
$DXTOOLKIT_PATH/dx_get_appliance -all -configfile ./dxtools.conf
```

##### Pull job list
```shell
./msksidekick pull-joblist --help
Usage: msksidekick pull-joblist [OPTIONS]

  This module will pull joblist from engine

Options:
  -m, --mskengname TEXT  Masking Engine name
  -u, --username TEXT    Masking msksidekick username to connect masking engines
  -p, --password TEXT    Masking msksidekick password to connect masking engines
  --protocol TEXT        http protocol
  --help                 Show this message and exit.

e.g.  
./msksidekick pull-joblist -m all --username admin --password xxxxxx --protocol http
```

##### Run job - simulation
```shell
./msksidekick -v run-job -j maskjob6 -e mskdevenv --username admin --password xxxxxx --protocol http --dxtoolkit_path /home/ubuntu/WSL/dxtoolkit2
```
By default this runs in simulation mode. If job need to be executed then "-r" switch need to be added to above command
##### Real run
```shell
./msksidekick -v run-job -j maskjob6 -e mskdevenv --username admin --password xxxxxx --protocol http --dxtoolkit_path /home/ubuntu/WSL/dxtoolkit2 -r
```

##### Sync Eng
```shell
./msksidekick sync-eng --srcmskengname atmskengine01 --tgtmskengname atmskengine02 -g --username admin --password xxxxxx
```
 --protocol parameter can be added to connect masking engine as [ http|https ]
 --delextra parameter can be added to delete all extra applications and environments in target engine

##### Sync Env
```shell
./msksidekick sync-env --srcmskengname atmskengine01 --tgtmskengname atmskengine02 --srcenvname mskuatenv --tgtenvname mskuatenv -g --username admin --password xxxxxx --protocol https
```

##### Sync Job
```shell
./msksidekick sync-job --srcmskengname atmskengine01 --tgtmskengname atmskengine02 --srcenvname mskdevenv --tgtenvname mskdevenv --srcjobname maskjob6 -g --username admin --password xxxxxx --protocol https
```

##### Cleanup Engine
```shell
./msksidekick cleanup-eng --mskengname atmskengine02 --username admin --password xxxxxx --protocol https
```

##### Backup Engine
```shell
./msksidekick offline-backup-eng --mskengname atmskengine02 --backup_dir /home/ubuntu/WSL/test --username admin --password xxxxxx --protocol http
```

##### Restore Engine
```shell
./msksidekick offline-restore-eng --mskengname atmskengine02 --backup_dir /home/ubuntu/WSL/test/MMDDYYYY_HH24MISS --username admin --password xxxxxx --protocol http
```

##### List Engine Usage
```shell
./msksidekick.py -v list-eng-usage --username admin --password xxxxxx --protocol http --dxtoolkit_path /home/ubuntu/WSL/dxtoolkit2
```

##### Pull job execution list from engine pool
```shell
./msksidekick pull-currjoblist --username admin --password xxxxxx --protocol https 
```
Only RUNNING and QUEUED jobs will be listed

##### Pull specific job status from engine pool
```shell
./msksidekick pull-currjoblist -j maskjob6 -e mskdevenv --username admin --password xxxxxx --protocol https
```
All status of Job will be listed

### <a id="contribute"></a>How to Contribute

Please read [CONTRIBUTING.md](./CONTRIBUTING.md) to understand the pull requests process.

### <a id="statement-of-support"></a>Statement of Support

This software is provided as-is, without warranty of any kind or commercial support through Delphix. See the associated license for additional details. Questions, issues, feature requests, and contributions should be directed to the community as outlined in the [Delphix Community Guidelines](https://delphix.github.io/community-guidelines.html).

### <a id="license"></a>License

This is code is licensed under the Apache License 2.0. Full license is available [here](./LICENSE).

