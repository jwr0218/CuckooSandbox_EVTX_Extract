# Extract_evtx_pcap

Previous method to extract EVTX have limitation that it only can restore evtx, not extraction. 
It means that there are some missing data on restored EVTX files.

In This Repository, I can happily address you about how to extract EVTX files from Cuckoo Sandbox's Guest Server.

Logic is that analyzer which will be activated on window Guest server, extract EVTX and send them to Host Sever when analyzing is over. 

This repo is first thing to extract intact EVTX files on Cuckoo Sandbox. 


## Install Cuckoo Sandbox 


### Install Tools
```shell
sudo apt-get update
sudo apt-get install python python-pip python-dev libffi-dev libssl-dev
sudo apt-get install virtualbox virtualbox-guest-additions-iso virtualbox-dkms
sudo apt-get install libjpeg-dev zlib1g-dev swig
```

### Install MongoDB

```shell
sudo apt-get update
sudo apt-get install -y mongodb-org
```

### Cuckoo Sandbox

```shell
sudo pip install -U pip setuptools
sudo pip install -U cuckoo
```


### Activate Cuckoo

```shell
cuckoo
```

## After Install Cuckoo Sandbox


### Replace Analyzer

```

├──cuckoo/
│  ├── Analyzer
│  │   ├── windows
│  │   │   ├──analyzer.py << (Replace it to this repo's analyzer.py)
```


### you can find EVTX files on 'extracted' folder

```

├──cuckoo/
....
│  ├── storage
│  │   ├── analyses
│  │   │   ├──{analyzed number}
│  │   │   │  ├──extracted
```
