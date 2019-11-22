# Limitation
Script does not currently identify which ESXi systems have been patched, and merely relies on major and minor revision numbrer to determine if the hypervisor is vulnerable.  If required we can check patches but this tool will live and die over a short periord of time so it isn't worth the effort.  

# Description:  

This tool enables operations teams to quickly identify and prioritize which vCenter clusters have virtual machines using the VMXNET3 adapter on top of ESXi hypervisors vulnerable to VMSA-2018-0027.  

VMware Advisory: https://www.vmware.com/security/advisories/VMSA-2018-0027.html  
CVE: CVE-2018-6981, CVE-2018-6982  

# Usage

Usage:
  vmxnet3_hunter.py -h | --help
  vmxnet3_hunter.py (--vsphere_list=<vsphere_list> --vsphere_user=<vsphere_user>)
 
Options:
  --vsphere_list=<vsphere_list>     A file containing a single IPv4 address per line
  --vsphere_user=<vsphere_user>     vCenter username ex: administrator@vsphere.local

# Example vsphere_list file
$ cat rhosts  
1.1.1.1  
2.2.2.2  
3.3.3.3  
4.4.4.4  
5.5.5.5  

# Example execution
$ python3 vmxnet3_hunter.py  --vsphere_list rhosts --vsphere_user administrator@sphere.local   
  
Password for user administrator@vsphere.local:  
  
Generating data list from: rhosts    
Description:  
Concurrently executing vCenter enumeration  
Conecting to vCenter: 1.1.1.1  
Enumerating ESXi Host: 1.1.1.1 
Enumerating Virtula Machine: None  
Enumerating Virtula Machine: None  
Enumerating Virtula Machine: None  
Found vm with vmxnet3: None  
Enumerating Virtula Machine: 1.1.1.1  
Found vm with vmxnet3: 1.1.1.1   
Enumerating ESXi Host: 1.1.1.1  
Enumerating Virtula Machine: None  
Enumerating ESXi Host: 1.1.1.1  
Enumerating Virtula Machine: None  
Enumerating vCenter: 1.1.1.1   
Writing our results to vmxnet3_results.log  

# Log output      
$ cat vmxnet3_results.log  
```json
[  
    {  
        "vCenterIP": {  
            "ClusterPatchPriority": [  
                "Lab"  
            ],  
            "ESXiHosts": [  
                {  
                    "Cluster": "Lab",  
                    "Name": "1.1.1.1 ",  
                    "PatchPriority": true,  
                    "Version": "6.5.0",  
                    "VirtualMachines": [  
                        {  
                            "family": null,    
                            "fullname": null,  
                            "hostname": null,  
                            "ip": null,  
                            "name": "ubuntu01",  
                            "nicDevice": "VMXNET3",  
                            "state": "notRunning"  
                        },  
                        {  
                            "family": "linuxGuest",  
                            "fullname": "Other 3.x or later Linux (64-bit)",  
                            "hostname": "debian01",  
                            "ip": "1.1.1.1 ",  
                            "name": "VMware vCenter Server Appliance",  
                            "nicDevice": "VMXNET3",  
                            "state": "running"  
                        }  
                    ],  
                    "VulnerableTo": "CVE-2018-6981, CVE-2018-6982, VMSA-2018-0027"  
                },  
                {  
                    "Cluster": "Lab",  
                    "Name": "1.1.1.1 ",  
                    "PatchPriority": false,  
                    "Version": "6.5.0",  
                    "VirtualMachines": [],  
                    "VulnerableTo": "CVE-2018-6981, CVE-2018-6982, VMSA-2018-0027"  
                },  
                {  
                    "Cluster": "Lab",  
                    "Name": "1.1.1.1 ",  
                    "PatchPriority": false,  
                    "Version": "6.5.0",  
                    "VirtualMachines": [],  
                    "VulnerableTo": "CVE-2018-6981, CVE-2018-6982, VMSA-2018-0027"  
                }  
            ],  
            "vCenterBuild": "8307201",  
            "vCenterIP": "1.1.1.1",  
            "vCenterVersion": "6.5.0"  
        }  
    }  
]  
```
