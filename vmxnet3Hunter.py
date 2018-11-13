#!/usr/bin/python3
"""
Usage:
  vmxnet3_hunter.py -h | --help
  vmxnet3_hunter.py (--vsphere_list=<vsphere_list> --vsphere_user=<vsphere_user>)
 
Options:
  --vsphere_list=<vsphere_list>     A file containing a single IPv4 address per line
  --vsphere_user=<vsphere_user>     vCenter username ex: administrator@vsphere.local
"""
import ssl
import ipaddress
import json
import concurrent.futures

from getpass import getpass
from docopt import docopt
from pyVim.connect import SmartConnect
from pyVmomi import vim


def generate_list_from_file(data_file):
    """
    Generate a list from a given file containing a single line of desired data, intended for IPv4 and passwords.

    Args:
        data_file: A file containing a single password or IPv4 address per line

    Returns:
        A list of passwords, IPv4
    """
    print("Generating data list from: {}".format(data_file))
    data_list = []
    with open(data_file, 'r') as my_file:
        for line in my_file:
            try:
                ip = line.strip('\n').strip(' ')
                ipaddress.ip_address(ip)
                data_list.append(ip)
            except:
                print("{} is not an IPv4 address".format(line))
                pass
    return data_list

def enum_vsphere(vsphere_ip, vsphere_user, vsphere_pass):
    """
    Connect to a vsphere server via api and gather all virtual machines with a vmxnet3 adapter.

    Args:
        vsphere_ip: target vCenter server
        vsphere_user: vCenter user
        vsphere_pass: vCenter password

    Returns:
        Dictionary containing the parent vCenter and a list of VMs using vmxnet3
    """
    print("Conecting to vCenter: {}".format(vsphere_ip))
    try:
        s = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        s.verify_mode = ssl.CERT_NONE
        si = SmartConnect(host=vsphere_ip, user=vsphere_user, pwd=vsphere_pass, sslContext=s)
        content = si.content
        host_container = content.viewManager.CreateContainerView(content.rootFolder, [vim.HostSystem], True)
        esxi_hosts = []
        cluster_patch_priority = []
        for esxi_obj in host_container.view:
            print("Enumerating ESXi Host: {}".format(esxi_obj.summary.config.name))
            if esxi_obj.summary.config.product.version >= str(6.5):
                vulnerable_cve = "CVE-2018-6981, CVE-2018-6982, VMSA-2018-0027"
            elif esxi_obj.summary.config.product.version >= str(6):
                vulnerable_cve = "CVE-2018-6981, VMSA-2018-0027"
            elif esxi_obj.summary.config.product.version < str(6):
                vulnerable_cve = "Not vulnerable to: VMSA-2018-0027"
            
            vms = []
            for vm_obj in esxi_obj.vm:
                print("Enumerating Virtula Machine: {}".format(vm_obj.guest.ipAddress))
                for device in vm_obj.config.hardware.device:
                    if isinstance(device, vim.vm.device.VirtualVmxnet3):
                        print("Found vm with vmxnet3: {}".format(vm_obj.guest.ipAddress))
                        vms.append(
                            {
                                "ip": vm_obj.guest.ipAddress,
                                "name": vm_obj.name,
                                "family": vm_obj.guest.guestFamily,
                                "fullname": vm_obj.guest.guestFullName,
                                "state": vm_obj.guest.guestState,
                                "hostname": vm_obj.guest.hostName,
                                "nicDevice": "VMXNET3"
                            }
                        )
                    else:
                        pass
            if vms:
                patch_priority = True
                cluster_patch_priority.append(esxi_obj.parent.name)
            else:
                patch_priority = False
            

            esxi_hosts.append(
                {
                    "VulnerableTo": vulnerable_cve,
                    "Version": esxi_obj.summary.config.product.version,
                    "Name": esxi_obj.summary.config.name,
                    "Cluster": esxi_obj.parent.name,
                    "VirtualMachines": vms,
                    "PatchPriority": patch_priority
                }
            )
        print("Enumerating vCenter: {}".format(vsphere_ip))
        vcenter_details = {
            "vCenterVersion": content.about.version,
            "vCenterBuild": content.about.build,
            "vCenterIP": vsphere_ip,
            "ESXiHosts": esxi_hosts, # comment out if you only want to return which clusters to patch
            "ClusterPatchPriority": cluster_patch_priority
        }
        return {"vCenterIP": vcenter_details}
    except vim.fault.InvalidLogin as ex:
        print("Login failed for vCenter: {}".format(vsphere_ip))
        pass

def enum_vsphere_concurrent(vsphere_list: list, vsphere_user: str, vsphere_pass: str):
    """
    Concurrently run the enum_vsphere function.

    Args:
        vsphere_list: List of vCenter IPs
        vsphere_user: vCenter user
        vsphere_pass: vCenter password

    Returns:
        A list of dictionaries containing the results for each vSphere server
    """
    print("Concurrently executing vCenter enumeration")
    results_list = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=50) as pool:
        results = {pool.submit(enum_vsphere, vsphere_ip, vsphere_user, vsphere_pass): vsphere_ip for vsphere_ip in vsphere_list}
        for future in concurrent.futures.as_completed(results):
            if future.result():
                results_list.append(future.result())
    return results_list

def results_to_file(results):
    """
    Write the results to a log file.

    Args:
        results: The results datastructure to write to output file
    
    Returns:
        Nothing is returned
    """
    print("Writing our results to vmxnet3_results.log")
    with open('vmxnet3_results.log', 'w+') as file:
        file.write(json.dumps(results, sort_keys=True, indent=4))

def main():
    """Run all of the things!"""
    opts = docopt(__doc__)
    try:
        vsphere_user = opts["--vsphere_user"]
        vsphere_pass = getpass("Password for user {}: ".format(vsphere_user))
        vsphere_list = generate_list_from_file(opts["--vsphere_list"])
        results = enum_vsphere_concurrent(vsphere_list, vsphere_user, vsphere_pass)
        results_to_file(results)
    except Exception as ex:
        print("Error: {}".format(str(ex)))

if __name__ == '__main__':
    main()

