import subprocess
import time 
import hashlib
import os
import sys

import Evtx.Evtx as evtx
import Evtx.Views as e_views



def convert_evtx_to_xml(evtx_file, xml_file):
    with open(xml_file, 'w') as out:
        with evtx.Evtx(evtx_file) as log:  
            out.write(e_views.XML_HEADER)
            out.write("<Events>")
            for record in log.records():
                out.write(record.xml())
            out.write("</Events>")

def main(machine,malware):

    cuckoo_command = "cuckoo submit --machine {} {}".format(machine,malware)

    try:
        output = subprocess.check_output(cuckoo_command, shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        output = e.output

    output_string = output.decode('utf-8')
    output_string_lst = output_string.split()
    task_id = output_string_lst[-1].replace('#','')

    print(output_string)
    print(task_id)
    return task_id
    

if __name__ == '__main__':
    
    #file_lst = os.listdir('/home/vtproj/malware')
    machines = ['Win7','Win7_pro','Win7_enter','Win10']
    if len(sys.argv) > 2:
        first_argument = sys.argv[1]
    
        second_argument = sys.argv[2]
        
        machine = machines[int(second_argument)]
    elif len(sys.argv) > 1:
        first_argument = sys.argv[1]
        second_argument = 3
        
        machine = machines[second_argument]
    else:
        print('Please input Malware address as a argument. \n Input arguemtns Schema : \tpython file.py malware_address (machine)  ')
        exit()
    print(machine)
    malware = '/home/vtproj/VT_Analysis_Project/extract_evtx_pcap/malware/{}'.format(first_argument)
    f = open(malware, 'rb')
    data = f.read()
    f.close()
    print("SHA-256: " + hashlib.sha256(data).hexdigest())
    sha_value = hashlib.sha256(data).hexdigest()
    print(sha_value)
    
    task_id = main(machines[3],malware)

    for t in range(10):
        file_path = '/home/vtproj/.cuckoo/storage/analyses/{}/extracted/'.format(task_id)

        
        file_exists = os.path.exists(file_path)
        
        if file_exists == False:
            time.sleep(30)
            continue
        
        evtx_lst = os.listdir(file_path)
        
        
        evtx_lst = [file for file in os.listdir(file_path) if file.endswith('.evtx')]

        


        if len(evtx_lst) > 0 : 
            #rename
            os.makedirs('/home/vtproj/VT_Analysis_Project/extract_evtx_pcap/output/{}/'.format(task_id))
            os.makedirs('/home/vtproj/VT_Analysis_Project/extract_evtx_pcap/output/{}/evtx'.format(task_id))
            os.makedirs('/home/vtproj/VT_Analysis_Project/extract_evtx_pcap/output/{}/pcap'.format(task_id))
            for idx,evtx_name in enumerate(evtx_lst):

                evtx_file_path = file_path + evtx_name
                
                evtx_to_path = '/home/vtproj/VT_Analysis_Project/extract_evtx_pcap/output/{}/evtx/'.format(task_id)
                to_evtx_file = evtx_to_path + 'evtx_{}_{}_{}.xml'.format(sha_value,'cuckoo',idx)
                print(evtx_file_path)
                print(to_evtx_file)
                try:
                    
                    convert_evtx_to_xml(evtx_file_path, to_evtx_file)            
                except KeyError as e:
                    print("Error process on EVTX to XML")
                    continue 
            pcap_path = '/home/vtproj/.cuckoo/storage/analyses/{}/dump_sorted.pcap'.format(task_id)        
            pcap_to_path = '/home/vtproj/VT_Analysis_Project/extract_evtx_pcap/output/{}/pcap/'.format(task_id)
            to_pcap_file = pcap_to_path + 'pcap_{}_{}.pcap'.format(sha_value,'cuckoo')
            

            print('pcap ===================================')
            for c in range(10):
                if os.path.exists(pcap_path):

                    os.rename(pcap_path, to_pcap_file)
                else:
                    #print('There is no PCAP. It will be checked in 5 sec ')                    
                    time.sleep(5)
                    continue
            pcap_path = '/home/vtproj/.cuckoo/storage/analyses/{}/dump.pcap'.format(task_id)    
            print(pcap_path)
            print(to_pcap_file)
            os.rename(pcap_path, to_pcap_file)
            print('pcap ===================================')
            break
        else:   
            time.sleep(20)
            continue
                
                

            