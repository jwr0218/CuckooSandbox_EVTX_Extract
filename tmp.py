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


evtx_file_path = '/home/vtproj/VT_Analysis_Project/extract_evtx_pcap/output/667/evtx/evtx_ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa_cuckoo_0.evtx'
xml_file_path = 'output.xml'

convert_evtx_to_xml(evtx_file_path, xml_file_path)


