__Author__ = 'Saumitra Paul Choudhury'
'''
Below code will parse the CFLOW header and exptract the tuple information


'''

import pyshark
import pdb,time,os,sys
import binascii
import struct
import socket
import csv
import argparse

class cflowParser(object):
    '''
    Input is pcap file (wireshark)
    Parser will scan the packets captured .
    With pyshark lib , each packet details will comes as list in hex format
    At position where Netflow header (Cflow) is present , need to convert hex to binary
    With struct lib , will read byte by byte for each field.
    Data will be then read into a csv file for each packet
    '''
    
    def __init__(self,pcap_file_name):
       '''
       Check if csv file is present.
       Intialize the csv file 
       '''
       current_directory = os.getcwd()+"/"
       if not os.path.isfile(current_directory+pcap_file_name):
          print "Abort as the pcap file is not found in the current directory"
          sys.exit()
       self.pcap_file_name = pcap_file_name
       self._flow_dict = {}
       logfile = self.pcap_file_name.split('.')[0] + '.csv'
       self.fp_cvs =  open(logfile,"w")
       self.csvout=csv.writer(self.fp_cvs)
       self.csvout.writerow(("Flow Count","Interface Id","Source Port","Source IP","Destination Port","Destination IP",\
                           "Packet Count","Start Time","End Time"))
       self.intfList = {}
       self.num_source_eps_ipv4 = []
       self.num_source_eps_ipv6 = []


    def parserFunc(self):
        '''
        Read the pcap file. Get the Cflow data in hex format . Converts into binary
        Read Binary data byte by byte , based on field characteristics.
        Field characteristics are found from the Netflow template packet.
        Stores the information in a data structure - for ipv4 and ipv6 

        '''
        flow_cnt = 0
        #logfile = 'data-' + time.strftime("%Y%m%d-%H%M%S")  + '.csv'
        cap = pyshark.FileCapture(self.pcap_file_name)
        for i in cap:
            try:
               hex_data = i[4]._all_fields['data']
               $Converting the hex into binary
               bin_data = binascii.unhexlify(hex_data)
               version = struct.unpack('>H',bin_data[0:2])[0]
               num_of_record = struct.unpack('>H',bin_data[2:4])[0]
               offset = 40
               offset1 = 64
               index = 0
               for pkt_id in range(0,num_of_record):
                    flowset_id = struct.unpack('>H',bin_data[20+index:22+index])[0]
                    flag = False
                    if flowset_id == 256:
                         '''
                         IPv4 Netflow data
                         '''
                         flag = True
                         pkt_cnt = struct.unpack('>I',bin_data[24+index:28+index])[0]
                         src_port = struct.unpack('>H',bin_data[34+index:36+index])[0]
                         src_ip = (socket.inet_ntoa(hex(struct.unpack('>I',bin_data[36+index:40+index])[0])[2:].zfill(8).decode('hex')),)[0]
                         dst_port = struct.unpack('>H',bin_data[40+index:42+index])[0]
                         dst_ip = (socket.inet_ntoa(hex(struct.unpack('>I',bin_data[42+index:46+index])[0])[2:].zfill(8).decode('hex')),)[0]
                         interface_id = struct.unpack('>I',bin_data[46+index:50+index])[0]
                         start_time = struct.unpack('>I',bin_data[52+index:56+index])[0]
                         end_time = struct.unpack('>I',bin_data[56+index:60+index])[0]
                         index = index + offset
                         if src_ip not in self.num_source_eps_ipv4:
                                 self.num_source_eps_ipv4.append(src_ip) 
                    elif flowset_id == 257:
                         '''
                         IPv6 Netflow data
                         '''
                         flag = True
                         tmp =""
                         tmp1 =""
                         pkt_cnt = struct.unpack('>I',bin_data[24+index:28+index])[0]
                         src_port = struct.unpack('>H',bin_data[34+index:36+index])[0]
                         src_data = [hex(val)[2:] for val in struct.unpack('>HHHHHHHH',bin_data[36+index:52+index])]
                         for value in src_data:
                             tmp = tmp + value + ":"
                         src_ip = tmp[0:-1]
                         #print "****{0}***".format(src_ip)
                         dst_port = struct.unpack('>H',bin_data[72+index:74+index])[0]
                         dst_data = [hex(val)[2:] for val in struct.unpack('>HHHHHHHH',bin_data[52+index:68+index])]
                         for value in dst_data:
                            tmp1 = tmp1 + value + ":"
                         dst_ip = tmp1[0:-1]
                         interface_id = struct.unpack('>I',bin_data[68+index:72+index])[0]
                         start_time = struct.unpack('>I',bin_data[76+index:80+index])[0]
                         end_time = struct.unpack('>I',bin_data[80+index:84+index])[0]
                         index = index + offset1
                         if src_ip not in self.num_source_eps_ipv6:
                                 self.num_source_eps_ipv6.append(src_ip) 
                    else:
                         pass
                    if flag:
                         #Building the dict
                         #Track the packet count for a tuple with Source IP as the key 
                         #Assuming destination port is same but source port can vary 
                         if src_ip not in self._flow_dict.keys():
                             self._flow_dict[src_ip]=[]
                         self._flow_dict[src_ip].append([src_ip,src_port,dst_ip,dst_port,pkt_cnt,interface_id,start_time,end_time])
            except IndexError:
               pass
            except:
               print "Exception happend %s", sys.exc_info()[0]
               print "Exception in parsing the file"
               return None 


    def getResult(self):
          '''
          Reads the data strcuture holding the information
          Dumps in the CSV file
          Also tell how many netflow packets are send from each switch interface
          ''' 
          flow_cnt = 0
          ret_dict = {}
          print "Parsing complete , extraction in progress"
          for key in self._flow_dict.keys():
                for i in range(0,len(self._flow_dict[key])):
                      flow_cnt +=1
                      src_ip = self._flow_dict[key][i][0]
                      src_port = self._flow_dict[key][i][1]
                      dst_ip = self._flow_dict[key][i][2]
                      dst_port = self._flow_dict[key][i][3]
                      pkt_cnt = self._flow_dict[key][i][4]
                      intf_id = self._flow_dict[key][i][5]
                      if intf_id not in ret_dict.keys() and src_port != 0:
                          ret_dict[intf_id] = int(pkt_cnt)
                      else:
                          if src_port != 0:
                                ret_dict[intf_id] = int(ret_dict[intf_id]) + int(pkt_cnt)
                      start_time = self._flow_dict[key][i][6]
                      end_time = self._flow_dict[key][i][7]
                      self.csvout.writerow((flow_cnt,intf_id,src_port,\
                                     src_ip,dst_port,dst_ip,pkt_cnt,start_time,end_time))
                      self.fp_cvs.flush()
          return ret_dict
    def cleanup(self):
          self.fp_cvs.close()
          print "Cleanup module"
                   
