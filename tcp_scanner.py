import socket
import sys
import requests
import time
import threading
import json
import os

class port_scanner:

    def __init__(self):
        self.config = {"p":"0-1024"}
        self.port_config = {}
        self.counter =0
        self.found = {}
        self.thread_counter = []
       
    def cls(self):
        if os.name !="nt":
            os.system("clear")
        else:
            os.system("cls")
    def get_service_arch(self,ele):
        if "--" in ele[0]:
            return f"{ele[0].split("--")[0]}:{ele[0].split("--")[1]}"
    def load_port_config_file(self):
        print("\n\t + [ Loading Port Config File ]")
        with open("port-config.txt",'r') as file:
            reader = file.read().splitlines()
        file.close()
        for i in reader:
            if ":" in i:
                sp = i.split(":")
                self.port_config[sp[0]] = self.get_service_arch(sp[1::])
        
    def is_port_open(self,port):
        
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(2)
        try:
            s.connect((self.config["ip"],port))
            self.found[port] = [self.port_config[str(port)].split(":")[0],self.port_config[str(port)].split(":")[1],""]
            print(f"\n\t\t [ + ]  open {port}\\tcp")
            self.counter += 1
            t = threading.Thread(target=self.get_banner,args=(s,port,))
            t.start()
            self.thread_counter.append(t)

        except:
            pass
    
    def get_banner(self,obj,port):

        if port == 80 or port == 443:
            res = requests.get(f'http://{sys.argv[sys.argv.index("-ip")+1]}/')
            self.found[port][-1] = res.headers["Server"]
            # try:

            #     ban = obj.recv(1024).decode()
            #     self.found[port][-1] = ban
            # except:
            #     self.found[port][-1] = ""
        else:
            # res = requests.get(f'http://{sys.argv[sys.argv.index("-ip")+1]}/')
            # self.found[port][-1] = res.headers["Server"]
            try:

                ban = obj.recv(1024).decode()
                self.found[port][-1] = ban
            except:
                self.found[port][-1] = ""
        obj.close()
    def configure(self):
        self.cls()
        print(sys.argv)
        for i in range(1,len(sys.argv)-1,2):
            ops = sys.argv[i].replace('-',"")
            ops = ops.lower()
            self.config[ops] = sys.argv[i+1]
        
        self.config["ip"] = socket.gethostbyname(self.config["ip"])
    def write_output_file(self,data):
        path = self.config['o']
        if os.path.exists(path):
            with open(path,'a') as file:
                file.write(data)
                file.write("\n")
                file.close()
        else:
            with open(path,'w') as file:
                file.write(f'\nReport for {self.config['ip']} [ {self.config['p']} ]')
                file.write("\n\t\t Port  \t\t\t Service \t\t\t Protocol \t\t\t Banner\t\t\t")
                file.write(data)
                file.close()
        
    def scanner(self):
        if len(sys.argv) > 1:
            if "-ip" in sys.argv:
                print(" [ + ]  Config Progress")
                self.configure()
                print("\n\t====================[ OPTIONS ]=================================")
                for i in self.config:
                    if i == "p":
                        print(f"\n\t + port : {self.config[i]}")
                    elif i=="o":
                        print(f"\n\t + output file : {self.config[i]}")
                    else:
                        print(f"\n\t + {i} : {self.config[i]} ")
                print("\n\t==========================================================")
                time.sleep(0.1)
                self.load_port_config_file()
                if "-" in self.config["p"]:
                    print("\n")
                    count = 0
                    for i in range(int(self.config["p"].split("-")[0]),int(self.config["p"].split("-")[1])):
                        count+=1
                        if count%1000==0:
                            time.sleep(2)
                        print("\t + Scanning Port",i,end='\r')
                        sys.stdout.flush()
                        try:
                            t = threading.Thread(target=self.is_port_open,args=(i,))
                            t.start()
                            self.thread_counter.append(t)
                        except:
                            pass
                    for i in self.thread_counter:
                        
                        i.join()
                    self.cls()
                    print(f"Report for {self.config["ip"]} @ {self.config["p"]}")
                    print("\n\t\t Port  \t\t\t Service \t\t\t Protocol \t\t\t Banner\t\t\t")
                    self.counter = 0
                    for i in self.found:
                        self.counter += 1
                        if 'o' in self.config.keys():
                            self.write_output_file(f"\n\t\t {i} \t\t\t {self.found[i][0]} \t\t\t\t {self.found[i][1]} \t\t\t\t {self.found[i][2]}")
                        print(f"\n\t\t {i} \t\t\t {self.found[i][0]} \t\t\t\t {self.found[i][1]} \t\t\t\t {self.found[i][2]}")
                    print("\n[ ! ] open Ports : ",self.counter )
                if 'o' in self.config.keys():
                    print('\n*****************************************')
                    conf = self.config['o']
                    if '/' in conf:
                        pass
                    else:
                        conf = os.getcwd() + "/" + conf
                    print("Output File Written : ",conf)
                    print("\n*****************************************")
            else:
                print("-ip parameter not found [ ! ]")
                self.help()
        else:
            self.help()

    def help(self):

        print(f"\nusage : {sys.argv[0]} -p 0-3000 -o <output file_name> -ip <ip address>")
        print("\n\t-p - port to scan [ Default : 1 - 1024 ] [ optional ]")
        print("\n\t-o - output file name with extention [optional ] [ Eg : out.txt]")
        print("\n\t-ip - ip address to scan via Tcp [ Required ]")
p = port_scanner()
p.scanner()