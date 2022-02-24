import scapy.all as sc
import argparse, os

class Extractor():
    def __init__(self) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument('--file', metavar='--f', help='Set .pcap file')
        parser.add_argument('--src', '--s', action='store_true', help='Display all source IPs')
        parser.add_argument('--dst', '--d', action='store_true', help='Display all destination IPs')
        parser.add_argument('--unique', '--u', action='store_true', help='Display only unique IPs (don\'t use with --len)')
        parser.add_argument('--len', '--l', action='store_false', help='Include packet length')
        parser.add_argument('--output', metavar='--o', type=str, help='Set name of output file. If not set will display data on screen')

        self.args = parser.parse_args()
        self.storage = []

    def extract_data(self) -> None:
        return sc.rdpcap(self.args.file)

    def save_data(self) -> None:
        self.parse_data()

        if self.args.output is not None:
            with open(f'{self.args.output}.txt', 'w+') as log:
                for data in self.storage:
                    log.write(data + '\n')
        else:
            print(self.storage)

    def parse_data(self) -> None:
        for i, pkt in enumerate(self.extract_data()):
            if (self.args.src):
                if self.args.len == True:
                    self.storage.append(pkt[sc.IP].src)
                else:
                    self.storage.append([pkt[sc.IP].src, pkt[sc.IP].len])

            elif (self.args.dst):
                if self.args.len == True:
                    self.storage.append(pkt[sc.IP].dst)
                else:
                    self.storage.append([pkt[sc.IP].dst, pkt[sc.IP].len])
            else:
                print(f'{sc.rdpcap(self.args.file)}\nUse: py scriptname.py --h')
                os._exit(0)
        
        if (self.args.unique):
            self.storage = set(self.storage)


ex = Extractor()
ex.save_data()
