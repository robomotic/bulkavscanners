from subprocess import Popen, PIPE
import re
import glob
import os
import pickle
import json
import time
import logging
import argparse
import datetime
import hashlib

__author__ = "Paolo Di Prodi"
__copyright__ = "Copyright 2018, Paolo Di Prodi"

__license__ = "Apache 2.0"
__version__ = "0.99"
__email__ = "contact [AT] logstotal.com"

STATE_FOLDER = os.path.join('progress','defender')

os.makedirs(STATE_FOLDER,exist_ok=True)

LOG_FOLDER = 'logs'

os.makedirs(LOG_FOLDER,exist_ok=True)

logging.basicConfig(
    format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
    handlers=[
        logging.FileHandler("{0}/{1}.log".format(LOG_FOLDER, 'defenderscan')),
        logging.StreamHandler()
    ],level=logging.DEBUG)

class WinDefenderProcessor():

    md5rex = re.compile(r"[0-9a-f]{32}$",re.IGNORECASE)
    sha1rex = re.compile(r"[0-9a-f]{40}$",re.IGNORECASE)
    sha256rex = re.compile(r"[0-9a-f]{64}$",re.IGNORECASE)

    threatrex = re.compile(r"^Threat\s+\:\s(.+)$")
    resrex = re.compile(r"^Resources\s+\:\s(\d+)\stotal$")
    filerex = re.compile(r"^\s+file\s+\:\s(.*)$")
    headrex = re.compile(r"found\s(\d+)\sthreats\.$")

    def __init__(self,hashtype='md5'):
        self.preferred_hash = hashtype
        self.state_path = os.path.join(STATE_FOLDER,'state.pk')
        self.get_version()
        if os.path.exists(self.state_path):
            with open(self.state_path, 'rb') as handle:
                self.state = pickle.load(handle)
        else:
            os.makedirs(LOG_FOLDER,exist_ok=True)
            self.state = []

    @staticmethod
    def hash_file(path):
        with open(path, 'rb') as file:
            data = file.read()
            info = {
                'md5': hashlib.md5(data).hexdigest(),
                'sha1': hashlib.sha1(data).hexdigest(),
                'sha256': hashlib.sha256(data).hexdigest()}

            return info

    def get_version(self):
        # use WMI to get all versions
        self.engine = '1.1.14800.3'
        self.platform = ' 4.14.17613.18039'
        self.signature = '1.267.196.0'

    def get_hash(self,filename):
        match = re.findall(self.md5rex, filename)
        if match:
            return ('md5',match[0].lower())

        match = re.findall(self.sha1rex, filename)
        if match:
            return ('sha1', match[0].lower())

        match = re.findall(self.sha256rex, filename)
        if match:
            return ('sha256', match[0].lower())

        return (None,None)

    def scan_folder(self,path,recursive = False, batch = 10):
        ''' Scan file one by one '''

        if path.endswith(os.path.sep):
            self.files = list(glob.iglob(path + '*', recursive=recursive))

        else:
            self.files = list(glob.iglob(path + os.path.sep + '*', recursive=recursive))

        logging.info("Preparing to scan {0} total files".format(len(self.files)))

        # which files were not scanned from last time
        notscanned = [path for path in self.files if path not in self.state]

        if len(notscanned) == 0:
            logging.warn("No new files to scan")
            return

        interrupted = False

        for filepath in notscanned:

            if interrupted == True:
                break

            try:
                [hashtype, value] = self.get_hash(os.path.basename(filepath))

                defender_process = Popen(['mpcmdrun', '-scan', '-scantype', '3', '-DisableRemediation', '-file', filepath],
                                         stdout=PIPE,stderr = PIPE)

                out, err = defender_process.communicate()

                if len(err.decode('utf-8')) > 0:
                    logging.error(err.decode('utf-8'))
                summary = self.parse_defender_out(out.decode('utf-8'))

                if hashtype is None or hashtype!=self.preferred_hash:
                    #compute the hash of the file
                    all_hash = WinDefenderProcessor.hash_file()
                    hashtype = self.preferred_hash
                    value = all_hash[self.preferred_hash]

                if 'Found' not in summary:
                    report = {hashtype: value, "defender": '',
                                    "engine": self.engine, "platform": self.platform,
                                    "signature": self.signature,
                                    'scanTime': datetime.datetime.utcnow().isoformat()}

                elif summary['Found'] > 0 :
                    for threat in summary['Threats']:
                        report = {hashtype: value, "defender": threat['Threat'],
                                        "engine": self.engine, "build": self.platform,
                                        "signature": self.signature,
                                        'scanTime': datetime.datetime.utcnow().isoformat()}
                self.state += [filepath]

            except KeyboardInterrupt:
                # remove the last chunk just in case
                del self.state[-1:]
                # kill the clamscan process
                if defender_process.poll() is not None:
                    defender_process.kill()

                logging.warning("Terminating batch process....")
                interrupted = True
            finally:

                yield report

                with open(self.state_path, 'wb') as handle:
                    pickle.dump(self.state, handle, protocol=pickle.HIGHEST_PROTOCOL)

    def parse_defender_out(self,report):
        # 'Threat                  : Virus:DOS/Svir'
        # 'Resources               : 1 total'
        # '    file                : F:\\VirusShare_xxxxx\\VirusShare_000a50c55a2f4517d2e27b21f4b27e3b'
        lines = report.split('\r\n')
        header = False
        begin_manifest = False
        end_manifest = False
        summary = {}
        detection = {}

        for line in lines:
            if 'LIST OF DETECTED THREATS' in line or 'Scan starting...' in line or 'Scan finished.' in line:
                header = True
                continue
            elif line.startswith("Scanning"):
                match = re.findall(self.headrex, line)
                if match:
                    summary["Found"] = int(match[0])
                    summary["Threats"] = []
                header = False
            elif 'Threat information' in line:
                begin_manifest = True
                continue
            elif line.count('-') == len(line):
                end_manifest = True
                # time to flush!
                if len(detection.keys())>0:
                    summary["Threats"].append(detection)
                detection = {}
                begin_manifest = False
            elif begin_manifest == True:
                match = re.findall(self.threatrex, line)
                if match:
                    detection['Threat'] = match[0]
                match = re.findall(self.resrex, line)
                if match:
                    detection['Resources'] = match[0]
                match = re.findall(self.filerex, line)
                if match:
                    if 'Files' in detection:
                        detection['Files'].append(match[0])
                    else:
                        detection['Files'] = [match[0]]
        return summary


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Scan an entire folder with ClamAv')

    parser.add_argument('--version',action='store_true',
                        help='Display Clam version')

    parser.add_argument('--scan',action='store_true',
                        help='Scan a folder')

    parser.add_argument('--folder',dest='folder', type=str,
                        help='Folder with virus samples')

    parser.add_argument('--detections',dest='detections', type=str,
                        help='Folder with the output of the scan')

    parser.add_argument('--merge', action='store_true',
                        help='Merge previous scans')

    parser.add_argument('--recursive', action='store_true',
                        help='Scan all files with nested folders')

    parser.add_argument('--batchsize', default = 140, type = int,
                        help='Batch scanning in groups')

    parser.add_argument('--newline', action='store_true', default= True,
                        help='Use new lines in json output')

    args = parser.parse_args()

    if args.merge:
        processor = WinDefenderProcessor()
        merged = processor.merge_scans(args.detections,args.newline)

    if args.version:
        processor = WinDefenderProcessor()
        version = processor.get_version()
        print("Version {0} Build {1}".format(version[0],version[1]))
        sigs = processor.get_definition_time()
        print("Signature date {0}".format(sigs.isoformat()))
    if args.scan:
        if args.folder:
            processor = WinDefenderProcessor()
            os.makedirs(args.detections,exist_ok=True)

            reports = []
            for report in processor.scan_folder(args.folder,recursive=args.recursive):

                reports.append(report)

                if len(reports) >= args.batchsize:
                    output_file = os.path.join(args.detections, "%s.json" % int(time.time()))

                    with open(output_file, "w") as file:
                        json.dump(reports, file)
                        logging.info("Saved %d " % len(reports))
                    reports = []

            if len(reports) > 0:
                output_file = os.path.join(args.detections, "%s.json" % int(time.time()))

                with open(output_file, "w") as file:
                    json.dump(reports, file)
                    logging.info("Saved %d " % len(reports))