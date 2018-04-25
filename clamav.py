#!/usr/bin/python3

from subprocess import Popen, PIPE
import sys
import json
import re
import glob
from itertools import islice
import pickle
import logging
import time
import datetime
import argparse
import os
import tempfile

STATE_FOLDER = os.path.join('progress','defender')

os.makedirs(STATE_FOLDER,exist_ok=True)

LOG_FOLDER = 'logs'

os.makedirs(LOG_FOLDER,exist_ok=True)

logging.basicConfig(
    format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
    handlers=[
        logging.FileHandler("{0}/{1}.log".format(LOG_FOLDER, 'clamavscan')),
        logging.StreamHandler()
    ],level=logging.DEBUG)


class ClamAvProcessor():
    md5rex = re.compile(r"[0-9a-f]{32}$",re.IGNORECASE)
    sha1rex = re.compile(r"[0-9a-f]{40}$",re.IGNORECASE)
    sha256rex = re.compile(r"[0-9a-f]{64}$",re.IGNORECASE)
    clamSigRex = re.compile(r"^ClamAV\s([0-9\.]+)\/(\d+)\/(\w+)\s(\w+)\s+(\d)+\s(\d+)\:(\d+)\:(\d+)\s(\d{4})$")
    options = []
    def __init__(self):

        self.get_banner()
        self.get_definition_time()
        self.get_version()

        self.state_path = os.path.join(STATE_FOLDER,'state.pk')

        if os.path.exists(self.state_path):
            with open(self.state_path, 'rb') as handle:
                self.state = pickle.load(handle)
        else:
            os.makedirs(LOG_FOLDER,exist_ok=True)
            self.state = []

    def get_banner(self):
        ''' Get the version banner '''
        clamscan_version = Popen(['clamscan', '-V'], stdout=PIPE)
        out, err = clamscan_version.communicate()
        clamscan_version.stdout.close()
        self.banner = out.decode('utf-8')

    def get_definition_time(self):
        '''
        Get the date time of the antivirus signatures
        '''

        match = re.search(self.clamSigRex, self.banner)
        if match:
            daystr = match.group(3)
            monthName = match.group(4)
            monthNum = datetime.datetime.strptime(monthName, '%b').month

            daynum = match.group(5)
            hour = match.group(6)
            minutes = match.group(7)
            seconds = match.group(8)
            year = match.group(9)

        self.signatureDate = datetime.datetime(int(year),monthNum,int(daynum),int(hour),int(minutes),int(seconds))

        return self.signatureDate

    def get_version(self):
        '''
        Get the version and build of the anti virus
        '''
        match = re.search(self.clamSigRex, self.banner)
        if match:
            self.version = match.group(1)
            self.build = match.group(2)

        return [self.version,self.build]

    def merge_scans(self,folder,jsonlines=False):
        '''
        :param folder: the folder which contains the json reports
        :param jsonlines: new line separated json or not
        :return: list of md5
        '''

        merged = []
        lookup = set()

        for r, d, files in os.walk(folder):
            #sort the reports in decreasing temporal order
            sorted_reports = sorted(files, reverse=True)
            for file in sorted_reports:
                if file.endswith(".json") and file.replace('.json','').isdigit():
                    logging.info("Processing file %s" % file)
                    path = os.path.join(r, file)

                    with open(path,'r') as fp:
                        detections = json.load(fp)
                        # the new files in this batch
                        unique = set([det['md5'] for det in detections])
                        # only add the new files
                        newfiles = [det for det in detections if det['md5'] not in lookup]
                        merged = merged + newfiles
                        #update the list of seen md5 so far
                        lookup = lookup.union(unique)

        timestamp = datetime.datetime.now().strftime("%b_%d_%Y_%H.%M.%S")
        out_merge = os.path.join(folder,"merged_{0}.json".format(timestamp))

        if jsonlines:
            with open(out_merge,"w") as file:
                for item in merged:
                    file.write(json.dumps(item))
                    file.write('\n')
        else:
            with open(out_merge,"w") as file:
                json.dump(merged,file)

        logging.info("Merged : total unique MD5 = %d" % len(merged))

        return len(merged)

    def chunk(self,it, size):
        ''' An iterator to chunk a list '''
        it = iter(it)
        return iter(lambda: list(islice(it, size)), ())

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
        ''' Scan the folder in batches for performance reasons'''

        if path.endswith(os.path.sep):
            self.files = list(glob.iglob(path + '*', recursive=recursive))

        else:
            self.files = list(glob.iglob(path + os.path.sep + '*', recursive=recursive))

        logging.info("Preparing to scan {0} total files".format(len(self.files)))
        files2copy =self.chunk(self.files,batch)
        # triggered when a keyboard interrupt is provided
        interrupted = False

        # each chunk contains a list of paths
        for chunk in files2copy:

            if len(chunk) == 0 or interrupted == True:
                break

            # which files were not scanned from last time
            notscanned = [path for path in chunk if path not in self.state]

            if len(notscanned) == 0:
                continue

            try:
                # a temporary file which contains the file paths to be scanned
                temp_scanlist = tempfile.NamedTemporaryFile(mode='w')
                temp_scanlist.write('\n'.join(notscanned))
                clamscan_process = Popen(['clamscan','--infected','-f', temp_scanlist.name], stdout=PIPE, stderr = PIPE)
                # LibClamAV Warning: cli_scanicon: found 1 invalid icon entries of 4 total

                out, err = clamscan_process.communicate()

                if out:
                    manifest = out.decode('utf-8')
                    if len(manifest.strip()) == 0:
                        continue
                if err:
                    logging.error(err.decode('utf-8'))

                detected = []
                head_summary = False
                reports = []

                for line in manifest.split('\n'):

                    if 'SCAN SUMMARY' in line:
                        head_summary = True
                        logging.info(line)
                        continue

                    if head_summary:
                        if len(line.strip()) > 0:
                            logging.info(line)

                    if head_summary == False:
                        cleaned = line.strip(' \t\n\r')
                        if len(cleaned) > 0:

                            line_chunked = cleaned.split(': ')
                            filepath = line_chunked[0]
                            family = line_chunked[1]

                            if family.endswith("FOUND"):
                                family = family.split(' ')[0]

                                [hashlen,value] = self.get_hash(os.path.basename(filepath))
                                if hashlen != None:
                                    reports.append( {hashlen: value, "clamav": family,
                                                     "version": self.version,"build":self.build,
                                                     'signatureTime':self.signatureDate.isoformat(),
                                                     'scanTime':datetime.datetime.utcnow()})

                                    detected.append(filepath)
                                else:
                                    logging.error("Unable to find hash for filename %s" % os.path.basename(filepath))


                # files without any detection
                not_detected = [item for item in notscanned if item not in detected]
                for filepath in not_detected:
                    [hashlen, value] = self.get_hash(os.path.basename(filepath))
                    if hashlen !=None and value != None:
                        reports.append( {hashlen: value, "clamav": '',
                                         "version": self.version,"build":self.build,
                                         'signatureTime':self.signatureDate.isoformat(),
                                         'scanTime': datetime.datetime.utcnow()} )
                    else:
                        logging.error("Unable to find hash for filename %s" % os.path.basename(filepath))
                # add to the state
                self.state += notscanned

            except KeyboardInterrupt:
                # remove the last chunk just in case
                del self.state[-len(chunk):]
                # kill the clamscan process
                if clamscan_process.poll() is not None:
                    clamscan_process.kill()

                logging.warning("Terminating batch process....")
                interrupted = True
            finally:
                yield reports
                temp_scanlist.close()
                with open(self.state_path, 'wb') as handle:
                    pickle.dump(self.state, handle, protocol=pickle.HIGHEST_PROTOCOL)


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
        processor = ClamAvProcessor()
        merged = processor.merge_scans(args.detections,args.newline)

    if args.version:
        processor = ClamAvProcessor()
        version = processor.get_version()
        print("Version {0} Build {1}".format(version[0],version[1]))
        sigs = processor.get_definition_time()
        print("Signature date {0}".format(sigs.isoformat()))
    if args.scan:
        if args.folder:
            processor = ClamAvProcessor()
            os.makedirs(args.detections,exist_ok=True)

            for reports in processor.scan_folder(args.folder,recursive=args.recursive,batch=args.batchsize):

                output_file = os.path.join(args.detections, "%s.json" % int(time.time()))

                with open(output_file, "w") as file:
                    json.dump(reports, file)
