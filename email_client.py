import datetime
import os
import email
import argparse
import hashlib
import json
import shlex
import smtplib
import imaplib
from os.path import basename
from colorama import *
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.utils import formatdate
from virus_total_apis import PublicApi as VirusTotalPublicApi

# Global variables
_smtp_ssl_host = "smtp.gmail.com"
_smtp_ssl_port = 465
_imap_ssl_host = "imap.gmail.com"
_imap_ssl_port = 993
_user = ""
_password = ""
_funcs = {}
_vt_api_key = ""
_virus_total = None


def cprint(msg, colorama_color):
    print(colorama_color + msg + Style.RESET_ALL)


def _set_globals(args):
    global _smtp_ssl_host, _smtp_ssl_port, _user, _password, _funcs, _vt_api_key, _virus_total
    if args.host == 'GMAIL':
        _smtp_ssl_host = 'smtp.gmail.com'
        _smtp_ssl_port = 465
        _imap_ssl_host = 'imap.gmail.com'
        _imap_ssl_port = 993
    elif args.host == 'HOTMAIL':
        _smtp_ssl_host = 'smtp.live.com'
        _smtp_ssl_port = 465
        _imap_ssl_host = 'imap-mail.outlook.com'
        _imap_ssl_port = 993
    _user = args.user
    _password = args.password
    _vt_api_key = args.vt_api_key
    _virus_total = VirusTotalPublicApi(_vt_api_key)
    _funcs['send'] = cmd_send
    _funcs['receive'] = cmd_receive
    _funcs['exit'] = cmd_exit
    _funcs['quit'] = cmd_exit
    _funcs['help'] = cmd_help


def parse_send(cmd):
    send_parser = argparse.ArgumentParser()
    send_parser.add_argument("-r", "--recipient", dest="recipient",
                              help="Recipient of this message (e.g. jdoe@gmail.com)",
                              required=True)
    send_parser.add_argument("-s", "--subject", dest="subject", default="[NO SUBJECT]", help="Subject of the message")
    send_parser.add_argument("-b", "--body", dest="body", default="[NO BODY]", help="Body of the message")
    send_parser.add_argument("-a", "--attachment_path", dest="attachment_path", default=None,
                              help="Path to Attached File")
    return send_parser.parse_args(cmd[1:])


def vt_scan(f):
    f_md5 = hashlib.md5(f).hexdigest()
    print("Scanning file via VirusTotal.com...", end=' ')
    try:
        file_report = _virus_total.get_file_report(f_md5)
        if file_report['results']['positives'] > 0:
            cprint("Infected :(", Fore.RED)
            print("Dump results (y/n)?", end=' ')
            dump = input('')
            if dump == 'y' or dump == 'yes':
                print(json.dumps(file_report, sort_keys=False, indent=4))
            return -1
    except Exception as e:
        cprint("Scan failed :(", Fore.RED)
        cprint(str(e), Fore.RED)
        return -1
    cprint("Clean!", Fore.GREEN)
    return 0


def login(server):
    print("Attempting to login...", end=' ')
    try:
        server.login(_user, _password)
        cprint("Login successful!", Fore.GREEN)
    except Exception as e:
        cprint("Login failed :(", Fore.RED)
        cprint(str(e), Fore.RED)
        return -1
    return 0


def send(server, args, msg):
    print('Sending "{}" to "{}" with attachment "{}"...'
          .format(args.subject, args.recipient, args.attachment_path), end=' ')
    try:
        server.sendmail(_user, args.recipient, msg.as_string())
        cprint("Send successful!", Fore.GREEN)
    except Exception as e:
        cprint("Send failed :(", Fore.RED)
        cprint(str(e), Fore.RED)
        return -1
    return 0


def cmd_send(cmd):
    args = parse_send(cmd)
    msg = MIMEMultipart()
    msg['Subject'] = args.subject
    msg['From'] = _user
    msg['To'] = args.recipient
    msg['Date'] = formatdate(localtime=True)
    msg.attach(MIMEText(args.body))
    if args.attachment_path is not None:
        with open(args.attachment_path, 'rb') as f:
            f = f.read()
            if vt_scan(f) == -1:
                return
            attachment = MIMEApplication(f, Name=basename(args.attachment_path))
        attachment['Content-Disposition'] = 'attachment; filename="%s"' % basename(args.attachment_path)
        msg.attach(attachment)

    server = smtplib.SMTP_SSL(_smtp_ssl_host, _smtp_ssl_port)
    if login(server) == -1:
        return
    if send(server, args, msg) == -1:
        return
    server.quit()


def parse_receive(cmd):
    receive_parser = argparse.ArgumentParser()
    receive_parser.add_argument("-d", "--dump_body", dest="dump_body", action="store_true", default=False,
                                help="Dump messages with bodies to stdout")
    receive_parser.add_argument("-f", "--filter", dest="filter", choices={"ALL", "UNSEEN"}, default="ALL",
                                help="Get ALL/UNSEEN emails")
    receive_parser.add_argument("-a", "--attachment", dest="attachment", action="store_true", default=False,
                                help="Download attachment if available")
    return receive_parser.parse_args(cmd[1:])


def fetch(server, l_filter):
    print("Fetching emails from inbox...", end=' ')
    server.list()
    server.select('inbox')
    try:
        result, data = server.uid('search', None, l_filter)
        cprint("Fetch successful!", Fore.GREEN)
        return result, data
    except Exception as e:
        cprint("Fetch failed :(", Fore.RED)
        print(str(e))


def cmd_receive(cmd):
    args = parse_receive(cmd)
    server = imaplib.IMAP4_SSL(_imap_ssl_host, _imap_ssl_port)
    if login(server) == -1:
        return
    result, data = fetch(server, args.filter)
    i = len(data[0].split())

    for x in range(i):
        latest_email_uid = data[0].split()[x]
        result, email_data = server.uid('fetch', latest_email_uid, '(RFC822)')
        raw_email = email_data[0][1]
        raw_email_string = raw_email.decode('utf-8')
        email_message = email.message_from_string(raw_email_string)

        # Header Details
        date_tuple = email.utils.parsedate_tz(email_message['Date'])
        if date_tuple:
            local_date = datetime.datetime.fromtimestamp(email.utils.mktime_tz(date_tuple))
            local_message_date = "%s" % (str(local_date.strftime("%a, %d %b %Y %H:%M:%S")))
        email_from = str(email.header.make_header(email.header.decode_header(email_message['From'])))
        email_to = str(email.header.make_header(email.header.decode_header(email_message['To'])))
        subject = str(email.header.make_header(email.header.decode_header(email_message['Subject'])))
        print(f"\t{Fore.CYAN}From:{Style.RESET_ALL}      %s\n\t{Fore.CYAN}To:{Style.RESET_ALL}        "
              f"%s\n\t{Fore.CYAN}Date:{Style.RESET_ALL}      %s\n\t{Fore.CYAN}Subject:{Style.RESET_ALL}   %s\n"
              % (email_from, email_to, local_message_date, subject))

        for part in email_message.walk():
            # Attachment details
            fileName = part.get_filename()
            if bool(fileName) and args.attachment:
                if not os.path.isdir(os.path.join(os.getcwd(), "downloads")):
                    os.mkdir(os.path.join(os.getcwd(), "downloads"))
                filePath = os.path.join(os.getcwd(), "downloads", fileName)
                downloaded = part.get_payload(decode=True)
                if vt_scan(downloaded) != -1:
                    fp = open(filePath, 'wb')
                    fp.write(downloaded)
                    fp.close()
                    print('Downloaded {color}"{file}"{reset} from email titled '
                          '{color}"{subject}"{reset} with UID {color}{uid}{reset}.'
                          .format(color=Fore.CYAN, reset=Style.RESET_ALL, file=fileName,
                                  subject=subject, uid=latest_email_uid.decode('utf-8')))
                else:
                    continue
            if part.get_content_type() == "text/plain":
                if part.get('Content-Disposition') is not None:
                    continue
                # Body details
                if args.dump_body:
                    body = part.get_payload(decode=True)
                    print(f"\t{Fore.CYAN}Body:{Style.RESET_ALL}\n    %s\n"
                          % (body.decode('utf-8')))
                else:
                    print("\n")


def cmd_exit(cmd):
    cprint("Have a nice day! Exiting...", Fore.YELLOW)
    exit()


def cmd_help(cmd):
    cprint("""     send
           usage: send -r RECIPIENT [-s SUBJECT] [-b BODY] [-a ATTACHMENT_PATH]
            optional arguments:
              -r RECIPIENT, --recipient RECIPIENT                       Recipient of this email (e.g. jdoe@gmail.com)
              -s SUBJECT, --subject SUBJECT                             Subject of the message
              -b BODY, --body BODY                                      Body of the message
              -a ATTACHMENT_PATH, --attachment_path ATTACHMENT_PATH     Path to Attached File
    receive
            usage: receive [-d] [-f {ALL,UNSEEN}]
            optional arguments:
              -d, --dump_body                                           Dump messages with bodies to stdout
              -f {ALL,UNSEEN}, --filter {ALL,UNSEEN}                    Get ALL/UNSEEN emails
              -a, --attachment                                          Download attachment if available
    exit
            usage: exit""", Fore.YELLOW)


def main(args):
    _set_globals(args)

    while True:
        print("<NetworkSecurityMini192>", end=' ')
        cmd = input('')
        if cmd == '':
            continue
        cmd = shlex.split(cmd)
        if cmd[0] == '':
            continue
        try:
            _funcs[cmd[0]](cmd)
        except KeyError:
            cprint("Unknown command - type \'help\' for command list.", Fore.RED)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-hst", "--host", default="GMAIL", dest="host", choices={'GMAIL', 'HOTMAIL'}, help="Email Host (GMAIL/HOTMAIL)")
    parser.add_argument("-usr", "--user", dest="user", help="Email Username (e.g username@gmail.com)", required=True)
    parser.add_argument("-pwd", "--password", dest="password", help="Email Password", required=True)
    parser.add_argument("-api", "--virus_total_api_key", dest="vt_api_key", help="VirusTotal.com Public API Key", required=True)
    return parser.parse_args()


if __name__ == '__main__':
    main(parse_args())
