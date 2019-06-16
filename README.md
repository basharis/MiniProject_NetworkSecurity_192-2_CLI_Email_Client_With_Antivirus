# Topics in Network Security 192: CLI Email Client With Antivirus

## Dependencies

• Python 3.7 with modules: 
  • smtplib (send) 
  • imaplib (receive) 
  • emails.mime 
  • virus_total_apis 
  • colorama

## Usage

```
     send
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
            usage: exit
```
