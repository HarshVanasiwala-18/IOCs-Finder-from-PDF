import regex
from pdfminer.high_level import extract_text
from nltk import sent_tokenize
import re

regex_ipv6 = r'([a-f0-9:]+:+)+[a-f0-9]+'
regex_ipv4 = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
regex_filename = r'[A-Za-z0-9-_\·]+\.(txt|php|exe|dll|bat|sys|htm|html|js|jar|jpg|png|vb|scr|pif|chm|zip|rar|cab|pdf|doc|docx|ppt|pptx|xls|xlsx|swf|gif|bat|pdf)'
regex_filepath = r'[a-z A-Z]:(\\([0-9 a-z A-Z _]+))+'
regex_sha1 = r'[a-f0-9]{40}|[A-F0-9]{40}'
regex_sha256 = r'[a-f0-9]{64}|[A-F0-9]{64}'
regex_sha512 = r'[a-f0-9]{128}|[A-F0-9]{128}'
regex_md5 = r'[a-f0-9]{32}|[A-F0-9]{32}'
regex_cve = r'CVE-[0-9]{4}-[0-9]{4,6}'
regex_domain = r'[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,6}'
regex_url = r'(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=∼ _|! : , .;]+[-A-Za-z0-9+&@#/%?=∼ _|]'
regex_list = {'FILENAME' : regex_filename, 'FILEPATH' : regex_filepath, 'IPV4' : regex_ipv4, 'IPV6' : regex_ipv6, 'SHA1' : regex_sha1, 'SHA256' : regex_sha256, 'SHA512' : regex_sha512, 'MD5' : regex_md5, 'CVE': regex_cve, 'URL' : regex_url, 'DOMAIN' : regex_domain}

directory = input('Enter the directory of the PDF file: ')
file = open(directory, 'rb')

if file:
    text = extract_text(file)
    text = text.replace('\n', ' ').replace('\r', '').replace('\t', '').replace('\f', '')
    sentences = sent_tokenize(text)
else:
    file.close()

entities = []

for sentence in sentences:
    for key, value in regex_list.items():
        regex = r'\b' + value + r'\b'
        if re.search(regex, sentence, re.IGNORECASE):
            for match in re.finditer(regex, sentence, re.IGNORECASE):
                entities.append((match.group(), key))

for enity in entities:
    print(enity)