import email.parser
import email
import email.policy
from email.parser import HeaderParser
import email.utils
import re
import pandas as pd
import pickle
from bs4 import BeautifulSoup
import whois
import socket
from cymruwhois import Client
import dns.resolver
import pandas as pd
import numpy as np
import pickle

url_model_pkl_file = "pd_app\\static\\pd_app\\url_classifier.pkl"
with open(url_model_pkl_file, 'rb') as file:
    url_model = pickle.load(file)

# Load the model once at the module level (global scope)
header_model_pkl_file = "pd_app\\static\\pd_app\\header_classifier.pkl"
with open(header_model_pkl_file, 'rb') as file:  
    header_model = pickle.load(file)

def extract_address_from_username(username):
    username = str(username)
    username = username[username.find("<")+1:username.find(">")]
    return username


def header_data(header):
    """To extract all the information about the header for successful classification"""
    required_headers = ['missing_list-id', 'missing_precedence', 'missing_delivered-to', 'missing_list-unsubscribe',
                        'missing_list-subscribe', 'missing_list-post', 'missing_list-help', 'missing_x-spam-status',
                        'str_return-path_bounce', 'str_precedence_list', 'domain_match_to_received']
    
    header_field_names = ['list-id', 'precedence', 'delivered-to', 'list-subscribe', 'list-unsubscribe',
                    'list-post', 'list-help', 'x-spam-status', 'return-path']
    
    fields = [element[0] for element in header]
    data = []

    # Mark missing headers
    for field in header_field_names:
        data.append(1 if field not in fields else 0)

    # Precedence list check
    data.append(0 if data[1] == 1 else 1)

    # Domain matched to receiver list
    data.append(1 if 'Received-SPF' in fields or 'DKIM-Signature' in fields else 0)

    # Convert to DataFrame
    header_df = pd.DataFrame(data=[data], columns=required_headers)
    header_df.fillna(0)
    
    # Convert to numpy array and handle NaNs
    header_array = header_df.to_numpy()
    header_array = np.nan_to_num(header_array, nan=0)

    # Ensure proper shape
    if header_array.ndim == 1:
        header_array = header_array.reshape(1, -1)  # Reshape if it's 1D
    

    #i need another variable called valid_username
    #value is true if the username does not contain an address email or an email address different from return path
    #else, false
    for head, value in header:
        if head == "Return-Path":
            sender = value
        elif head == "From":
            sender = value
        else:
            valid_username = 0
    sender = email.utils.parseaddr(str(sender))
    real_sender_address = sender[1]
    address_found_in_username = extract_address_from_username(sender[0])
    if real_sender_address == address_found_in_username:
        valid_username = 1
    else:
        valid_username = 0
    
    return header_df, valid_username

def extract_url(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.iter_parts():
            charset = part.get_content_charset() or 'utf-8'
            content_type = part.get_content_type()
            if content_type == 'text/html':
                try:
                    body = part.get_payload(decode=True).decode(charset, errors='ignore')
                    print("HTML body extracted.")
                    break  # Extract only the first HTML part
                except Exception as e:
                    print(f"Error decoding HTML part: {e}")
                    return []

    else:
        # For single part messages
        charset = msg.get_content_charset() or 'utf-8'  # Fallback to UTF-8
        body = msg.get_payload(decode=True).decode(charset, errors='ignore')


    if not body:
        print("No HTML body found.")
        return []

    print("Extracted body:", body)  # Debugging line
    soup = BeautifulSoup(body, 'html.parser')
    links = [a['href'] for a in soup.find_all('a', href=True)]

    return links


def check_header(header_df, valid_username):
    """to classify the header using the header classifier"""
    label = None
    #there needs to another condition, if the an email address is found in the 
    if valid_username:
        label = header_model.predict(header_df)
        return label
    else:
        label = 2
        return label

    #return False
    
def check_url(url_df):
    label = None
    """to classify the urls using the url classifier"""
    label = url_model.predict(url_df)
    return label

"""header_model_pkl_file = "static/pd_app/header_classifier.pkl"
            url_model_pkl_file = "static/pd_app/url_classifier.pkl"
            #to have the two  ai models loaded
            with open(header_model_pkl_file, 'rb') as file:
                header_model = pickle.load(file)
            with open(url_model_pkl_file, 'rb') as file:
                url_model = pickle.load(file)"""

def is_registered(domain_name):
    """
    A function that returns a boolean indicating 
    whether a `domain_name` is registered
    """
    try:
        w = whois.whois(domain_name)
    except Exception:
        return False
    else:
        return bool(w.domain_name)

def url_information(url):
    """This function returns features needed for domain classification in the form of a DataFrame."""
    
    # Extract domain from URL
    hostname = re.findall(r'://([\w\-\.]+)', url)
    if not hostname:
        return None  # Return None or handle error if URL is invalid
    hostname = hostname[0]

    if is_registered(hostname):
        # Domain length
        DomainLength = len(hostname)

        # Vowel ratio
        VowelRatio = len(re.findall(r'[aeiouAEIOU]', hostname)) / len(hostname)

        # Consonant ratio
        ConsonantRatio = len(re.findall(r'[^aeiouAEIOU\d\s]', hostname)) / len(hostname)
        # Numeric ratio
        NumericRatio = len(re.findall(r"[0-9]", hostname)) / len(hostname)

        # Numeric sequence
        NumericSequence = len(re.findall(r"[0-9]", hostname))

        special_characters = "!@#$%^&*()-+?_=,<>/'"
        StrangeCharacters = sum(1 for c in hostname if c in special_characters)

        # Domain IP
        try:
            Ip = socket.gethostbyname(hostname)
        except socket.error:
            Ip = None  # Handle error if IP resolution fails

        # ASN number
        c = Client()
        r = c.lookup(Ip) if Ip else None
        ASN = r.asn if r else None
        # SPF info and TXT DNS response
        getresolver = dns.resolver.Resolver()
        try:
            gettext = getresolver.resolve(hostname, "SPF")
            gettextdns = getresolver.resolve(hostname, 'TXT')
            HasSPFInfo = bool(gettext)
            TXTDnsResponse = bool(gettextdns)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            HasSPFInfo = False
            TXTDnsResponse = False
        
        data = [[TXTDnsResponse, HasSPFInfo, ASN if ASN is not None else 0, StrangeCharacters, 
                ConsonantRatio, NumericRatio, VowelRatio, NumericSequence, DomainLength]]
        
        url_info_dataframe = pd.DataFrame(data=data, columns=['TXTDnsResponse', 'HasSPFInfo', 'ASN', 'StrangeCharacters',
            'ConsoantRatio', 'NumericRatio', 'VowelRatio', 'NumericSequence', 'DomainLength'
        ])
        url_info_dataframe.fillna(0)
        # Convert to numpy array and handle NaNs
        url_array = url_info_dataframe.to_numpy()
        url_array = np.nan_to_num(url_array, nan=0)
        url_info_dataframe = url_info_dataframe.fillna(0)
        
        return url_info_dataframe
    else:
        return None  # Handle case where domain is not registered