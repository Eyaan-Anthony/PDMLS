from django.shortcuts import render
from django.utils.timezone import datetime
from django.http import HttpResponse, HttpResponseRedirect
from .forms import LoginForm, MailFolderForm,connect_to_mailbox, serialize_imap, deserialize_imap
import imaplib
from django.core import serializers
import json
from django.shortcuts import redirect
from django.urls import reverse


import email
import email.policy

# Create your views here.
from django.http import HttpResponse
import email.parser
from pd_app.myfunctions import *


def home(request):
    return render(
        request,
        'pd_app/home.html'
    )

def LoginView(request):
    
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            request.session['username'] = username
            request.session['password'] = password

            server = connect_to_mailbox(username, password)
            if server:

                imap_data = serialize_imap(server)
                json_data = json.dumps(imap_data)

                #server = deserialize_imap(imap_data, username, password)
                # Store relevant data in the session
                request.session['imap_host'] = imap_data['host']
                request.session['imap_port'] = imap_data['port']
        

                #request.session['server'] = server
                return redirect('Profile')
            
            else:
                return(HttpResponse("Check internet connection and enter valid email and password"))
        else:
            context = {
                'form':form
            }
            return render(request, 'pd_app/login.html', context)
    else:
        form = LoginForm()
        return render(request, 'pd_app/login.html', {'form': form})


def Profile(request):
    # Fetch username and password from session
    username = request.session.get('username')
    password = request.session.get('password')

    if not username or not password:
        return HttpResponse("User not authenticated.")

    server = connect_to_mailbox(username, password)
    if not server:
        return HttpResponse("Failed to connect to mailbox")

    if request.method == "POST":
        form = MailFolderForm(request.POST)
        if form.is_valid():
            folder = form.cleaned_data['folder']
            url_list = []
            try:
                server.select(folder)
                # Use search to get email IDs
                result, email_ids = server.search(None, 'ALL')  # 'ALL' retrieves all emails
                phishing_attempts = []
                malicious_urls = []

                if result == 'OK':  # Check if folder selected successfully
                    # Adjust this number to fetch fewer emails
                    #total_emails = int(mail_list[1][0])
                    #num_to_fetch = min(total_emails, 40)  # Fetch up to 10 emails
                    email_ids = email_ids[0].split()  # Assuming email_ids is in the first element
                    email_ids = [id.decode('utf-8') for id in email_ids]  # Decode byte strings to UTF-8
                    email_ids = email_ids[::-1]
                    print("displaying ids")
                    print(email_ids)
                    num_to_fetch = min(len(email_ids), 2)  # Fetch up to 10 most recent emails

                    for i in range(num_to_fetch):
                        email_id = email_ids[i]
                        fetch_response = server.fetch(email_id, '(RFC822)')
                        print(f"Fetch result for email ID {email_id}: {fetch_response}") #debugging line

                        if fetch_response[0] == "OK":
                            mail_data = fetch_response[1][0][1]
                            mail = email.message_from_bytes(mail_data, policy=email.policy.default)
                            header = mail.items()
                            header_df, valid_username = header_data(header)
                            label = None #initialize it before you use it
                            label = check_header(header_df, valid_username)

                            if label==2:
                                phishing_attempts.append((mail['Message-ID'], header))
                                print(f"Phishing attempt found in Email ID: {email_id}")
                            else: 
                                continue

                            
                            url_list = extract_url(mail)
                            print(f"Extracted URLs from Email ID {email_id}: {url_list}")
                            for url in url_list:
                                url_df = url_information(url)

                                if url_df is not None:
                                    url_df.columns = ['TXTDnsResponse', 'HasSPFInfo', 'ASN', 'StrangeCharacters',
            'ConsoantRatio', 'NumericRatio', 'VowelRatio', 'NumericSequence', 'DomainLength'
        ]
                                    label = check_url(url_df)
                                    if label[0] == 0:
                                        malicious_urls.append(url)
                                        #print(f"Malicious URL found: {url}")
                                    else:
                                        print(f"URL is safe: {url}")  # Debugging statement
                                else:
                                    continue

                phishing_count = len(phishing_attempts)
                url_count = len(malicious_urls)
                context = {
                    'phishing_attempts': phishing_attempts,
                    'malicious_urls': malicious_urls,
                    'form': form,
                    'folder': folder,
                    'phishing_count': phishing_count,
                    'url_count': url_count,
                    'username': username
                }

                print(f"Number of emails fetched: {num_to_fetch}")
                print(f"Header items: {header}")
                print(f"Extracted URLs: {url_list}")
            except Exception as e:
                return HttpResponse(f"An error occurred: {str(e)}")
            # Debugging before rendering
            print("Rendering Profile with context:", context)
            return render(request, 'pd_app/Profile.html', context=context)

    else:
        form = MailFolderForm()
        return render(request, 'pd_app/Profile.html', {'form': form})



    