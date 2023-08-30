import base64
import re
import time
from pathlib import Path
import random

import pandas as pd
import streamlit as st

from Abuseipdb.AbuseIPDB import check_ip
favicon = Path(__file__).parent / 'favicon.ico'
st.set_page_config(page_title="Cyberani Solutions | Bulker", page_icon=str(favicon), layout="wide", initial_sidebar_state="auto", menu_items=None)
st.markdown("""<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.0.0/dist/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">""",unsafe_allow_html=True)

def img_to_bytes(img_path):
    img_bytes = Path(img_path).read_bytes()
    encoded = base64.b64encode(img_bytes).decode()
    return encoded

st.markdown("""<style>       
    hr{
        background: linear-gradient(to right, blue, green);
        height: 5px;
    }
</style>""",unsafe_allow_html=True)
def img_to_html(img_path):
    img_html = "<img src='data:image/png;base64,{}' class='img-fluid' width=350px>".format(
        img_to_bytes(img_path)
    )
    return img_html
Logo = Path(__file__).parent / 'cyberani.png'
st.markdown(
        '<p style="text-align: center; color: grey;">' + img_to_html(Logo) + '</p><hr>', unsafe_allow_html=True)

Logo_side = Path(__file__).parent / 'favicon.png'
st.sidebar.image(str(Logo_side), use_column_width=True)


def home():
    import streamlit as st
    st.write(
        "Welcome to the IP, Email, and URL Reputation Checker application | Bulker. "
        "This tool aims to make searching for the reputation of IPs, emails, and URLs easier and faster."
    )

    st.header("Features")
    st.markdown(
        "- Check the reputation of an IP address to identify potential malicious activity.\n"
        "- Verify the reputation of an email address to detect spam or phishing.\n"
        "- Evaluate the reputation of a URL to identify potential unsafe websites."
    )

    st.header("How to Use")
    st.write(
        "1. Enter an IP address, email address, or URL in the respective input box.\n"
        "2. Click the 'Check' button to get the reputation information.\n"
        "3. The application will display the reputation status and any additional details.\n"
    )

    st.header("Note")
    st.write(
        "This application is for informational purposes only and does not provide real-time data. "
        "It relies on predefined databases and services for reputation checks."
    )


def extract_attack_signature_and_ports(comment):
    # Dictionary of attack categories and their associated patterns
    attack_patterns = {
        "ssh": ["ssh", "sshd"],
        "malware": ["malware", "virus", "trojan"],
        "sql-injection": ["sql injection", "sql-inject"],
        "brute-force": ["brute force", "credential stuffing"],
        "exploit": ["exploit", "vulnerability"],
        "phishing": ["phishing", "fraud"],
        "ddos": ["ddos", "distributed denial of service","distributed"],
        "port scan":["port scanning","scanning"],
        "Unauthorized connection":["Unauthorized connection","Unauthorized"],
        "authentication failure":["authentication failure","authentication","failure"],
        "Failed password":["Failed password"],
        "Invalid user":["Invalid user"],
        "honeypot":["honeypot"],
        "telnet":['telnet'],
        "Unauthorized activity":['Unauthorized activity'],
        "Unsolicited connection":["Unsolicited connection"]
        # Add more categories and patterns here
    }

    port_pattern = r'port (\d+)'

    attack_signatures = []
    ports = []

    # Find attack signatures in the comment
    for category, patterns in attack_patterns.items():
        for pattern in patterns:
            if re.search(pattern, comment, re.IGNORECASE):
                attack_signatures.append(category)
                break

    # Find port numbers in the comment
    port_matches = re.findall(port_pattern, comment)
    ports = [int(port) for port in port_matches]

    return attack_signatures, ports

def extract_ips(ip_string):
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    ip_array = re.findall(ip_pattern, ip_string)
    return ip_array

def AbuseIPDB():
    import streamlit as st
    import plotly.express as px
    import pandas as pd
    if "data" not in st.session_state:
        data = {
            "ipAddress": [],
            "isPublic": [],
            "ipVersion": [],
            "isWhitelisted": [],
            "abuseConfidenceScore": [],
            "countryCode": [],
            "usageType": [],
            "isp": [],
            "domain": [],
            "hostnames": [],
            "isTor": [],
            "countryName": [],
            "totalReports": [],
            "numDistinctUsers": [],
            "lastReportedAt": [],
            "reports": []
        }

        # Create an empty DataFrame
        df = pd.DataFrame(data)

        # Fill the DataFrame with zeros (for numeric columns)
        numeric_columns = [
            "ipVersion", "abuseConfidenceScore", "totalReports", "numDistinctUsers"
        ]
        df[numeric_columns] = df[numeric_columns].fillna(0)

        st.session_state['data'] = df
    if "signature" not in st.session_state:
        st.session_state['signature'] = []
    st.markdown("<h3>IP Reputation Engine (IRE)</h3>",unsafe_allow_html=True)
    st.write("The IRE will recieve Bulk number of IPs and scan them against the best 3 IP database service (Project Honey Pot, AbuseIPDB, Spamhaus)")

    IP = st.text_area("IRE", height=500, max_chars=None, key="IRE_IPs", placeholder="Paste IP here", disabled=False, label_visibility="visible")
    IP = extract_ips(IP)
    json_response=[]
    comments=''
    if st.button("Scan",key="ScanIP"):
        progress_bar = st.progress(0)  # Initialize the progress bar
        json_response = []
        comments = ''
        total_ips = len(IP)
        completed_ips = 0

        with st.spinner("Scanning"):
            for i in IP:
                json_response.append(check_ip(i, 30))
                completed_ips += 1
                progress_percentage = int((completed_ips / total_ips) * 100)
                progress_bar.progress(progress_percentage,str(int(progress_percentage))+" %")  # Update the progress bar

        data = pd.DataFrame(json_response)
        st.session_state['data']=data
        for i in range(len(data["reports"][0])):
            try:
                comments+= data["reports"][0][i]["comment"]+" "
            except Exception as e:
                pass
                try:
                    comments += data["reports"][1][i]["comment"] + " "
                except Exception as e:
                    pass
                try:
                    comments += data["reports"][2][i]["comment"] + " "
                except Exception as e:
                    pass
                try:
                    comments += data["reports"][3][i]["comment"] + " "
                except Exception as e:
                    pass
                try:
                    comments += data["reports"][4][i]["comment"] + " "
                except Exception as e:
                    pass
        signature,ports=extract_attack_signature_and_ports(comments)
        st.session_state['signature'] = signature
    st.title("Attack Data Visualization")

    # Sidebar navigation
    page = st.sidebar.selectbox("Select a page", ("Sammary","Attack Signatures", "Abuse Confidence Scores",
                                                      "Usage Types", "Total Reports Over Time",
                                                      "Country Distribution", "Domain Distribution"))

    # Chart pages
    # ... (existing code)
    if page == "Sammary":
        st.write(st.session_state['data'])
    elif page == "Attack Signatures":

        signature_counts = {}
        ip_signatures = {}  # Dictionary to store IP - Signature pairs

        for sig in st.session_state['signature']:
            signature_counts[sig] = signature_counts.get(sig, 0) + 1
        try:
            for idx, sig in enumerate(st.session_state['signature']):
                ip = st.session_state['data']['ipAddress'][idx]  # Get the IP corresponding to the signature
                if ip not in ip_signatures:
                    ip_signatures[ip] = []
                ip_signatures[ip].append(sig)
        except Exception as e:
            st.error(f"Error occurred during assigning IP addresses to signatures: {e}")
        # Create a Pie chart for attack signatures using Plotly
        fig1 = px.pie(names=list(signature_counts.keys()), values=list(signature_counts.values()),
                      title="Attack Signatures")
        st.subheader("Pie Chart: Attack Signatures")
        st.plotly_chart(fig1,use_container_width=True)

        # Display IP - Signature pairs
        st.subheader("IP - Signature Pairs")
        selected_ip = st.selectbox(
            "Select an IP to observe its signatures",
            options=list(ip_signatures.keys()),
            format_func=lambda ip: f"{ip} - {', '.join(ip_signatures[ip])}"
        )

        if selected_ip:
            st.write(f"IP: {selected_ip}")
            st.write(f"Signatures: {', '.join(ip_signatures[selected_ip])}")
            st.write("-" * 40)



    elif page == "Abuse Confidence Scores":

        st.subheader("IP Addresses vs Abuse Confidence Scores")

        # Get unique IP addresses

        unique_ips = st.session_state['data']['ipAddress'].unique()

        # Display search box to find an IP address

        selected_ip = st.selectbox(

            "Select an IP to observe its abuse confidence score",

            options=unique_ips,

            format_func=lambda ip: ip

        )

        # Display the abuse confidence score for the selected IP

        if selected_ip:
            confidence_score = st.session_state['data'].set_index("ipAddress").loc[selected_ip]["abuseConfidenceScore"]

            st.write(f"Selected IP: {selected_ip}")

            st.write(f"Abuse Confidence Score: {confidence_score}")

        # Create a bar chart for all IP addresses against abuseConfidenceScore

        st.bar_chart(st.session_state['data'].set_index("ipAddress")["abuseConfidenceScore"],use_container_width=True)

    elif page == "Usage Types":
        import streamlit as st
        import pandas as pd
        import plotly.express as px

        # Assuming st.session_state['data'] contains your data

        # Create a Streamlit app page
        st.title("Usage Types Distribution")

        # Group usage types by IP addresses
        usage_type_group = st.session_state['data'].groupby('usageType')['ipAddress'].apply(list).reset_index()

        # Create a list to hold usage type and associated IP addresses pairs
        usage_type_ip_pairs = []
        for _, row in usage_type_group.iterrows():
            for ip_address in row['ipAddress']:
                usage_type_ip_pairs.append({'Usage Type': row['usageType'], 'IP Address': ip_address})

        # Create a DataFrame from the list
        df_combined_usage_type = pd.DataFrame(usage_type_ip_pairs)

        # Create a pie chart using Plotly
        fig = px.pie(df_combined_usage_type, names='Usage Type', title="Usage Types Distribution",
                     hover_data=['IP Address'],
                     hover_name='Usage Type',
                     labels={'Usage Type': 'Usage Type', 'IP Address': 'IP Address'})

        # Customize hovertemplate to include both usage type and IP address
        fig.update_traces(hovertemplate="%{label}<br>IP Address: %{customdata}")

        # Display the chart
        st.plotly_chart(fig,use_container_width=True)


    elif page == "Total Reports Over Time":

        st.subheader("Total Reports Over Time")

        # Create a list of unique IP addresses

        unique_ips = st.session_state['data']['ipAddress'].unique().tolist()

        # Add an option for displaying all IPs

        unique_ips.insert(0, "All IPs")

        # Selection box for choosing IP addresses

        selected_ip = st.selectbox("Select an IP address", options=unique_ips)

        if selected_ip == "All IPs":

            # Create a Line chart of totalReports for all IP addresses

            st.line_chart(st.session_state['data'].set_index("lastReportedAt")["totalReports"],use_container_width=True)

        else:

            # Filter data for the selected IP and create the Line chart

            filtered_data = st.session_state['data'][st.session_state['data']['ipAddress'] == selected_ip]

            st.line_chart(filtered_data.set_index("lastReportedAt")["totalReports"],use_container_width=True)


    elif page == "Country Distribution":

        # Create a Pie chart of countryName

        st.subheader("Country Distribution")

        country_counts = st.session_state['data']["countryName"].value_counts()

        fig_country = px.pie(country_counts, names=country_counts.index, values=country_counts.values)

        st.plotly_chart(fig_country,use_container_width=True)

        # Create a multiselect widget to filter IP addresses

        selected_countries = st.multiselect(

            "Select Countries to Filter",

            options=country_counts.index.tolist(),

            default=None

        )

        if selected_countries:

            filtered_data = st.session_state['data'][st.session_state['data']["countryName"].isin(selected_countries)]

            # Create a dropdown widget to select IP addresses

            selected_ip = st.selectbox(

                "Select an IP to observe its signatures",

                options=filtered_data["ipAddress"],

                format_func=lambda ip: ip

            )

            if selected_ip:

                comments = ''

                for i, ip in enumerate(st.session_state['data']['ipAddress']):

                    if ip == selected_ip:

                        for j in range(len(st.session_state['data']["reports"][i])):
                            comments += st.session_state['data']["reports"][i][j]["comment"] + " "

                        signatures, ports = extract_attack_signature_and_ports(comments)

                        st.write(f"IP: {selected_ip}")

                        st.write(f"Signatures: {', '.join(signatures)}")

                        st.write("-" * 40)

                        break
    elif page == "Domain Distribution":
                        # Group domains by IP addresses
                        ip_domain_group = st.session_state['data'].groupby('ipAddress')['domain'].apply(
                            list).reset_index()

                        # Create a Streamlit app page
                        st.title("Domain Distribution")

                        # Create a list to hold domain and IP address pairs
                        domain_ip_pairs = []
                        for _, row in ip_domain_group.iterrows():
                            for domain in row['domain']:
                                domain_ip_pairs.append({'Domain': domain, 'IP Address': row['ipAddress']})

                        # Create a DataFrame from the list
                        df_combined_domain = pd.DataFrame(domain_ip_pairs)

                        # Create a pie chart using Plotly
                        fig = px.pie(df_combined_domain, names='Domain', title="Domains Distribution",
                                     hover_data=['IP Address'],
                                     hover_name='Domain',
                                     labels={'Domain': 'Domain', 'IP Address': 'IP Address'})

                        # Customize hovertemplate to include both domain and IP address
                        fig.update_traces(hovertemplate="%{label}<br>IP Address: %{customdata}")

                        st.plotly_chart(fig,use_container_width=True)

                        # Create a multiselect widget to filter IP addresses
                        selected_ips = st.multiselect(
                            "Select IPs to observe their domains",
                            options=ip_domain_group['ipAddress'].tolist(),
                            default=None
                        )

                        if selected_ips:
                            st.subheader("Domains for Selected IPs")
                            for selected_ip in selected_ips:
                                filtered_domains = df_combined_domain[df_combined_domain['IP Address'] == selected_ip][
                                    'Domain']
                                st.write(f"IP Address: {selected_ip}")
                                st.write(f"Domains: {', '.join(filtered_domains)}")
                                st.write("-" * 40)

def VT():
    import streamlit as st
    import pandas as pd
    import requests
    import pycountry
    
    API_KEY = 'b66edaf4b66520d9a8d17bc674fde9821c9327c04c1e99a82b8186ac486c2b02'
    
    def get_country_name(country_code):
        try:
            return pycountry.countries.get(alpha_2=country_code).name
        except AttributeError:
            return country_code  # If the conversion fails, return the code itself
    
    def get_virustotal_data(item):
        headers = {
            "x-apikey": API_KEY
        }
    
        # Determine if it's an IP, Hash, URL, or Domain
        if len(item.split('.')) == 4:  # Assuming it's an IP
            endpoint = f'https://www.virustotal.com/api/v3/ip_addresses/{item}'
        elif len(item) in [32, 40, 64]:  # Assuming it's a hash (MD5, SHA1, SHA256)
            endpoint = f'https://www.virustotal.com/api/v3/files/{item}'
        elif '://' in item:  # Assuming it's a URL
            endpoint = f'https://www.virustotal.com/api/v3/urls/{item}'
        else:  # Assuming it's a Domain
            endpoint = f'https://www.virustotal.com/api/v3/domains/{item}'
    
        response = requests.get(endpoint, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            
            # General result structure
            result = {
                "item": item,
            }
            
            # For IP addresses
            if endpoint.endswith(f'ip_addresses/{item}'):
                country_code = data['data']['attributes'].get('country', 'N/A')
                network = data['data']['attributes'].get('network', 'N/A')
                result.update({
                    "type": "IP",
                    "score": f"{data['data']['attributes']['last_analysis_stats']['malicious']}/{data['data']['attributes']['last_analysis_stats']['harmless']}",
                    "reputation": data['data']['attributes'].get('reputation', 'N/A'),
                    "country": get_country_name(country_code),
                    "network": network
                })
    
            # For hashes
            elif len(item) in [32, 40, 64]:
                hash_type = "MD5" if len(item) == 32 else ("SHA1" if len(item) == 40 else "SHA256")
                file_name = data['data']['attributes'].get('name', 'N/A')
                signature_names = data['data']['attributes'].get('names', [])
                threat_label = signature_names[0] if signature_names else "N/A"
                malicious_detections = data['data']['attributes']['last_analysis_stats']['malicious']
                total_detections = sum(data['data']['attributes']['last_analysis_stats'].values())  # Sum of all analysis stats
    
                result.update({
                "item": item,
                "type": hash_type,
                "score": f"{malicious_detections}/{total_detections}",
                "threat_label": threat_label,
                    
                })
    
            # For URLs and Domains
            else:
                categories = ", ".join(data['data']['attributes'].get('categories', {}).values())
                result.update({
                    "type": "URL" if '://' in item else "Domain",
                    "score": f"{data['data']['attributes']['last_analysis_stats']['malicious']}/{data['data']['attributes']['last_analysis_stats']['harmless']}",
                    "reputation": data['data']['attributes'].get('reputation', 'N/A'),
                    "categories": categories
                })
    
            return result
        else:
            return {"item": item, "error": response.text}
    
    
    st.title("VirusTotal Bulk Lookup")
    
    uploaded_file = st.file_uploader("Upload CSV or TXT file", type=['csv', 'txt'])
    user_input = st.text_area("Paste your hashes/IPs/URLs/Domains here (newline separated)")
    submit_button = st.button("Submit")
    
    if submit_button:
        if uploaded_file:
            if uploaded_file.type == "text/csv":
                data = pd.read_csv(uploaded_file)
            else:
                data = pd.DataFrame({'item': [line.strip().decode('utf-8') for line in uploaded_file.readlines()]})
    
            results = [get_virustotal_data(item) for item in data['item']]
            df_results = pd.DataFrame(results)  # Convert to DataFrame
                
            st.write(df_results)  # Display DataFrame
    
            csv = df_results.to_csv(index=False)
            st.download_button("Download CSV", csv, "output.csv")
    
        elif user_input:
            items = user_input.split('\n')
            results = [get_virustotal_data(item.strip()) for item in items]
            df_results = pd.DataFrame(results)  # Convert to DataFrame
                
            st.write(df_results)  # Display DataFrame
                
            csv = df_results.to_csv(index=False)
            st.download_button("Download CSV", csv, "output.csv")

        
    
page_names_to_funcs = {
    "Home":home,
    "IP reputation": AbuseIPDB,
    "Hash Reputation":VT
}

demo_name = st.sidebar.selectbox("Choose a mode", page_names_to_funcs.keys())
page_names_to_funcs[demo_name]()
